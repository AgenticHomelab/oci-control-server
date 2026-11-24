"""Real native crypto, disposable stores; only homeserver I/O is simulated."""
import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("mautrix.crypto")
from mautrix.crypto import OlmMachine
from mautrix.crypto.store.memory import MemoryCryptoStore
from mautrix.errors import EncryptionError
from mautrix.types import (
    ClaimKeysResponse, DeviceID, EventType, Membership, MemberStateEventContent,
    QueryKeysResponse, RoomEncryptionStateEventContent, EncryptionAlgorithm,
    RoomID, UserID, ToDeviceEvent, TrustState,
)

ROOM = RoomID("!direct:example.invalid")
BOT = UserID("@bot:example.invalid")
USER = UserID("@recipient:example.invalid")
GRANTS = [{"room_id": ROOM, "user_id": USER, "device_id": "RECIPIENT"}]


class Wire:
    def __init__(self):
        self.machines, self.keys, self.events = {}, {}, []
        self.members = {(ROOM, BOT): Membership.JOIN, (ROOM, USER): Membership.JOIN}
        self.claims = 0

    def client(self, user, device):
        wire = self

        class Client:
            mxid, device_id = user, DeviceID(device)
            def add_event_handler(self, *args, **kwargs):
                pass
            async def upload_keys(self, **kwargs):
                return {}
            async def get_state_event(self, room, event_type, state_key=""):
                if event_type == EventType.ROOM_ENCRYPTION:
                    return RoomEncryptionStateEventContent(algorithm=EncryptionAlgorithm.MEGOLM_V1)
                return MemberStateEventContent(membership=wire.members.get((room, state_key), Membership.LEAVE))
            async def query_keys(self, query, **kwargs):
                if not isinstance(query, dict):
                    query = {u: [d for uid, d in wire.keys if uid == u] for u in query}
                return QueryKeysResponse.deserialize({"device_keys": {
                    u: {d: wire.keys[u, d].serialize() for d in ds if (u, d) in wire.keys}
                    for u, ds in query.items()}})
            async def claim_keys(self, query):
                wire.claims += 1
                result = {}
                for u, ds in query.items():
                    result[u] = {}
                    for d in ds:
                        account = wire.machines[u, d].account
                        kid, key = next(iter(account.get_one_time_keys(u, d, 0).items()))
                        result[u][d] = {kid: key}
                        account.mark_keys_as_published()
                return ClaimKeysResponse.deserialize({"one_time_keys": result})
            async def send_to_one_device(self, kind, u, d, content):
                wire.events.append((u, d, ToDeviceEvent.deserialize({
                    "sender": user, "type": str(kind), "content": content.serialize()})))
            async def send_to_device(self, kind, messages):
                for u, ds in messages.items():
                    for d, content in ds.items():
                        await self.send_to_one_device(kind, u, d, content)
        return Client()

    async def machine(self, user, device, cls=OlmMachine, **kwargs):
        class State:
            async def get_encryption_info(self, room):
                return RoomEncryptionStateEventContent(algorithm=EncryptionAlgorithm.MEGOLM_V1)
            async def find_shared_rooms(self, user):
                return [ROOM]
        machine = cls(self.client(user, device), MemoryCryptoStore(device, "test"), State(), **kwargs)
        await machine.load()
        machine.share_keys_min_trust = machine.send_keys_min_trust = TrustState.UNVERIFIED
        self.machines[user, DeviceID(device)] = machine
        self.keys[user, DeviceID(device)] = machine.account.get_device_keys(user, DeviceID(device))
        return machine


async def prepare(sender=None, wire=None, grants=GRANTS):
    from plugins.platforms.matrix.direct_key_delivery import DirectKeyDeliveryMachine
    wire = wire or Wire()
    sender = sender or await wire.machine(BOT, "BOT", DirectKeyDeliveryMachine, grants=grants)
    recipient = await wire.machine(USER, "RECIPIENT")
    await sender._fetch_keys([USER], include_untracked=True)
    await sender.share_group_session(ROOM, [USER])
    wire.events.clear()
    return wire, sender, recipient


async def encrypt(sender, body="message", kind=EventType.ROOM_MESSAGE, room=ROOM):
    return await sender.encrypt_megolm_event(room, kind, {"msgtype": "m.text", "body": body})


@pytest.mark.asyncio
async def test_yaml_adapter_delivers_direct_current_key_before_encryption(tmp_path, monkeypatch):
    import hermes_yaml as yaml
    from gateway.config import load_gateway_config, Platform
    from plugins.platforms.matrix.adapter import MatrixAdapter

    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"matrix": {
        "enabled": True, "homeserver": "https://example.invalid", "user_id": str(BOT),
        "e2ee_mode": "required", "direct_key_delivery": GRANTS}}))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = load_gateway_config().platforms[Platform.MATRIX]
    assert config.extra["direct_key_delivery"] == GRANTS
    adapter = MatrixAdapter(config)
    adapter._resolve_store_dir()
    wire = Wire()
    client = wire.client(BOT, "BOT")
    try:
        assert await adapter._connect_setup_e2ee(client, SimpleNamespace(), SimpleNamespace())
        assert type(client.crypto).__name__ == "DirectKeyDeliveryMachine"
        wire, sender, recipient = await prepare(client.crypto, wire)
        identity = (sender.account.identity_key, sender.account.signing_key)
        encrypted = await encrypt(sender)
        assert len(wire.events) == 1
        u, d, event = wire.events.pop()
        assert (u, d) == (USER, "RECIPIENT")
        decoded = await recipient._decrypt_olm_event(event)
        assert decoded.type == EventType.ROOM_KEY
        assert decoded.content.room_id == ROOM
        assert decoded.content.session_id == encrypted.session_id
        import olm
        key = olm.InboundGroupSession(decoded.content.session_key)
        assert key.first_known_index == 0
        assert key.decrypt(encrypted.ciphertext)[1] == 0
        assert identity == (sender.account.identity_key, sender.account.signing_key)
    finally:
        if adapter._crypto_db:
            await adapter._crypto_db.stop()



@pytest.mark.asyncio
async def test_late_device_receives_current_index_without_history():
    """A recipient joining after the ratchet advances cannot decrypt previous messages."""
    import olm
    wire, sender, recipient = await prepare()
    earlier = await OlmMachine._encrypt_megolm_event(
        sender, ROOM, EventType.ROOM_MESSAGE, {"msgtype": "m.text", "body": "earlier"}
    )
    later = await encrypt(sender, "later")
    assert len(wire.events) == 1
    u, d, event = wire.events.pop()
    assert (u, d) == (USER, "RECIPIENT")
    decoded = await recipient._decrypt_olm_event(event)
    assert decoded.type == EventType.ROOM_KEY
    key = olm.InboundGroupSession(decoded.content.session_key)
    assert key.first_known_index > 0
    assert key.decrypt(later.ciphertext)[1] == key.first_known_index
    with pytest.raises(olm.OlmGroupSessionError):
        key.decrypt(earlier.ciphertext)


async def revoke(wire, sender, reason):
    device = await sender.crypto_store.get_device(USER, DeviceID("RECIPIENT"))
    if reason == "blacklist":
        device.trust = TrustState.BLACKLISTED
    elif reason == "deleted":
        device.deleted = True
    elif reason in ("recipient_left", "bot_left"):
        wire.members[ROOM, USER if reason == "recipient_left" else BOT] = Membership.LEAVE
    elif reason == "key_drift":
        await wire.machine(USER, "RECIPIENT")
    elif reason == "bad_signature":
        wire.keys[USER, DeviceID("RECIPIENT")].signatures[USER]["ed25519:RECIPIENT"] = "invalid"
    elif reason == "outbound_removed":
        await sender.crypto_store.remove_outbound_group_session(ROOM)
    elif reason == "foreign_key":
        outbound = await sender.crypto_store.get_outbound_group_session(ROOM)
        inbound = await sender.crypto_store.get_group_session(ROOM, outbound.id)
        inbound.signing_key = "not-bots-signing-key"
    else:
        raise AssertionError(reason)
    if reason in ("blacklist", "deleted"):
        await sender.crypto_store.put_devices(USER, {device.device_id: device})


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["blacklist", "deleted", "recipient_left", "bot_left", "key_drift", "bad_signature", "foreign_key"])
@pytest.mark.parametrize("stage", ["before", "claim"])
async def test_authorization_rechecked_after_fresh_claim(reason, stage):
    wire, sender, _ = await prepare()
    if stage == "before":
        await revoke(wire, sender, reason)
    else:
        original = sender.client.claim_keys
        async def claim(query):
            result = await original(query)
            await revoke(wire, sender, reason)
            return result
        sender.client.claim_keys = claim
    with pytest.raises(EncryptionError, match="Direct key delivery failed"):
        await encrypt(sender)
    assert not wire.events, "No scoped key or ciphertext may leave after authorization fails"


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["blacklist", "deleted", "recipient_left", "key_drift", "outbound_removed"])
@pytest.mark.parametrize("stage", ["claim", "olm_store", "room_store"])
async def test_revocation_across_crypto_awaits_aborts_ciphertext(reason, stage):
    wire, sender, _ = await prepare()
    target, method = ((sender.client, "claim_keys") if stage == "claim" else
                      (sender.crypto_store, "update_session" if stage == "olm_store" else "update_outbound_group_session"))
    original = getattr(target, method)
    async def mutate(*args, **kwargs):
        result = await original(*args, **kwargs)
        await revoke(wire, sender, reason)
        return result
    setattr(target, method, mutate)
    with pytest.raises(EncryptionError, match="Direct key delivery failed"):
        await encrypt(sender)
    if stage != "room_store":
        assert not wire.events, "Reject invalidation during Olm/store awaits before any key disclosure"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing", "invalid_signature", "network", "second_missing"])
async def test_incomplete_fresh_handshake_never_uses_old_olm_or_sends_partial_keys(failure):
    grants = GRANTS + ([{**GRANTS[0], "device_id": "SECOND"}] if failure == "second_missing" else [])
    wire, sender, _ = await prepare(grants=grants)
    if failure == "second_missing":
        await wire.machine(USER, "SECOND")
        await sender._fetch_keys([USER], include_untracked=True)
    original = sender.client.claim_keys
    async def claim(query):
        if failure == "network":
            raise RuntimeError("SECRET raw response must never leak")
        if failure == "missing" or (failure == "second_missing" and "SECOND" in query[USER]):
            return ClaimKeysResponse.deserialize({"one_time_keys": {}})
        result = await original(query)
        if failure == "invalid_signature":
            key = next(iter(result.one_time_keys[USER][DeviceID("RECIPIENT")].values()))
            key["signatures"][USER]["ed25519:RECIPIENT"] = "invalid"
        return result
    sender.client.claim_keys = claim
    with pytest.raises(EncryptionError, match="^Direct key delivery failed$") as error:
        await encrypt(sender)
    assert "SECRET" not in str(error.value)
    assert not wire.events


@pytest.mark.asyncio
async def test_stalled_delivery_has_bounded_sanitized_failure(monkeypatch):
    from plugins.platforms.matrix import direct_key_delivery
    wire, sender, _ = await prepare()
    monkeypatch.setattr(direct_key_delivery, "_DELIVERY_TIMEOUT_SECONDS", 0.01, raising=False)
    async def stalled(query):
        await asyncio.Event().wait()
    sender.client.query_keys = stalled
    with pytest.raises(EncryptionError, match="^Direct key delivery failed$"):
        await asyncio.wait_for(encrypt(sender), 2)
    assert not wire.events


@pytest.mark.parametrize("grants", [
    {}, False, "all", [None], [{}], [{**GRANTS[0], "extra": True}],
    [{**GRANTS[0], "room_id": "*"}], [{**GRANTS[0], "room_id": "#alias:example.invalid"}],
    [{**GRANTS[0], "user_id": "@recipient"}], [{**GRANTS[0], "user_id": " @recipient:example.invalid"}],
    [{**GRANTS[0], "device_id": "*"}], [{**GRANTS[0], "device_id": "RECIPIENT "}],
    [{**GRANTS[0], "device_id": ""}], [{**GRANTS[0], "device_id": "x" * 256}], GRANTS * 65,
])
def test_invalid_grants_fail_closed(grants):
    from plugins.platforms.matrix.direct_key_delivery import DirectKeyDeliveryMachine
    with pytest.raises(ValueError, match="Invalid matrix.direct_key_delivery"):
        DirectKeyDeliveryMachine(Wire().client(BOT, "BOT"), MemoryCryptoStore("test", "test"), None, grants=grants)


def test_duplicate_grants_are_immutable_and_do_not_duplicate_delivery():
    from plugins.platforms.matrix.direct_key_delivery import DirectKeyDeliveryMachine
    config = [dict(GRANTS[0]), dict(GRANTS[0])]
    machine = DirectKeyDeliveryMachine(Wire().client(BOT, "BOT"), MemoryCryptoStore("test", "test"), None, grants=config)
    config[0]["device_id"] = "ATTACKER"
    assert machine._direct_grants == ((ROOM, USER, "RECIPIENT"),)


@pytest.mark.asyncio
@pytest.mark.parametrize("scopes", [[], None])
async def test_unconfigured_adapter_is_stock_machine_with_normal_flow(scopes, tmp_path, monkeypatch):
    import hermes_yaml as yaml
    from gateway.config import load_gateway_config, Platform
    from plugins.platforms.matrix.adapter import MatrixAdapter

    matrix = {"enabled": True, "homeserver": "https://example.invalid", "user_id": str(BOT),
              "e2ee_mode": "required"}
    if scopes is not None:
        matrix["direct_key_delivery"] = scopes
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"matrix": matrix}))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = load_gateway_config().platforms[Platform.MATRIX]
    assert config.extra.get("direct_key_delivery", None) in ([], None)
    adapter = MatrixAdapter(config)
    adapter._resolve_store_dir()
    wire = Wire()
    client = wire.client(BOT, "BOT")
    try:
        assert await adapter._connect_setup_e2ee(client, SimpleNamespace(), SimpleNamespace())
        assert type(client.crypto) is OlmMachine
        wire, sender, recipient = await prepare(client.crypto, wire)
        claims = wire.claims
        encrypted = await encrypt(sender)
        assert not wire.events, "No extra key delivery without configuration"
        assert wire.claims == claims
        assert encrypted.ciphertext
    finally:
        if adapter._crypto_db:
            await adapter._crypto_db.stop()


@pytest.mark.asyncio
async def test_unrelated_room_grant_does_not_deliver():
    grants = [{"room_id": RoomID("!other:example.invalid"), "user_id": USER, "device_id": "RECIPIENT"}]
    wire, sender, recipient = await prepare(grants=grants)
    claims = wire.claims
    await encrypt(sender)
    assert not wire.events, "No direct delivery for rooms outside the grants"
    assert wire.claims == claims
