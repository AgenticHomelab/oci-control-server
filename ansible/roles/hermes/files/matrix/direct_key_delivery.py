"""Opt-in direct current-index room keys, immediately before room encryption."""
import asyncio
import re

from mautrix.crypto import OlmMachine
from mautrix.errors import EncryptionError
from mautrix.types import EventType, Membership, TrustState

_DELIVERY_TIMEOUT_SECONDS = 30

_ROOM = re.compile(r"^![^:]+:.+$")
_USER = re.compile(r"^@[^:]+:.+$")
_DEVICE = re.compile(r"^[A-Za-z0-9_-]+$")


def _validated_grants(grants):
    """Exact room/user/device grants only; copied so later config edits cannot widen them."""
    if not isinstance(grants, list) or not grants or len(grants) > 64:
        raise ValueError("Invalid matrix.direct_key_delivery: a non-empty list of at most 64 grants is required")
    result = []
    for grant in grants:
        if not isinstance(grant, dict) or set(grant) != {"room_id", "user_id", "device_id"}:
            raise ValueError("Invalid matrix.direct_key_delivery grant: exact room_id/user_id/device_id required")
        room, user, device = grant["room_id"], grant["user_id"], grant["device_id"]
        if not (isinstance(room, str) and _ROOM.match(room) and isinstance(user, str) and _USER.match(user)
                and isinstance(device, str) and 0 < len(device) <= 255 and _DEVICE.match(device)):
            raise ValueError("Invalid matrix.direct_key_delivery grant: malformed identifiers")
        result.append((room, user, device))
    return tuple(dict.fromkeys(result))


class DirectKeyDeliveryMachine(OlmMachine):
    def __init__(self, *args, grants, **kwargs):
        super().__init__(*args, **kwargs)
        self._direct_grants = _validated_grants(grants)

    async def _current(self, room_id, session_id, *, used=False):
        outbound = await self.crypto_store.get_outbound_group_session(room_id)
        if (not outbound or outbound.id != session_id or outbound.room_id != room_id
                or not outbound.shared or (not used and outbound.expired)):
            raise EncryptionError("Outbound session changed")
        own = await self.crypto_store.get_group_session(room_id, session_id)
        if (not own or own.sender_key != self.account.identity_key
                or own.signing_key != self.account.signing_key or own.room_id != room_id):
            raise EncryptionError("Not an own outbound session")
        return outbound

    async def _authorized(self, room_id, targets, expected=None):
        for user in {self.client.mxid, *(user for user, _ in targets)}:
            member = await self.client.get_state_event(room_id, EventType.ROOM_MEMBER, user)
            if member.membership != Membership.JOIN:
                raise EncryptionError("Not joined")
        query = {}
        for user, device in targets:
            query.setdefault(user, []).append(device)
        fresh = await self.client.query_keys(query)
        devices = []
        for user, device_id in targets:
            device = await self.crypto_store.get_device(user, device_id)
            if (not device or device.deleted or device.trust == TrustState.BLACKLISTED
                    or device.user_id != user or device.device_id != device_id):
                raise EncryptionError("Unauthorized device")
            keys = fresh.device_keys.get(user, {}).get(device_id)
            if not keys:
                raise EncryptionError("Missing device keys")
            checked = await self._validate_device(user, device_id, keys, device)
            if checked.identity_key != device.identity_key:
                raise EncryptionError("Device identity changed")
            devices.append(device)
        if expected is not None and expected != [(d.identity_key, d.signing_key) for d in devices]:
            raise EncryptionError("Device changed while delivering")
        return devices

    async def _deliver(self, room_id, session_id, targets):
        await self._current(room_id, session_id)
        devices = await self._authorized(room_id, targets)
        fingerprints = [(d.identity_key, d.signing_key) for d in devices]
        sessions = []
        for device in devices:
            previous = await self.crypto_store.get_latest_session(device.identity_key)
            previous_id = previous.id if previous else None
            await self._create_outbound_sessions(
                {device.user_id: {device.device_id: device}}, _force_recreate_session=True)
            session = await self.crypto_store.get_latest_session(device.identity_key)
            # Native SDK may return normally for invalid/partial key claims.
            if not session or session.id == previous_id:
                raise EncryptionError("No fresh Olm session")
            sessions.append(session)
        # Never claim (including via send_encrypted_to_device) after final authorization.
        async with self._olm_lock:
            devices = await self._authorized(room_id, targets, fingerprints)
            outbound = await self._current(room_id, session_id)
            messages = {}
            for device, session in zip(devices, sessions):
                encrypted = await self._encrypt_olm_event(session, device, EventType.ROOM_KEY, outbound.share_content)
                messages.setdefault(device.user_id, {})[device.device_id] = encrypted
            # Encryption persists Olm state through an await. Recheck before disclosing anything.
            await self._authorized(room_id, targets, fingerprints)
            await self._current(room_id, session_id)
            await self.client.send_to_device(EventType.TO_DEVICE_ENCRYPTED, messages)
        return fingerprints

    async def _encrypt_megolm_event(self, room_id, event_type, content):
        # Called inside the SDK's per-room Megolm lock, for every encrypted event type.
        targets = [(user, device) for room, user, device in self._direct_grants if room == room_id]
        if not targets:
            return await super()._encrypt_megolm_event(room_id, event_type, content)
        try:
            async with asyncio.timeout(_DELIVERY_TIMEOUT_SECONDS):
                outbound = await self.crypto_store.get_outbound_group_session(room_id)
                if not outbound or not outbound.shared or outbound.expired:
                    # Keep the SDK's missing/expired-session rotation behavior.
                    return await super()._encrypt_megolm_event(room_id, event_type, content)
                fingerprints = await self._deliver(room_id, outbound.id, targets)
                encrypted = await super()._encrypt_megolm_event(room_id, event_type, content)
                await self._authorized(room_id, targets, fingerprints)
                await self._current(room_id, outbound.id, used=True)
                if encrypted.session_id != outbound.id:
                    raise EncryptionError("Outbound session changed during encryption")
                return encrypted
        except Exception:
            # Never expose keys or a raw homeserver response to callers/loggers.
            raise EncryptionError("Direct key delivery failed") from None
