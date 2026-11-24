# Reviewed Matrix direct-key delivery overlay

Hermes's locally installed Matrix E2EE customization is a source overlay,
not a second application installation or a new service. The authoritative
implementation now lives in `ansible/roles/hermes/files/matrix/` and is applied
by the isolated `hermes-update.yml` playbook. The normal host play audits
but does not overwrite or update this code.

## Behavior and threat boundary

The opt-in `matrix.direct_key_delivery` setting is a non-empty list
of exact `room_id`, `user_id`, `device_id` grants (up to 64).
No wildcard grant is supported. Keep actual Matrix IDs and credentials out
of the public repository. The adapter uses `DirectKeyDeliveryMachine`
only with explicit grants. It fails the encrypted send if device signatures,
identity, membership, outbound session, fresh Olm claim or final rechecks fail.

**This is an additional direct key-delivery operation, not a room-wide
device access-control mechanism.** Ordinary Matrix key sharing by the
underlying SDK continues to operate. Configure and audit room membership,
device trust and the upstream E2EE policy independently. Unverified,
non-blacklisted devices may receive a key if the exact grant allows them.
Treat every grant as authorization for access to the room's key from the
current Megolm ratchet position onward.

The key is sent before the corresponding encrypted message. The
cryptographic tests cover revocation during awaited operations, missing/
invalid one-time keys, lack of partial sends, bounded failures, invalid grants
and the normal unconfigured fallback. They also exercise a nonzero Megolm
message index to test exclusion of earlier ciphertext. The tests simulate
homeserver I/O; they are not a live Matrix acceptance test.

## Upgrade and ownership

- The original Oct 2026 checkout on control-01 contained exactly two edited
  tracked files (Matrix adapter and website instructions) and two untracked
  files (direct-key implementation and its test). The isolated play accepts
  those exact filenames **and** checks known Git blob identities for the
  adapter, implementation and test before invoking any mutating updater.
  Any other change blocks the operation.
- The old website documentation changes are preserved in the upstream
  updater's retained Git stash, not overwritten or silently copied into
  a different upstream release. This document is the durable operational
  replacement. Examine the retained stash before deliberately deleting it.
- The upstream updater is called with `--backup --keep-stash
  --no-gateway-restart` to retain original edits and defer gateway restarts
  until Ansible has installed the reviewed source overlay. Do not run the
  updater with a different stash/restart policy manually.
- The adapter patch is approved **only for Hermes v0.23.4**.
  `ansible/roles/hermes/files/matrix/adapter-v0.23.4.patch` applies to that
  version's exact upstream source. New Hermes release PRs must rebase and
  review the patch and run native crypto regression tests again; the overlay
  play refuses an unreviewed later release.
- The `Hermes Matrix E2EE compatibility` GitHub Actions workflow checks
  the real published Hermes source, applies the patch and runs the real
  `mautrix` crypto tests. The normal offline CI checks the Ansible
  owner/entrypoint contract. A green offline check is not proof of
  cryptographic behavior.
- After the separately approved production upgrade, verify the patch
  identities, both systemd user units and actual Matrix E2EE messaging,
  including a newly granted device and a revoked device. Also confirm
  independent backup/recovery, native jobs and dashboard authentication.
  Do not call the migration accepted from service liveness alone.

Use `docs/manual-upgrades.md` for preflight, upgrade commands and
production rollback considerations. The normal host play intentionally
does **not** reconcile native data, remove old stashes or silently push the
checkout forward.
