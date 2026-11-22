# WIP: Transparent S/MIME + PGP read-path decryption

> **WORK IN PROGRESS — not for upstream.** This branch is an in-progress
> feature branch on the fork. Do not open a PR against
> `tecnologicachile/mail-mcp` until the checklist below is complete
> (platform parity is a hard precondition — see the roadmap). Remove this
> file before any upstream PR.

## What this branch adds (opt-in, presence-gated)

When an account sets `MAIL_SMIME_<ID>_ENABLED` / `MAIL_PGP_<ID>_ENABLED`:

- `imap_get_message` transparently decrypts/digests detected crypto
  structures and returns the message as if it had never been encrypted
  (Apple-Mail semantics), plus a `crypto` metadata block:
  `{scheme, encrypted, decrypted, signed?, verified?, signer_cn?,
  signer_email?, failure_reason?, original_part_id, inner_part_prefix}`.
- `imap_get_attachment` resolves attachment parts inside decrypted content
  (`d`-prefixed part ids, e.g. `d1.2`).
- Failures are fail-open: the original view plus a bounded
  `failure_reason`; decryption never fails a tool call.
- **Inert without config:** no crypto code path, no subprocess, unchanged
  tool schema (37 tools), byte-identical responses — covered by tests.

Without any `MAIL_SMIME_*` / `MAIL_PGP_*` settings the build behaves
exactly like `main`.

## Status (updated as work progresses)

| Area | State |
|---|---|
| S/MIME enveloped-data decrypt (macOS `security cms -D`, keychain identity) | ✅ live-verified 22.11. (CipherMail/Proxmox gateway mail) |
| PGP/MIME + inline decrypt (`gpg`, passphrase on stdin fd 0) | ✅ live-verified 22.11. (ProtonMail application mail incl. inner attachments) |
| ProtonMail flat-sibling PGP/MIME detection (no RFC-3156 wrapper) | ✅ live-found + fixed |
| gpg signature classification (Good/BAD/can't-check) | ✅ live-verified |
| Opaque `signed-data` content extraction + signature verification (`openssl smime -verify`) | ✅ live-verified 22.11. (own opaque-signed sent mail: extracted + `verified: true`) |
| Clear-signed `multipart/signed` detection + verification (whole raw message, no byte reconstruction) | ✅ fixture-verified (canonical openssl-signed mails) + live in sign-then-envelop inner |
| Sign-then-envelop inner signature (Ruhl "double layer") | ✅ live-verified 22.11. (`decrypted+signed+verified` all true on real incoming mail) |
| Signer cert/trust-chain validation (macOS keychain `verify-certificate`) | ⬜ planned (digest validity only for now) |
| Linux backend: enveloped decrypt via `openssl smime -decrypt` (PEM key files) | ⬜ next step (openssl verify paths are already cross-platform) |
| Upstream design issue / PR | ⬜ only after macOS + Linux both work |

Signature-verification semantics: `verified: true` means the **signature
digest is valid** (`openssl smime -verify -noverify` for S/MIME — computed
over the whole raw message for clear-signed mail; over the embedded content
for opaque signed-data; gpg for PGP). Certificate chain/trust is NOT
validated yet (`-noverify`) — that is a separate, planned step. `verified:
null` = present but not determinable (e.g. unknown PGP signer key, or an
operational verification error, reported via `failure_reason`).

## Design (the seam for later phases)

- `src/crypto/backend.rs` — `DecryptBackend` trait. Step-1 backends are
  subprocesses (`security cms` for macOS keychain decryption, `gpg` for
  PGP, `openssl smime` for signature verification — the latter is already
  cross-platform). A native-Rust backend (`cryptographic-message-syntax` /
  `sequoia-openpgp`) later implements the same trait.
- `src/crypto/detect.rs` — pure structure detection, no IO, runs on every
  platform (fixture-tested).
- `src/crypto/mod.rs` — config discovery, orchestration, bounded in-memory
  cache for decrypted content (TTL 600 s, max 16 entries).
- Env vars: `MAIL_SMIME_<ID>_ENABLED`, `MAIL_PGP_<ID>_ENABLED`,
  `MAIL_PGP_<ID>_PASS` / `MAIL_PGP_<ID>_PASS_KEYCHAIN_SERVICE` /
  `_PASS_KEYCHAIN_ACCOUNT`, `MAIL_PGP_<ID>_GPG_BIN`,
  `MAIL_CRYPTO_TIMEOUT_MS` (default 30 000).

## Verification log (keep appending)

- 22.11. (Sirius): full matrix live — S/MIME CipherMail mail transparent
  decrypt; PGP/MIME ProtonMail application mail transparent decrypt with
  all six inner attachments downloadable via `d`-prefixed part ids;
  plaintext mails unchanged (no `crypto` field); tool schema unchanged.
  Two real-world fixes resulted (ProtonMail flat siblings; gpg nonzero
  exit with valid plaintext when the signer key is unknown).
- 22.11.: rebased onto upstream v0.7.1 (base `7fb7267`), validation green
  (fmt, clippy `-D warnings`, full test suite).
- 22.11.: signature verification added (`openssl smime -verify -noverify`)
  and live-verified: own opaque-signed sent mail extracts + `verified:
  true`; real incoming Ruhl sign-then-envelop mail reports
  `decrypted+signed+verified` all true. Clear-signed verification runs
  over the whole raw message (byte reconstruction of the signed part is
  the classic trailing-CRLF pitfall — canonical openssl-signed fixture
  mails verify; tampered ones report `verified: false`).

## Living tracker

Fine-grained decisions, gotchas, and session history live in the private
`mail-triage` repo (`tasks/mail-mcp-smime-pgp-integration.md`,
git.unibw.de) — this file tracks only the branch-level status.
