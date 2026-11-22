//! Decryption backend contract.
//!
//! The seam between mail-mcp and the actual crypto. Step 1 ships a
//! subprocess-based implementation (`security cms` on macOS, `gpg`
//! everywhere — see [`super::subprocess`]). A later native-Rust backend
//! (`cryptographic-message-syntax` / `sequoia-openpgp`) implements the same
//! trait and replaces the subprocesses without touching the orchestration
//! in [`super`].

use std::time::Duration;

use futures::future::BoxFuture;

/// Bounded, secret-free failure description for one crypto operation.
///
/// `message` is derived from tool stderr/exit status and is truncated before
/// it is constructed. It must never contain key material or passphrases.
#[derive(Debug, Clone)]
pub struct CryptoStepError {
    /// Coarse failure classification for callers and tests
    pub kind: CryptoErrorKind,
    /// Human-readable, bounded reason (no secrets)
    pub message: String,
}

impl CryptoStepError {
    /// Build an error with a pre-bounded message.
    pub fn new(kind: CryptoErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: crate::mime::truncate_chars(message.into(), 200),
        }
    }
}

impl std::fmt::Display for CryptoStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Coarse failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    /// The helper process ran but refused the input (bad data, missing key,
    /// wrong identity, locked keychain, …)
    ProcessFailed,
    /// The helper exceeded the configured wall-clock budget
    TimedOut,
    /// No backend available for this platform/configuration
    Unsupported,
}

/// Signature status reported alongside decrypted content, when knowable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature present and verified by the helper
    Verified,
    /// Signature present but not (fully) verified — e.g. extracted from a
    /// signed-data structure without chain validation
    Unverified,
    /// Signature present and invalid/expired/bad
    Bad,
}

/// What a backend reports about a signature.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Verification outcome
    pub status: SignatureStatus,
    /// Signer description (CN or uid) when the helper reports one
    pub signer: Option<String>,
}

/// Result of a successful decryption/extraction.
#[derive(Debug)]
pub struct DecryptOutcome {
    /// The recovered content bytes (a MIME entity, or raw body bytes)
    pub content: Vec<u8>,
    /// Signature metadata when the structure carries a signature
    pub signature: Option<SignatureInfo>,
}

/// Decrypt/extract content from S/MIME and PGP payloads.
///
/// Implementations must be cancellation-safe: subprocess-based backends
/// kill their child process when the future is dropped.
pub trait DecryptBackend: Send + Sync {
    /// Decrypt an S/MIME `enveloped-data` payload (DER bytes) into the
    /// inner MIME entity.
    fn smime_enveloped<'a>(
        &'a self,
        der: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>>;

    /// Extract the embedded content of an S/MIME opaque `signed-data`
    /// payload (DER bytes) and report signature validity when checkable.
    fn smime_signed_content<'a>(
        &'a self,
        der: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>>;

    /// Verify a clear-signed S/MIME message (`multipart/signed`): the whole
    /// raw message (exactly as the sender's MUA assembled it — no byte
    /// reconstruction, which is the classic trailing-CRLF pitfall of
    /// detached signatures). Content output is not needed: the first part is
    /// already visible to plain parsing.
    fn smime_verify_clear_signed<'a>(
        &'a self,
        raw_mime: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<SignatureInfo, CryptoStepError>>;

    /// Decrypt a PGP payload (armored or binary OpenPGP message).
    fn pgp_decrypt<'a>(
        &'a self,
        ciphertext: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>>;
}
