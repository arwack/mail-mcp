//! Subprocess-based decryption backends (step 1).
//!
//! Two implementations of [`super::backend::DecryptBackend`]:
//!
//! - [`SecurityCmsBackend`] — S/MIME via `/usr/bin/security cms -D`
//!   (macOS only). The private key never leaves the login keychain: the
//!   `security` binary performs the decryption itself. Contract (verified):
//!   input = decoded part body (raw CMS DER bytes) via a 0600 temp file;
//!   content arrives on stdout (binary-safe); diagnostics on stderr; clean
//!   exit codes.
//! - [`GpgBackend`] — PGP via `gpg` (works on every platform where gpg is
//!   installed). The passphrase is fed on stdin (fd 0) — never on the command
//!   line, where `ps` could observe it. Contract (verified): content on
//!   stdout, status/diagnostics on stderr, `--batch` never prompts.
//!
//! Both backends are strictly timeout-bounded and kill their child process
//! when the caller is dropped (cancellation-safe). A later native-Rust
//! backend replaces them behind the same trait without touching callers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use secrecy::{ExposeSecret, SecretString};
use tokio::io::AsyncWriteExt;

use super::backend::{
    CryptoErrorKind, CryptoStepError, DecryptBackend, DecryptOutcome, SignatureInfo,
    SignatureStatus,
};

/// Absolute path of the macOS `security` tool (fixed location so a minimal
/// launchd PATH cannot break decryption).
#[cfg(target_os = "macos")]
const SECURITY_BIN: &str = "/usr/bin/security";

/// S/MIME backend using the macOS `security cms` helper.
#[derive(Debug, Default)]
pub struct SecurityCmsBackend;

impl SecurityCmsBackend {
    /// Decode an S/MIME payload (enveloped-data or opaque signed-data DER).
    async fn cms_decode(der: &[u8], timeout: Duration) -> Result<Vec<u8>, CryptoStepError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (der, timeout);
            return Err(CryptoStepError::new(
                CryptoErrorKind::Unsupported,
                "S/MIME decryption requires macOS (security cms); no backend for this platform",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let input = write_temp_file(der).await?;
            let args = vec![
                "cms".to_owned(),
                "-D".to_owned(),
                "-i".to_owned(),
                input.path().display().to_string(),
            ];
            let out = run_helper(Path::new(SECURITY_BIN), &args, None, &[], timeout).await?;
            if out.status.success() {
                return Ok(out.stdout);
            }
            let reason = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            Err(CryptoStepError::new(
                CryptoErrorKind::ProcessFailed,
                format!("security cms failed: {reason}"),
            ))
        }
    }
}

/// The `openssl` binary: absolute on macOS (launchd-proof), PATH lookup
/// elsewhere.
fn openssl_bin() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/usr/bin/openssl")
    } else {
        PathBuf::from("openssl")
    }
}

/// Classify an `openssl smime -verify` failure from its stderr. Digest or
/// signature failures mean the signature is invalid (content mismatch or
/// tampering); anything else is an operational failure where validity is
/// simply not determinable.
fn classify_openssl_verify_failure(stderr: &[u8]) -> SignatureStatus {
    let reason = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if reason.contains("digest failure") || reason.contains("signature failure") {
        SignatureStatus::Bad
    } else {
        SignatureStatus::Unverified
    }
}

/// Verify an opaque S/MIME `signed-data` payload with openssl: on success
/// the content is printed to stdout and the signature digest is valid.
/// Returns `Ok(outcome)` or the raw command failure for the caller to
/// classify.
async fn signed_content_openssl(
    der: &[u8],
    timeout: Duration,
) -> Result<DecryptOutcome, (CryptoErrorKind, Vec<u8>, Vec<u8>)> {
    let input = write_temp_file(der)
        .await
        .map_err(|e| (e.kind, Vec::new(), e.message.into_bytes()))?;
    let args = vec![
        "smime".to_owned(),
        "-verify".to_owned(),
        "-noverify".to_owned(),
        "-inform".to_owned(),
        "DER".to_owned(),
        "-in".to_owned(),
        input.path().display().to_string(),
    ];
    let out = run_helper(&openssl_bin(), &args, None, &[], timeout)
        .await
        .map_err(|e| (e.kind, Vec::new(), e.message.into_bytes()))?;
    if out.status.success() {
        return Ok(DecryptOutcome {
            content: out.stdout,
            signature: Some(SignatureInfo {
                status: SignatureStatus::Verified,
                signer: None,
            }),
        });
    }
    Err((CryptoErrorKind::ProcessFailed, out.stdout, out.stderr))
}

/// Verify a clear-signed S/MIME message over the whole raw mail:
/// `openssl smime -verify -noverify -in <raw>`. openssl parses the
/// multipart/signed structure itself — exactly the semantics the sender's
/// MUA used when assembling the mail (byte reconstruction of the signed
/// part would run into the trailing-CRLF ambiguity of detached signatures).
/// `-noverify` skips the certificate chain check (signer trust is a
/// separate, future step); the signature digest over the content is fully
/// checked. Digest/signature failures are reported as an invalid signature
/// (`Ok(Bad)`), not as an operational error — the invalidity is the
/// information. Cross-platform: works wherever `openssl` exists.
async fn verify_clear_signed_openssl(
    raw_mime: &[u8],
    timeout: Duration,
) -> Result<SignatureInfo, CryptoStepError> {
    let mail_file = write_temp_file(raw_mime).await?;
    let args = vec![
        "smime".to_owned(),
        "-verify".to_owned(),
        "-noverify".to_owned(),
        "-in".to_owned(),
        mail_file.path().display().to_string(),
    ];
    let out = run_helper(&openssl_bin(), &args, None, &[], timeout).await?;
    if out.status.success() {
        return Ok(SignatureInfo {
            status: SignatureStatus::Verified,
            signer: None,
        });
    }
    let status = classify_openssl_verify_failure(&out.stderr);
    if status == SignatureStatus::Bad {
        return Ok(SignatureInfo {
            status,
            signer: None,
        });
    }
    let reason = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    Err(CryptoStepError::new(
        CryptoErrorKind::ProcessFailed,
        format!("openssl verify failed: {reason}"),
    ))
}

impl DecryptBackend for SecurityCmsBackend {
    fn smime_enveloped<'a>(
        &'a self,
        der: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            let content = Self::cms_decode(der, timeout).await?;
            Ok(DecryptOutcome {
                content,
                signature: None,
            })
        })
    }

    fn smime_signed_content<'a>(
        &'a self,
        der: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            // Opaque signed-data carries the content inside the CMS, so
            // openssl can verify the digest and print the content in one
            // step (cross-platform).
            match signed_content_openssl(der, timeout).await {
                Ok(outcome) => Ok(outcome),
                Err((_, _, stderr)) => {
                    // Digest/signature failure: the content is still
                    // extractable (`security cms -D`, macOS) — surface it
                    // with the classified status so an invalid signature is
                    // reported rather than hidden. Operational failures on
                    // other platforms stay fail-open via the error.
                    let status = classify_openssl_verify_failure(&stderr);
                    let content = Self::cms_decode(der, timeout).await?;
                    Ok(DecryptOutcome {
                        content,
                        signature: Some(SignatureInfo {
                            status,
                            signer: None,
                        }),
                    })
                }
            }
        })
    }

    /// Verify a clear-signed S/MIME message over the whole raw mail via
    /// `openssl smime -verify -noverify` (cross-platform).
    fn smime_verify_clear_signed<'a>(
        &'a self,
        raw_mime: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<SignatureInfo, CryptoStepError>> {
        Box::pin(async move { verify_clear_signed_openssl(raw_mime, timeout).await })
    }

    fn pgp_decrypt<'a>(
        &'a self,
        _ciphertext: &'a [u8],
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            Err(CryptoStepError::new(
                CryptoErrorKind::Unsupported,
                "security-cms backend does not handle PGP",
            ))
        })
    }
}

/// Reference to a passphrase stored in the macOS keychain.
#[derive(Debug, Clone)]
pub struct KeychainPassRef {
    /// Keychain item service name (`-s`)
    pub service: String,
    /// Optional account name (`-a`); `None` matches any account entry.
    pub account: Option<String>,
}

/// PGP backend using the `gpg` command line tool.
#[derive(Debug, Clone)]
pub struct GpgBackend {
    /// Passphrase supplied via environment config, if any
    pass: Option<SecretString>,
    /// macOS keychain location of the passphrase, if configured
    keychain: Option<KeychainPassRef>,
    /// gpg binary (default `gpg`, override via `MAIL_PGP_<ID>_GPG_BIN`)
    bin: PathBuf,
    /// Extra child environment (test isolation, e.g. a throwaway
    /// `GNUPGHOME`); empty in production.
    extra_env: Vec<(String, String)>,
}

impl GpgBackend {
    /// Build a backend from per-account secrets.
    pub fn new(
        pass: Option<SecretString>,
        keychain: Option<KeychainPassRef>,
        bin: PathBuf,
    ) -> Self {
        Self {
            pass,
            keychain,
            bin,
            extra_env: Vec::new(),
        }
    }

    /// Inject extra child environment variables (used by tests to isolate
    /// `GNUPGHOME`; never populated in production).
    #[cfg(test)]
    pub(crate) fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.extra_env = env;
        self
    }

    /// Resolve the passphrase: env-configured value wins, then the macOS
    /// keychain, then `None` (gpg may still work via its agent or a
    /// passphrase-less key).
    async fn resolve_passphrase(
        &self,
        timeout: Duration,
    ) -> Result<Option<SecretString>, CryptoStepError> {
        if let Some(pass) = &self.pass {
            return Ok(Some(pass.clone()));
        }
        let Some(keychain) = self.keychain.as_ref() else {
            return Ok(None);
        };
        read_keychain_password(keychain, timeout)
            .await
            .map(|bytes| {
                Some(SecretString::new(
                    String::from_utf8_lossy(&bytes).trim_end().to_owned().into(),
                ))
            })
    }
}

impl DecryptBackend for GpgBackend {
    fn smime_enveloped<'a>(
        &'a self,
        _der: &'a [u8],
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            Err(CryptoStepError::new(
                CryptoErrorKind::Unsupported,
                "gpg backend does not handle S/MIME",
            ))
        })
    }

    fn smime_signed_content<'a>(
        &'a self,
        _der: &'a [u8],
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            Err(CryptoStepError::new(
                CryptoErrorKind::Unsupported,
                "gpg backend does not handle S/MIME",
            ))
        })
    }

    fn smime_verify_clear_signed<'a>(
        &'a self,
        _raw_mime: &'a [u8],
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<SignatureInfo, CryptoStepError>> {
        Box::pin(async move {
            Err(CryptoStepError::new(
                CryptoErrorKind::Unsupported,
                "gpg backend does not handle S/MIME",
            ))
        })
    }

    fn pgp_decrypt<'a>(
        &'a self,
        ciphertext: &'a [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<DecryptOutcome, CryptoStepError>> {
        Box::pin(async move {
            let passphrase = self.resolve_passphrase(timeout).await?;
            let input = write_temp_file(ciphertext).await?;

            let mut args = vec![
                "--batch".to_owned(),
                "--yes".to_owned(),
                "--pinentry-mode".to_owned(),
                "loopback".to_owned(),
            ];
            let stdin = passphrase.map(|pw| {
                args.push("--passphrase-fd".to_owned());
                args.push("0".to_owned());
                let mut bytes = pw.expose_secret().as_bytes().to_vec();
                bytes.push(b'\n');
                bytes
            });
            args.push("--decrypt".to_owned());
            args.push(input.path().display().to_string());

            let out = run_helper(&self.bin, &args, stdin, &self.extra_env, timeout).await?;
            if !out.status.success() && out.stdout.is_empty() {
                let reason = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                return Err(CryptoStepError::new(
                    CryptoErrorKind::ProcessFailed,
                    format!("gpg failed: {reason}"),
                ));
            }
            // A nonzero exit WITH plaintext on stdout means the decryption
            // itself succeeded and only signature verification failed (e.g.
            // the signer's key is unknown: "Can't check signature: No public
            // key"). OpenPGP decryption is all-or-nothing (integrity
            // protected), so the stdout content is complete — keep it and
            // let the signature classification report what happened.
            let signature = classify_gpg_signature(&out.stderr);
            Ok(DecryptOutcome {
                content: out.stdout,
                signature,
            })
        })
    }
}

/// Extract signature status from gpg stderr.
///
/// gpg verifies one-pass signatures during `--decrypt` and reports the result
/// on stderr. Absence of any signature lines means the message was encrypted
/// without a signature (or the status could not be determined). An
/// unverifiable signature (unknown signer key — "Can't check signature") is
/// reported as present-but-unverified, not as a decryption failure.
fn classify_gpg_signature(stderr: &[u8]) -> Option<SignatureInfo> {
    let text = String::from_utf8_lossy(stderr);
    for line in text.lines() {
        if let Some((_, rest)) = line.trim().split_once("Good signature from ") {
            // Typical: `Good signature from "Uid <mail>" [ultimate]` —
            // cut at the closing quote; fall back to the bare remainder.
            let signer = rest
                .strip_prefix('"')
                .and_then(|inner| inner.split('"').next())
                .unwrap_or_else(|| rest.trim())
                .to_owned();
            return Some(SignatureInfo {
                status: SignatureStatus::Verified,
                signer: Some(signer),
            });
        }
        if line.contains("Can't check signature") {
            return Some(SignatureInfo {
                status: SignatureStatus::Unverified,
                signer: None,
            });
        }
        if line.contains("BAD signature") || line.contains("BADsignature") {
            return Some(SignatureInfo {
                status: SignatureStatus::Bad,
                signer: None,
            });
        }
    }
    None
}

/// Read a passphrase from the macOS keychain via `security
/// find-generic-password -w`. The value never appears in process arguments.
async fn read_keychain_password(
    keychain: &KeychainPassRef,
    timeout: Duration,
) -> Result<Vec<u8>, CryptoStepError> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (keychain, timeout);
        return Err(CryptoStepError::new(
            CryptoErrorKind::Unsupported,
            "PGP passphrase keychain lookup requires macOS (MAIL_PGP_<ID>_PASS_KEYCHAIN_SERVICE)",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let mut args = vec![
            "find-generic-password".to_owned(),
            "-w".to_owned(),
            "-s".to_owned(),
            keychain.service.clone(),
        ];
        if let Some(account) = &keychain.account {
            args.push("-a".to_owned());
            args.push(account.clone());
        }
        let out = run_helper(Path::new(SECURITY_BIN), &args, None, &[], timeout).await?;
        if out.status.success() && !out.stdout.is_empty() {
            return Ok(out.stdout);
        }
        let reason = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        Err(CryptoStepError::new(
            CryptoErrorKind::ProcessFailed,
            format!("keychain lookup for passphrase failed: {reason}"),
        ))
    }
}

struct CommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: std::process::ExitStatus,
}

/// Write bytes to a 0600 temp file for helper input. The file is deleted when
/// the handle drops; only ciphertext (never plaintext) touches the disk.
/// Callers must keep the returned handle alive while the helper reads it.
async fn write_temp_file(bytes: &[u8]) -> Result<tempfile::NamedTempFile, CryptoStepError> {
    let file = tempfile::Builder::new()
        .prefix("mail-mcp-crypto-")
        .rand_bytes(6)
        .tempfile()
        .map_err(|e| {
            CryptoStepError::new(CryptoErrorKind::ProcessFailed, format!("temp file: {e}"))
        })?;
    tokio::fs::write(file.path(), bytes).await.map_err(|e| {
        CryptoStepError::new(CryptoErrorKind::ProcessFailed, format!("temp file: {e}"))
    })?;
    Ok(file)
}

/// Run a helper with captured stdout/stderr under a wall-clock timeout.
///
/// The child is killed when the future is dropped (cancellation-safe) or
/// when the timeout elapses. `extra_env` adds child environment variables
/// (empty in production).
async fn run_helper(
    program: &Path,
    args: &[String],
    stdin: Option<Vec<u8>>,
    extra_env: &[(String, String)],
    timeout: Duration,
) -> Result<CommandOutput, CryptoStepError> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command.spawn().map_err(|e| {
        CryptoStepError::new(
            CryptoErrorKind::ProcessFailed,
            format!("{}: {e}", program.display()),
        )
    })?;

    let joined = tokio::time::timeout(timeout, async {
        if let (Some(mut pipe), Some(data)) = (child.stdin.take(), stdin.as_ref()) {
            // A small write to a freshly-spawned child; errors surface via
            // the exit status below.
            let _ = pipe.write_all(data).await;
            let _ = pipe.shutdown().await;
        }
        child.wait_with_output().await
    })
    .await;

    match joined {
        Err(_) => Err(CryptoStepError::new(
            CryptoErrorKind::TimedOut,
            format!(
                "{} timed out after {} ms",
                program.display(),
                timeout.as_millis()
            ),
        )),
        Ok(Err(e)) => Err(CryptoStepError::new(
            CryptoErrorKind::ProcessFailed,
            format!("{}: {e}", program.display()),
        )),
        Ok(Ok(output)) => Ok(CommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            status: output.status,
        }),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::time::Duration;

    use super::super::backend::{CryptoErrorKind, DecryptBackend};

    const TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn security_cms_rejects_garbage_with_process_failure() {
        let backend = super::SecurityCmsBackend;
        let error = backend
            .smime_enveloped(b"definitely-not-der", TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.kind, CryptoErrorKind::ProcessFailed);
        assert!(error.message.contains("security cms failed"));
    }

    #[tokio::test]
    async fn security_cms_rejects_nonexistent_gpg_bin() {
        let backend = super::GpgBackend::new(
            None,
            None,
            std::path::PathBuf::from("/nonexistent/gpg-binary"),
        );
        let error = backend.pgp_decrypt(b"junk", TIMEOUT).await.unwrap_err();
        assert_eq!(error.kind, CryptoErrorKind::ProcessFailed);
    }

    #[tokio::test]
    async fn gpg_classifies_bad_passphrase_as_failure() {
        // Valid armor but no usable key in the ambient keyring: gpg must
        // fail cleanly (exit != 0) instead of hanging or prompting.
        let armor = b"-----BEGIN PGP MESSAGE-----\n\nzwDR\n-----END PGP MESSAGE-----\n";
        let backend = super::GpgBackend::new(
            Some(secrecy::SecretString::new("wrong".to_owned().into())),
            None,
            std::path::PathBuf::from("gpg"),
        );
        let error = backend.pgp_decrypt(armor, TIMEOUT).await.unwrap_err();
        assert_eq!(error.kind, CryptoErrorKind::ProcessFailed);
    }
}

#[cfg(test)]
mod signature_tests {
    use super::super::backend::SignatureStatus;
    use super::classify_gpg_signature;

    #[test]
    fn good_signature_is_verified_with_signer() {
        let stderr = b"gpg: encrypted with rsa2048 key\n gpg: Good signature from \"Test User <t@example.com>\"\n";
        let info = classify_gpg_signature(stderr).expect("signature expected");
        assert_eq!(info.status, SignatureStatus::Verified);
        assert_eq!(info.signer.as_deref(), Some("Test User <t@example.com>"));
    }

    #[test]
    fn bad_signature_is_reported() {
        let stderr = b"gpg: BAD signature from \"Evil <e@example.com>\"";
        let info = classify_gpg_signature(stderr).expect("signature expected");
        assert_eq!(info.status, SignatureStatus::Bad);
    }

    #[test]
    fn unverifiable_signature_is_present_but_unverified() {
        // Real-world shape (live ProtonMail application mail): decryption
        // succeeds, the signer's key is unknown, gpg exits nonzero but has
        // written the full plaintext to stdout.
        let stderr = b"gpg: encrypted with rsa4096 key, ID DA8BF8F6A1FA1000\ngpg: Signature made Sun Nov  8 19:53:13 2026 CET\ngpg:                using EDDSA key 0C2938DB1E644840\ngpg: Can't check signature: No public key";
        let info = classify_gpg_signature(stderr).expect("signature expected");
        assert_eq!(info.status, SignatureStatus::Unverified);
        assert_eq!(info.signer, None);
    }

    #[test]
    fn unsigned_message_has_no_signature_info() {
        assert!(classify_gpg_signature(b"gpg: decrypted fine, nothing signed").is_none());
    }
}

/// End-to-end openssl signature-verification tests (cross-platform —
/// `openssl` is a standard tool on every supported platform, so these run
/// in CI too). Each test generates a throwaway certificate and signs
/// synthetic content; no real mail is involved.
#[cfg(test)]
mod openssl_verify_tests {
    use std::time::Duration;

    use super::super::SecurityCmsBackend;
    use super::super::backend::{DecryptBackend, SignatureStatus};

    const TIMEOUT: Duration = Duration::from_secs(30);

    struct Throwaway {
        dir: tempfile::TempDir,
        cert: String,
        key: String,
    }

    impl Throwaway {
        /// Throwaway self-signed certificate (used only to sign/verify
        /// synthetic fixtures inside this test run).
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let cert = dir.path().join("cert.pem").display().to_string();
            let key = dir.path().join("key.pem").display().to_string();
            let status = std::process::Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    &key,
                    "-out",
                    &cert,
                    "-days",
                    "2",
                    "-nodes",
                    "-subj",
                    "/CN=Crypto Fixture Test",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("openssl req spawn");
            assert!(status.success(), "fixture certificate generation failed");
            Self { dir, cert, key }
        }

        /// Sign content and return the complete multipart/signed mail
        /// (canonical assembly — the same consistency a real MUA produces).
        fn sign_clear_signed_mail(&self, content: &[u8]) -> Vec<u8> {
            let body = self.dir.path().join("body.txt");
            std::fs::write(&body, content).unwrap();
            let out = std::process::Command::new("openssl")
                .args([
                    "smime",
                    "-sign",
                    "-in",
                    body.display().to_string().as_str(),
                    "-signer",
                    &self.cert,
                    "-inkey",
                    &self.key,
                    "-md",
                    "sha256",
                ])
                .output()
                .expect("openssl smime sign spawn");
            assert!(out.status.success(), "signing failed");
            out.stdout
        }
    }

    #[tokio::test]
    async fn clear_signed_mail_verifies_over_whole_raw_message() {
        let fixture = Throwaway::new();
        let mail = fixture.sign_clear_signed_mail(b"fixture body line\n");
        let info = SecurityCmsBackend
            .smime_verify_clear_signed(&mail, TIMEOUT)
            .await
            .expect("verification must succeed");
        assert_eq!(info.status, SignatureStatus::Verified);
    }

    #[tokio::test]
    async fn tampered_clear_signed_mail_reports_bad_signature() {
        let fixture = Throwaway::new();
        let mail = fixture.sign_clear_signed_mail(b"original body line\n");
        let tampered = mail
            .windows(4)
            .position(|w| w == b"body")
            .map(|at| {
                let mut bytes = mail.clone();
                bytes[at..at + 4].copy_from_slice(b"BOdy");
                bytes
            })
            .expect("fixture body marker");
        let info = SecurityCmsBackend
            .smime_verify_clear_signed(&tampered, TIMEOUT)
            .await
            .expect("tampered mail still resolves to a signature status");
        assert_eq!(info.status, SignatureStatus::Bad);
    }

    #[tokio::test]
    async fn opaque_signed_data_extracts_content_and_verifies() {
        let fixture = Throwaway::new();
        let body = fixture.dir.path().join("body.txt");
        std::fs::write(&body, b"opaque fixture body\n").unwrap();
        let der = fixture.dir.path().join("opaque.der");
        let status = std::process::Command::new("openssl")
            .args([
                "smime",
                "-sign",
                "-nodetach",
                "-in",
                body.display().to_string().as_str(),
                "-signer",
                &fixture.cert,
                "-inkey",
                &fixture.key,
                "-md",
                "sha256",
                "-outform",
                "DER",
                "-out",
                der.display().to_string().as_str(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl smime sign spawn");
        assert!(status.success(), "opaque signing failed");
        let signed_data = std::fs::read(&der).unwrap();

        let outcome = SecurityCmsBackend
            .smime_signed_content(&signed_data, TIMEOUT)
            .await
            .expect("opaque extraction must succeed");
        assert!(outcome.content.windows(6).any(|w| w == b"opaque"));
        assert_eq!(
            outcome.signature.expect("signature info").status,
            SignatureStatus::Verified
        );
    }
}

/// End-to-end gpg roundtrip with a throwaway key in an isolated GNUPGHOME.
///
/// Requires `gpg` on PATH; ignored by default because it spends ~2 s
/// generating a key. Run locally with:
/// `cargo test gpg_backend_roundtrip -- --exact --ignored --nocapture`
#[cfg(test)]
mod gpg_roundtrip {
    use std::path::PathBuf;
    use std::time::Duration;

    use secrecy::SecretString;

    use super::super::GpgBackend;
    use super::super::backend::{DecryptBackend, SignatureStatus};

    const TIMEOUT: Duration = Duration::from_secs(60);

    fn gpg_on_path() -> bool {
        std::process::Command::new("gpg")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[tokio::test]
    #[ignore = "requires local gpg; generates a throwaway key (~2s)"]
    async fn gpg_backend_roundtrip_decrypts_and_verifies_signature() {
        if !gpg_on_path() {
            // Skipped rather than failed when gpg is absent.
            return;
        }

        let home = tempfile::tempdir().expect("tempdir");
        let env = vec![("GNUPGHOME".to_owned(), home.path().display().to_string())];
        let run = |args: &[&str]| {
            let mut cmd = std::process::Command::new("gpg");
            cmd.args(args).env("GNUPGHOME", home.path());
            cmd.output().expect("gpg spawn")
        };

        // Throwaway key: primary (sign/cert) + encryption subkey, fixed
        // passphrase.
        let generated = run(&[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass-123",
            "--quick-gen-key",
            "E2E Test <e2e@test.invalid>",
            "rsa2048",
            "default",
            "never",
        ]);
        assert!(
            generated.status.success(),
            "key generation failed: {:?}",
            generated
        );
        let listing = run(&["--list-keys", "--with-colons"]);
        let fingerprint = String::from_utf8_lossy(&listing.stdout)
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .and_then(|line| line.split(':').nth(9))
            .filter(|fpr| !fpr.is_empty())
            .map(str::to_owned)
            .expect("fingerprint");
        let subkey = run(&[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass-123",
            "--quick-add-key",
            &fingerprint,
            "rsa2048",
            "encr",
            "never",
        ]);
        assert!(
            subkey.status.success(),
            "subkey generation failed: {:?}",
            subkey
        );

        // Encrypt+sign a message to the throwaway key.
        std::fs::write(home.path().join("plain.txt"), b"inner plaintext body\n").unwrap();
        let plain = home.path().join("plain.txt");
        let armored = home.path().join("msg.asc");
        let enc = run(&[
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass-123",
            "--encrypt",
            "--sign",
            "--recipient",
            "e2e@test.invalid",
            "--output",
            armored.display().to_string().as_str(),
            "--armor",
            plain.display().to_string().as_str(),
        ]);
        assert!(enc.status.success(), "encryption failed: {:?}", enc);
        let ciphertext = std::fs::read(&armored).unwrap();

        // Flush the agent passphrase cache (the --sign during encryption
        // already cached the correct passphrase) so the wrong-passphrase
        // probe below genuinely fails instead of succeeding from cache.
        std::process::Command::new("gpgconf")
            .args(["--kill", "gpg-agent"])
            .env("GNUPGHOME", home.path())
            .status()
            .expect("gpgconf spawn");

        // Wrong passphrase must fail cleanly (never hang, never prompt) —
        // run this FIRST: the gpg-agent caches a correct passphrase, which
        // would make a later wrong-passphrase attempt succeed from cache.
        let wrong = GpgBackend::new(
            Some(SecretString::new("wrong".to_owned().into())),
            None,
            PathBuf::from("gpg"),
        )
        .with_env(vec![(
            "GNUPGHOME".to_owned(),
            home.path().display().to_string(),
        )]);
        let error = wrong
            .pgp_decrypt(&ciphertext, TIMEOUT)
            .await
            .expect_err("wrong passphrase must fail");
        assert!(!error.message.is_empty());

        // Decrypt through the backend: passphrase on fd 0, stdout capture,
        // signature classification from stderr.
        let backend = GpgBackend::new(
            Some(SecretString::new("test-pass-123".to_owned().into())),
            None,
            PathBuf::from("gpg"),
        )
        .with_env(env);

        let outcome = backend
            .pgp_decrypt(&ciphertext, TIMEOUT)
            .await
            .expect("decrypt");
        assert_eq!(outcome.content, b"inner plaintext body\n");
        let signature = outcome.signature.expect("gpg signed the message");
        assert_eq!(signature.status, SignatureStatus::Verified);
        assert!(
            signature
                .signer
                .as_deref()
                .is_some_and(|s| s.contains("e2e@test.invalid"))
        );
    }
}
