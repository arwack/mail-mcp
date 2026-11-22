//! Transparent, config-gated decryption of S/MIME and PGP mail (read path).
//!
//! When an account has crypto enabled (`MAIL_SMIME_<ID>_ENABLED` /
//! `MAIL_PGP_<ID>_ENABLED`), `imap_get_message` transparently decrypts
//! recognized encrypted/signed structures and returns the message as if it
//! had never been encrypted; `imap_get_attachment` resolves attachment parts
//! inside the decrypted content (prefixed part ids). Failures are fail-open:
//! the original view plus a `crypto` block explaining what happened — the
//! tool call itself never fails because of decryption.
//!
//! **Inert by construction:** with no crypto settings, `CryptoConfig` is
//! empty, no `CryptoService` is built, detection never runs, and no
//! subprocess is ever spawned — behavior and tool schema are byte-identical
//! for deployments that do not opt in.
//!
//! Step 1 uses subprocess helpers (`security cms` on macOS, `gpg` for PGP)
//! behind the [`backend::DecryptBackend`] trait; a native-Rust backend can
//! replace them later without touching this orchestration or the server
//! integration.

pub mod backend;
pub mod detect;
pub mod subprocess;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::config_file::{Settings, segments_with_suffix};
use crate::errors::AppResult;
use crate::mime;

use backend::DecryptBackend;
use detect::Detected;
use subprocess::{GpgBackend, KeychainPassRef, SecurityCmsBackend};

/// Human-readable failure reason from a backend error, using the coarse
/// classification for the timeout case (process failures already carry
/// their own bounded message).
fn failure_reason(error: backend::CryptoStepError) -> String {
    match error.kind {
        backend::CryptoErrorKind::TimedOut => format!("decryption timed out: {}", error.message),
        backend::CryptoErrorKind::Unsupported | backend::CryptoErrorKind::ProcessFailed => {
            error.message
        }
    }
}

/// Part-id prefix for attachments found inside decrypted content. Outer
/// part ids are always numeric (`1`, `1.2`), so the alphabetic prefix makes
/// collisions impossible and lets `imap_get_attachment` tell inner and outer
/// parts apart.
pub const INNER_PART_PREFIX: &str = "d";

/// Default wall-clock budget for one crypto helper subprocess
/// (`MAIL_CRYPTO_TIMEOUT_MS`).
pub const DEFAULT_CRYPTO_TIMEOUT_MS: u64 = 30_000;

/// Per-account crypto settings.
#[derive(Debug, Clone, Default)]
pub struct AccountCryptoConfig {
    /// S/MIME read path enabled (`MAIL_SMIME_<ID>_ENABLED=true`)
    pub smime_enabled: bool,
    /// PGP read path enabled (`MAIL_PGP_<ID>_ENABLED=true`)
    pub pgp_enabled: bool,
    /// PGP passphrase from `MAIL_PGP_<ID>_PASS` (env)
    pub pgp_pass: Option<SecretString>,
    /// macOS keychain service holding the PGP passphrase
    pub pgp_pass_keychain_service: Option<String>,
    /// Optional keychain account name for the passphrase item
    pub pgp_pass_keychain_account: Option<String>,
    /// gpg binary (default `gpg`, override via `MAIL_PGP_<ID>_GPG_BIN`)
    pub gpg_bin: std::path::PathBuf,
}

impl AccountCryptoConfig {
    /// Whether this account opted into any crypto read path.
    pub fn enabled(&self) -> bool {
        self.smime_enabled || self.pgp_enabled
    }
}

/// Server-wide crypto configuration, discovered presence-based from
/// `MAIL_SMIME_*` / `MAIL_PGP_*` settings.
#[derive(Debug, Clone, Default)]
pub struct CryptoConfig {
    /// Per-account settings, keyed by `account_id`
    pub accounts: BTreeMap<String, AccountCryptoConfig>,
    /// Subprocess wall-clock budget in milliseconds
    pub timeout_ms: u64,
}

impl CryptoConfig {
    /// Load crypto settings from the effective `MAIL_*` map.
    ///
    /// Absence of all `MAIL_SMIME_*` / `MAIL_PGP_*` keys yields an empty
    /// config (inert). Explicit `ENABLED=false` disables that path for the
    /// account.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for malformed boolean/u64 values (the value is
    /// never echoed, so a misplaced secret in a key name is not printed).
    pub fn load(settings: &Settings) -> AppResult<Self> {
        let mut accounts: BTreeMap<String, AccountCryptoConfig> = BTreeMap::new();

        for segment in segments_with_suffix(settings, "MAIL_SMIME_", "ENABLED") {
            let key = format!("MAIL_SMIME_{segment}_ENABLED");
            if crate::config::parse_bool_setting(settings, &key, false)? {
                accounts
                    .entry(segment.to_ascii_lowercase())
                    .or_default()
                    .smime_enabled = true;
            }
        }

        for segment in segments_with_suffix(settings, "MAIL_PGP_", "ENABLED") {
            let prefix = format!("MAIL_PGP_{segment}_");
            let account_id = segment.to_ascii_lowercase();
            if !crate::config::parse_bool_setting(settings, &format!("{prefix}ENABLED"), false)? {
                continue;
            }
            let account = accounts.entry(account_id).or_default();
            account.pgp_enabled = true;
            account.pgp_pass = setting_value(settings, &format!("{prefix}PASS"))
                .map(|v| SecretString::new(v.to_owned().into()));
            account.pgp_pass_keychain_service =
                setting_value(settings, &format!("{prefix}PASS_KEYCHAIN_SERVICE"))
                    .map(str::to_owned);
            account.pgp_pass_keychain_account =
                setting_value(settings, &format!("{prefix}PASS_KEYCHAIN_ACCOUNT"))
                    .map(str::to_owned);
            account.gpg_bin = setting_value(settings, &format!("{prefix}GPG_BIN"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("gpg"));
        }

        let timeout_ms = crate::config::parse_u64_setting(
            settings,
            "MAIL_CRYPTO_TIMEOUT_MS",
            DEFAULT_CRYPTO_TIMEOUT_MS,
        )?;

        Ok(Self {
            accounts,
            timeout_ms,
        })
    }

    /// Whether any account opted into crypto (drives `CryptoService`
    /// construction).
    pub fn has_enabled_account(&self) -> bool {
        self.accounts.values().any(AccountCryptoConfig::enabled)
    }
}

/// Non-empty trimmed setting value.
fn setting_value<'a>(settings: &'a Settings, key: &str) -> Option<&'a str> {
    settings
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Parsing limits applied to decrypted inner content (mirrors the
/// `imap_get_message` inputs so the inner view honors the same bounds).
#[derive(Debug, Clone, Copy)]
pub struct InnerViewLimits {
    /// Maximum body characters for the inner view
    pub body_max_chars: usize,
    /// Whether to include sanitized HTML body from the inner view
    pub include_html: bool,
    /// Whether to extract text from inner PDF attachments
    pub extract_attachment_text: bool,
    /// Maximum extracted text length per inner PDF attachment
    pub attachment_text_max_chars: usize,
}

/// Crypto metadata block attached to `imap_get_message` responses.
///
/// Present only when an encrypted/signed structure was detected for an
/// account with crypto configured. Field semantics:
///
/// - `encrypted` — the structure actually encrypted content (enveloped-data,
///   PGP ciphertext). `false` means signed-only.
/// - `decrypted` — the readable inner content was recovered (decrypted or,
///   for opaque signed-data, extracted). `false` plus `failure_reason`
///   explains the fallback to the original view.
/// - `signed`/`verified` — signature presence/verification when knowable;
///   `null` means no signature found or not checked in this step.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
pub struct CryptoBlock {
    /// Crypto scheme: `smime` or `pgp`
    pub scheme: String,
    /// Whether the structure encrypted content (vs. signing only)
    pub encrypted: bool,
    /// Whether readable inner content was recovered
    pub decrypted: bool,
    /// Whether a signature was detected, if determinable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Whether the signature verified, if checked
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// Signer common name, when reported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_cn: Option<String>,
    /// Signer email address, when reported
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_email: Option<String>,
    /// Bounded, secret-free reason when `decrypted` is `false`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Outer MIME part id that carried the crypto payload
    pub original_part_id: String,
    /// Prefix applied to part ids inside the decrypted content
    pub inner_part_prefix: String,
}

impl CryptoBlock {
    /// New failure block: detected but not recovered.
    fn failure(detected: &Detected, reason: String) -> Self {
        Self {
            scheme: detected.kind.scheme().to_owned(),
            encrypted: detected.kind.is_encrypted(),
            decrypted: false,
            signed: None,
            verified: None,
            signer_cn: None,
            signer_email: None,
            failure_reason: Some(crate::mime::truncate_chars(reason, 200)),
            original_part_id: detected.part_id.clone(),
            inner_part_prefix: INNER_PART_PREFIX.to_owned(),
        }
    }
}

/// Outcome of running the crypto pipeline for one message.
#[derive(Debug)]
pub struct Resolution {
    /// Metadata block for the response
    pub block: CryptoBlock,
    /// Recovered inner bytes when decryption/extraction succeeded
    pub inner: Option<Arc<Vec<u8>>>,
}

/// Successful decryption cache entry.
struct CacheEntry {
    inner: Arc<Vec<u8>>,
    block: CryptoBlock,
    inserted_at: Instant,
    expires_at: Instant,
}

/// Cache lifetime for decrypted content (mirrors the cursor TTL default).
const CACHE_TTL: Duration = Duration::from_secs(600);
/// Upper bound of cached decryptions (a full body read plus a few
/// attachment downloads should hit one entry per message).
const CACHE_MAX_ENTRIES: usize = 16;

/// Orchestrates detection, backends, and the decrypted-content cache.
///
/// Constructed only when at least one account opted in; `None` otherwise
/// (see [`CryptoService::opt_new`]).
pub struct CryptoService {
    accounts: BTreeMap<String, AccountCryptoConfig>,
    smime_backend: Arc<SecurityCmsBackend>,
    pgp_backends: HashMap<String, Arc<GpgBackend>>,
    timeout: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl CryptoService {
    /// Build the service from crypto config.
    pub fn new(config: &CryptoConfig) -> Self {
        let mut pgp_backends = HashMap::new();
        for (account_id, account) in &config.accounts {
            if !account.pgp_enabled {
                continue;
            }
            let keychain =
                account
                    .pgp_pass_keychain_service
                    .as_ref()
                    .map(|service| KeychainPassRef {
                        service: service.clone(),
                        account: account.pgp_pass_keychain_account.clone(),
                    });
            pgp_backends.insert(
                account_id.clone(),
                Arc::new(GpgBackend::new(
                    account.pgp_pass.clone(),
                    keychain,
                    account.gpg_bin.clone(),
                )),
            );
        }
        Self {
            accounts: config.accounts.clone(),
            smime_backend: Arc::new(SecurityCmsBackend),
            pgp_backends,
            timeout: Duration::from_millis(config.timeout_ms.max(1)),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `Some` only when at least one account opted in; `None` keeps the
    /// server fully inert.
    pub fn opt_new(config: &CryptoConfig) -> Option<Arc<Self>> {
        if config.has_enabled_account() {
            Some(Arc::new(Self::new(config)))
        } else {
            None
        }
    }

    /// Whether this account opted into any crypto read path.
    pub fn has_account(&self, account_id: &str) -> bool {
        self.accounts
            .get(account_id)
            .is_some_and(AccountCryptoConfig::enabled)
    }

    /// Run the crypto pipeline for one raw message.
    ///
    /// Returns `None` when the account has no crypto config or the message
    /// carries no decryptable structure (inert cases — callers keep the
    /// plain view). `Some` otherwise, with `inner` bytes on success.
    pub async fn resolve(
        &self,
        account_id: &str,
        cache_key: &str,
        raw: &[u8],
    ) -> Option<Resolution> {
        let account = self.accounts.get(account_id)?;
        let detected = detect::detect(raw)?;

        if let Some(cached) = self.cache_get(cache_key) {
            return Some(Resolution {
                block: cached.block,
                inner: Some(cached.inner),
            });
        }

        // Select the backend for the detected kind; disabled paths yield a
        // failure block (fail-open: original view plus explanation).
        let backend: Arc<dyn DecryptBackend> = match detected.kind {
            detect::CryptoKind::SmimeEnveloped
            | detect::CryptoKind::SmimeSigned
            | detect::CryptoKind::SmimeClearSigned
                if !account.smime_enabled =>
            {
                return Some(Resolution {
                    block: CryptoBlock::failure(
                        &detected,
                        "S/MIME decryption is not enabled for this account (set MAIL_SMIME_<ID>_ENABLED=true)".to_owned(),
                    ),
                    inner: None,
                });
            }
            detect::CryptoKind::SmimeEnveloped
            | detect::CryptoKind::SmimeSigned
            | detect::CryptoKind::SmimeClearSigned => self.smime_backend.clone(),
            detect::CryptoKind::PgpMime | detect::CryptoKind::PgpInline if !account.pgp_enabled => {
                return Some(Resolution {
                    block: CryptoBlock::failure(
                        &detected,
                        "PGP decryption is not enabled for this account (set MAIL_PGP_<ID>_ENABLED=true)".to_owned(),
                    ),
                    inner: None,
                });
            }
            detect::CryptoKind::PgpMime | detect::CryptoKind::PgpInline => {
                self.pgp_backends.get(account_id)?.clone()
            }
        };

        // Clear-signed mail: the content is already visible to plain
        // parsing — nothing to decrypt or extract. Only the signature
        // status is added, verified over the whole raw message. Operational
        // verification errors keep the original view plus a failure_reason
        // (fail-open).
        if detected.kind == detect::CryptoKind::SmimeClearSigned {
            let (verified, failure_reason_field) =
                match backend.smime_verify_clear_signed(raw, self.timeout).await {
                    Ok(info) => (
                        match info.status {
                            backend::SignatureStatus::Verified => Some(true),
                            backend::SignatureStatus::Bad => Some(false),
                            backend::SignatureStatus::Unverified => None,
                        },
                        None,
                    ),
                    Err(error) => (None, Some(failure_reason(error))),
                };
            return Some(Resolution {
                block: CryptoBlock {
                    scheme: detected.kind.scheme().to_owned(),
                    encrypted: false,
                    decrypted: false,
                    signed: Some(true),
                    verified,
                    signer_cn: None,
                    signer_email: None,
                    failure_reason: failure_reason_field,
                    original_part_id: detected.part_id.clone(),
                    inner_part_prefix: INNER_PART_PREFIX.to_owned(),
                },
                inner: None,
            });
        }

        let outcome = match detected.kind {
            detect::CryptoKind::SmimeEnveloped => {
                backend
                    .smime_enveloped(&detected.payload, self.timeout)
                    .await
            }
            detect::CryptoKind::SmimeSigned => {
                backend
                    .smime_signed_content(&detected.payload, self.timeout)
                    .await
            }
            detect::CryptoKind::PgpMime | detect::CryptoKind::PgpInline => {
                backend.pgp_decrypt(&detected.payload, self.timeout).await
            }
            detect::CryptoKind::SmimeClearSigned => unreachable!("handled above"),
        };
        let mut outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return Some(Resolution {
                    block: CryptoBlock::failure(&detected, failure_reason(error)),
                    inner: None,
                });
            }
        };
        let mut signature = outcome.signature;

        // Sign-then-envelop mail nests the signature inside the decrypted
        // MIME entity (opaque `signed-data` wrappers are unwrapped so the
        // visible body is the actual content; a clear-signed inner part is
        // verified in place — its content is already visible in the tree).
        // Bounded depth.
        for _ in 0..2 {
            let Some(inner_detected) = detect::detect(&outcome.content) else {
                break;
            };
            if !account.smime_enabled {
                break;
            }
            match inner_detected.kind {
                detect::CryptoKind::SmimeSigned => {
                    match self
                        .smime_backend
                        .smime_signed_content(&inner_detected.payload, self.timeout)
                        .await
                    {
                        Ok(nested) => {
                            outcome = nested;
                            signature = outcome.signature;
                        }
                        Err(error) => {
                            return Some(Resolution {
                                block: CryptoBlock::failure(&detected, failure_reason(error)),
                                inner: None,
                            });
                        }
                    }
                }
                detect::CryptoKind::SmimeClearSigned => {
                    // Verify over the decrypted inner MIME (the
                    // multipart/signed entity as the sender assembled it).
                    signature = backend
                        .smime_verify_clear_signed(&outcome.content, self.timeout)
                        .await
                        .ok()
                        .or(signature);
                    break;
                }
                _ => break,
            }
        }

        let signature = signature.as_ref();
        let (signer_cn, signer_email) = signature
            .and_then(|s| s.signer.as_deref())
            .map(split_signer)
            .unwrap_or((None, None));

        let block = CryptoBlock {
            scheme: detected.kind.scheme().to_owned(),
            encrypted: detected.kind.is_encrypted(),
            decrypted: true,
            signed: signature.map(|_| true),
            verified: signature.and_then(|s| match s.status {
                backend::SignatureStatus::Verified => Some(true),
                backend::SignatureStatus::Bad => Some(false),
                backend::SignatureStatus::Unverified => None,
            }),
            signer_cn,
            signer_email,
            failure_reason: None,
            original_part_id: detected.part_id.clone(),
            inner_part_prefix: INNER_PART_PREFIX.to_owned(),
        };

        let inner = Arc::new(outcome.content);
        self.cache_put(cache_key.to_owned(), inner.clone(), block.clone());
        Some(Resolution {
            block,
            inner: Some(inner),
        })
    }

    /// Select an attachment inside the decrypted content of a message.
    ///
    /// `part_id` values coming from `imap_get_message` carry the
    /// [`INNER_PART_PREFIX`]; the prefix is stripped before the inner lookup
    /// and re-applied on the returned attachment. `filename` matches
    /// directly. Returns `None` when the message is not decrypted content or
    /// nothing matched (the caller falls back to its normal `NotFound`).
    pub async fn select_inner_attachment(
        &self,
        account_id: &str,
        cache_key: &str,
        raw: &[u8],
        part_id: Option<&str>,
        filename: Option<&str>,
    ) -> Option<mime::ExtractedAttachment> {
        let inner_part_id = part_id.and_then(|id| id.strip_prefix(INNER_PART_PREFIX));
        if part_id.is_some() && inner_part_id.is_none() && filename.is_none() {
            // An explicit outer-style part id that missed the outer tree is
            // not silently remapped to inner parts.
            return None;
        }

        let resolution = self.resolve(account_id, cache_key, raw).await?;
        let inner = resolution.inner?;
        let attachments = mime::collect_attachments(&inner).ok()?;
        let mut selected = select_inner(&attachments, inner_part_id, filename)?;
        selected.part_id = format!("{INNER_PART_PREFIX}{}", selected.part_id);
        Some(selected)
    }

    fn cache_get(&self, key: &str) -> Option<CacheEntry> {
        let mut cache = self.cache.lock().ok()?;
        match cache.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(CacheEntry {
                inner: entry.inner.clone(),
                block: entry.block.clone(),
                inserted_at: entry.inserted_at,
                expires_at: entry.expires_at,
            }),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn cache_put(&self, key: String, inner: Arc<Vec<u8>>, block: CryptoBlock) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        while cache.len() >= CACHE_MAX_ENTRIES {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(oldest) => {
                    cache.remove(&oldest);
                }
                None => break,
            }
        }
        cache.insert(
            key,
            CacheEntry {
                inner,
                block,
                inserted_at: now,
                expires_at: now + CACHE_TTL,
            },
        );
    }
}

/// Mirror of the server's attachment selection for inner parts: exact
/// `part_id` first, then case-insensitive `filename`.
fn select_inner(
    attachments: &[mime::ExtractedAttachment],
    part_id: Option<&str>,
    filename: Option<&str>,
) -> Option<mime::ExtractedAttachment> {
    if let Some(part_id) = part_id
        && let Some(hit) = attachments.iter().find(|a| a.part_id == part_id)
    {
        return Some(hit.clone());
    }
    filename.and_then(|name| {
        let name = name.to_ascii_lowercase();
        attachments
            .iter()
            .find(|a| {
                a.filename
                    .as_deref()
                    .is_some_and(|f| f.to_ascii_lowercase() == name)
            })
            .cloned()
    })
}

/// Split a signer description like `"Test User <t@example.com>"` into CN and
/// email parts.
fn split_signer(signer: &str) -> (Option<String>, Option<String>) {
    let trimmed = signer.trim_matches('"');
    if let Some((start, len)) = trimmed
        .find('<')
        .and_then(|start| trimmed[start..].find('>').map(|end| (start, end)))
    {
        let cn = trimmed[..start].trim();
        let email = &trimmed[start + 1..start + len];
        (
            (!cn.is_empty()).then(|| cn.to_owned()),
            (!email.is_empty()).then(|| email.to_owned()),
        )
    } else if trimmed.contains('@') {
        (None, Some(trimmed.to_owned()))
    } else {
        (Some(trimmed.to_owned()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::split_signer;

    #[test]
    fn signer_split_name_and_email() {
        let (cn, email) = split_signer("Test User <t@example.com>");
        assert_eq!(cn.as_deref(), Some("Test User"));
        assert_eq!(email.as_deref(), Some("t@example.com"));
    }

    #[test]
    fn signer_split_email_only() {
        let (cn, email) = split_signer("t@example.com");
        assert_eq!(cn, None);
        assert_eq!(email.as_deref(), Some("t@example.com"));
    }

    #[test]
    fn signer_split_name_only() {
        let (cn, email) = split_signer("Some Body");
        assert_eq!(cn.as_deref(), Some("Some Body"));
        assert_eq!(email, None);
    }
}

#[cfg(test)]
mod config_tests {
    use super::{AccountCryptoConfig, CryptoConfig, CryptoService};

    fn settings(pairs: &[(&str, &str)]) -> crate::config_file::Settings {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn smime_enveloped_mail() -> Vec<u8> {
        b"From: a@example.com\r\nSubject: t\r\n\
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
dGVzdA=="
            .to_vec()
    }

    #[test]
    fn no_crypto_keys_yield_inert_config() {
        let config = CryptoConfig::load(&settings(&[
            ("MAIL_IMAP_WORK_HOST", "imap.example.com"),
            ("MAIL_IMAP_WORK_USER", "u"),
            ("MAIL_IMAP_WORK_PASS", "p"),
        ]))
        .unwrap();
        assert!(!config.has_enabled_account());
        assert!(CryptoService::opt_new(&config).is_none());
    }

    #[test]
    fn enabled_flags_create_accounts() {
        let config = CryptoConfig::load(&settings(&[
            ("MAIL_SMIME_WORK_ENABLED", "true"),
            ("MAIL_SMIME_RZLEITUNG_ENABLED", "1"),
            ("MAIL_PGP_WORK_ENABLED", "yes"),
        ]))
        .unwrap();
        assert!(config.has_enabled_account());
        assert!(config.accounts["work"].smime_enabled);
        assert!(config.accounts["work"].pgp_enabled);
        assert!(config.accounts["rzleitung"].smime_enabled);
        assert!(!config.accounts["rzleitung"].pgp_enabled);
        assert!(CryptoService::opt_new(&config).is_some());
    }

    #[test]
    fn explicit_false_and_invalid_values_behave() {
        // Explicit false stays inert; invalid booleans error at startup
        // without echoing the (possibly mistyped secret) value.
        let config =
            CryptoConfig::load(&settings(&[("MAIL_SMIME_WORK_ENABLED", "false")])).unwrap();
        assert!(!config.has_enabled_account());

        let error =
            CryptoConfig::load(&settings(&[("MAIL_SMIME_WORK_ENABLED", "maybe")])).unwrap_err();
        assert!(error.to_string().contains("MAIL_SMIME_WORK_ENABLED"));
    }

    #[test]
    fn pgp_secrets_parse() {
        let config = CryptoConfig::load(&settings(&[
            ("MAIL_PGP_WORK_ENABLED", "true"),
            ("MAIL_PGP_WORK_PASS", "env-pass"),
            ("MAIL_PGP_WORK_GPG_BIN", "/opt/homebrew/bin/gpg"),
        ]))
        .unwrap();
        let account: &AccountCryptoConfig = &config.accounts["work"];
        assert_eq!(account.pgp_pass_keychain_service, None);
        assert_eq!(
            account.gpg_bin,
            std::path::PathBuf::from("/opt/homebrew/bin/gpg")
        );

        let config = CryptoConfig::load(&settings(&[
            ("MAIL_PGP_WORK_ENABLED", "true"),
            (
                "MAIL_PGP_WORK_PASS_KEYCHAIN_SERVICE",
                "opencode-pgp-arno-work",
            ),
            ("MAIL_PGP_WORK_PASS_KEYCHAIN_ACCOUNT", "awa"),
        ]))
        .unwrap();
        let account: &AccountCryptoConfig = &config.accounts["work"];
        assert_eq!(
            account.pgp_pass_keychain_service.as_deref(),
            Some("opencode-pgp-arno-work")
        );
        assert_eq!(account.pgp_pass_keychain_account.as_deref(), Some("awa"));
        // Default gpg binary when unset.
        assert_eq!(account.gpg_bin, std::path::PathBuf::from("gpg"));
    }

    #[test]
    fn crypto_block_omits_unset_optional_fields() {
        let block = serde_json::to_value(super::CryptoBlock {
            scheme: "smime".to_owned(),
            encrypted: true,
            decrypted: false,
            signed: None,
            verified: None,
            signer_cn: None,
            signer_email: None,
            failure_reason: Some("no identity".to_owned()),
            original_part_id: "1".to_owned(),
            inner_part_prefix: "d".to_owned(),
        })
        .unwrap();
        let map = block.as_object().unwrap();
        assert!(!map.contains_key("signed"));
        assert!(!map.contains_key("verified"));
        assert!(!map.contains_key("signer_cn"));
        assert!(!map.contains_key("signer_email"));
        assert_eq!(map["failure_reason"], "no identity");
        // Round trip: absent optional fields deserialize back to None.
        let parsed: super::CryptoBlock = serde_json::from_value(block).unwrap();
        assert!(parsed.signed.is_none());
        assert!(parsed.verified.is_none());
    }

    #[tokio::test]
    async fn plaintext_mail_resolves_to_none_even_when_configured() {
        // Inert guarantee: crypto config present, but a plaintext mail
        // produces no block and no subprocess — the plain view stands.
        let config = CryptoConfig::load(&settings(&[("MAIL_SMIME_WORK_ENABLED", "true")])).unwrap();
        let service = CryptoService::opt_new(&config).expect("service");
        let resolution = service
            .resolve(
                "work",
                "imap:work:INBOX:1:42",
                b"Subject: hi\r\n\r\nplain body",
            )
            .await;
        assert!(resolution.is_none());
    }

    #[tokio::test]
    async fn unknown_account_resolves_to_none() {
        let config = CryptoConfig::load(&settings(&[("MAIL_SMIME_WORK_ENABLED", "true")])).unwrap();
        let service = CryptoService::opt_new(&config).expect("service");
        let resolution = service
            .resolve("other", "imap:other:INBOX:1:42", &smime_enveloped_mail())
            .await;
        assert!(resolution.is_none());
    }

    #[tokio::test]
    async fn disabled_scheme_yields_failure_block() {
        // PGP configured, but the mail is S/MIME: fail-open with a clear
        // reason instead of pretending the mail is unreadable.
        let config = CryptoConfig::load(&settings(&[("MAIL_PGP_WORK_ENABLED", "true")])).unwrap();
        let service = CryptoService::opt_new(&config).expect("service");
        let resolution = service
            .resolve("work", "imap:work:INBOX:1:42", &smime_enveloped_mail())
            .await
            .expect("detected structure");
        assert!(resolution.inner.is_none());
        assert!(!resolution.block.decrypted);
        assert!(resolution.block.encrypted);
        assert_eq!(resolution.block.scheme, "smime");
        assert!(
            resolution
                .block
                .failure_reason
                .as_deref()
                .unwrap()
                .contains("not enabled")
        );
    }

    #[tokio::test]
    async fn undecryptable_payload_yields_failure_block() {
        // Enabled backend + garbage payload: bounded failure reason, no
        // tool-level error (works cross-platform: macOS reports a cms
        // failure, other platforms an unsupported backend).
        let config = CryptoConfig::load(&settings(&[
            ("MAIL_SMIME_WORK_ENABLED", "true"),
            ("MAIL_PGP_WORK_ENABLED", "true"),
        ]))
        .unwrap();
        let service = CryptoService::opt_new(&config).expect("service");
        let resolution = service
            .resolve("work", "imap:work:INBOX:1:42", &smime_enveloped_mail())
            .await
            .expect("detected structure");
        assert!(resolution.inner.is_none());
        assert!(!resolution.block.decrypted);
        assert!(resolution.block.failure_reason.is_some());
        // Failure reasons are bounded.
        assert!(resolution.block.failure_reason.unwrap().len() <= 200);
    }

    #[test]
    fn inner_attachment_selector_mirrors_outer_semantics() {
        use crate::mime::ExtractedAttachment;

        let attachments = vec![
            ExtractedAttachment {
                filename: Some("report.pdf".to_owned()),
                content_type: "application/pdf".to_owned(),
                part_id: "1.2".to_owned(),
                bytes: vec![1],
            },
            ExtractedAttachment {
                filename: Some("Photo.JPG".to_owned()),
                content_type: "image/jpeg".to_owned(),
                part_id: "2".to_owned(),
                bytes: vec![2],
            },
        ];

        // Exact part id wins.
        let hit = super::select_inner(&attachments, Some("1.2"), None).unwrap();
        assert_eq!(hit.part_id, "1.2");
        // Filename is case-insensitive.
        let hit = super::select_inner(&attachments, None, Some("photo.jpg")).unwrap();
        assert_eq!(hit.part_id, "2");
        // Miss returns None.
        assert!(super::select_inner(&attachments, Some("9"), None).is_none());
        assert!(super::select_inner(&attachments, None, Some("missing.bin")).is_none());
    }
}
