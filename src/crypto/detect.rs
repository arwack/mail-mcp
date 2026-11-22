//! Detection of encrypted/signed structures in a raw RFC822 message.
//!
//! Pure parsing only — no IO, no key access, runs on every platform. The
//! detector finds the payload bytes that a decryption backend needs:
//!
//! - S/MIME enveloped-data and opaque signed-data (`application/pkcs7-mime`,
//!   `smime-type=enveloped-data|signed-data`) — the payload is the decoded
//!   part body (DER `ContentInfo`).
//! - PGP/MIME (`multipart/encrypted` with `protocol="application/pgp-encrypted"`)
//!   — the payload is the decoded body of the `application/octet-stream` part
//!   (typically armored `encrypted.asc`).
//! - Inline PGP (a `text/*` body that starts with the ASCII armor header).
//!
//! Clear-signed structures (`multipart/signed`) are deliberately NOT
//! detected: their content is already visible to plain parsing, and step 1
//! does not verify signatures of clear-signed parts.

use mailparse::ParsedMail;

/// The crypto structure found in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoKind {
    /// S/MIME enveloped-data (encrypted for one or more recipients)
    SmimeEnveloped,
    /// S/MIME opaque signed-data (content embedded in the CMS structure)
    SmimeSigned,
    /// PGP/MIME (`multipart/encrypted`)
    PgpMime,
    /// Inline PGP ASCII armor in a text body
    PgpInline,
}

impl CryptoKind {
    /// Scheme label used in the response `crypto` block.
    pub fn scheme(self) -> &'static str {
        match self {
            CryptoKind::SmimeEnveloped | CryptoKind::SmimeSigned => "smime",
            CryptoKind::PgpMime | CryptoKind::PgpInline => "pgp",
        }
    }

    /// Whether the structure actually encrypts content (vs. signing only).
    pub fn is_encrypted(self) -> bool {
        matches!(
            self,
            CryptoKind::SmimeEnveloped | CryptoKind::PgpMime | CryptoKind::PgpInline
        )
    }
}

/// A detected crypto payload, ready to hand to a decryption backend.
#[derive(Debug, Clone)]
pub struct Detected {
    /// Which structure was found
    pub kind: CryptoKind,
    /// Decoded payload bytes (transfer encoding already undone)
    pub payload: Vec<u8>,
    /// Outer MIME part id carrying the payload (matches `imap_get_message`
    /// part numbering, e.g. `1` or `1.2`)
    pub part_id: String,
}

/// Detect a decryptable crypto structure in a raw message.
///
/// Returns the first match in MIME walk order. `None` for plaintext mail,
/// clear-signed-only mail, and unsupported `smime-type` values (e.g.
/// `certs-only`).
pub fn detect(raw: &[u8]) -> Option<Detected> {
    let parsed = mailparse::parse_mail(raw).ok()?;
    walk(&parsed, "1")
}

fn walk(part: &ParsedMail<'_>, part_id: &str) -> Option<Detected> {
    if part.subparts.is_empty() {
        return inspect_leaf(part, part_id);
    }

    let ctype = part.ctype.mimetype.to_ascii_lowercase();
    if ctype == "multipart/encrypted"
        && part
            .ctype
            .params
            .get("protocol")
            .is_some_and(|p| p.eq_ignore_ascii_case("application/pgp-encrypted"))
    {
        // RFC 3156: part 1 = version, part 2 = octet-stream ciphertext.
        for (idx, sub) in part.subparts.iter().enumerate() {
            let sub_ctype = sub.ctype.mimetype.to_ascii_lowercase();
            if sub_ctype == "application/octet-stream" || sub_ctype == "text/plain" {
                let payload = sub.get_body_raw().ok()?;
                return Some(Detected {
                    kind: CryptoKind::PgpMime,
                    payload,
                    part_id: format!("{part_id}.{}", idx + 1),
                });
            }
        }
        return None;
    }

    for (idx, sub) in part.subparts.iter().enumerate() {
        if let Some(hit) = walk(sub, &format!("{part_id}.{}", idx + 1)) {
            return Some(hit);
        }
    }
    None
}

fn inspect_leaf(part: &ParsedMail<'_>, part_id: &str) -> Option<Detected> {
    let ctype = part.ctype.mimetype.to_ascii_lowercase();

    if ctype == "application/pkcs7-mime" || ctype == "application/x-pkcs7-mime" {
        let smime_type = part
            .ctype
            .params
            .get("smime-type")
            .map(|s| s.to_ascii_lowercase());
        let kind = match smime_type.as_deref() {
            Some("enveloped-data") => CryptoKind::SmimeEnveloped,
            Some("signed-data") => CryptoKind::SmimeSigned,
            _ => return None,
        };
        let payload = part.get_body_raw().ok()?;
        return Some(Detected {
            kind,
            payload,
            part_id: part_id.to_owned(),
        });
    }

    // Inline PGP: a text body carrying ASCII armor directly.
    let looks_armored = ctype == "text/plain" || ctype == "text/html" || ctype.is_empty();
    if looks_armored
        && let Ok(body) = part.get_body_raw()
        && body.starts_with(b"-----BEGIN PGP MESSAGE-----")
    {
        return Some(Detected {
            kind: CryptoKind::PgpInline,
            payload: body,
            part_id: part_id.to_owned(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{CryptoKind, detect};

    const SMIME_ENVELOPED: &str = "From: a@example.com\r\n\
Subject: test\r\n\
MIME-Version: 1.0\r\n\
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\
\r\n\
dGVzdGRhdGE=";

    #[test]
    fn detects_smime_enveloped_top_level() {
        let hit = detect(SMIME_ENVELOPED.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::SmimeEnveloped);
        assert_eq!(hit.part_id, "1");
        assert_eq!(hit.payload, b"testdata");
        assert!(hit.kind.is_encrypted());
    }

    #[test]
    fn detects_smime_signed_opaque() {
        let raw = SMIME_ENVELOPED.replace("enveloped-data", "signed-data");
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::SmimeSigned);
        assert!(!hit.kind.is_encrypted());
    }

    #[test]
    fn detects_smime_nested_in_multipart() {
        let raw = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
--BB\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\ndGVzdA==\r\n\
--BB--\r\n"
            .to_owned();
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::SmimeEnveloped);
        assert_eq!(hit.part_id, "1.2");
    }

    #[test]
    fn ignores_certificates_only() {
        let raw = SMIME_ENVELOPED.replace("enveloped-data", "certs-only");
        assert!(detect(raw.as_bytes()).is_none());
    }

    #[test]
    fn ignores_x_pkcs7_signature_clear_signed() {
        // Clear-signed multipart is visible already; not our job in step 1.
        let raw = "Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=sha-256; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\nvisible body\r\n\
--BB\r\nContent-Type: application/x-pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n\
--BB--\r\n";
        assert!(detect(raw.as_bytes()).is_none());
    }

    #[test]
    fn detects_pgp_mime() {
        let raw = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
--BB\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
Content-Disposition: attachment; filename=\"encrypted.asc\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
h4IBDQ==\r\n\
--BB--\r\n";
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::PgpMime);
        assert_eq!(hit.part_id, "1.2");
        assert_eq!(hit.payload, b"\x87\x82\x01\x0d".as_slice());
    }

    #[test]
    fn detects_inline_pgp_armor() {
        let raw = "From: a@example.com\r\nSubject: t\r\nContent-Type: text/plain\r\n\r\n\
-----BEGIN PGP MESSAGE-----\r\nabc\r\n-----END PGP MESSAGE-----\r\n";
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::PgpInline);
        assert!(hit.payload.starts_with(b"-----BEGIN PGP MESSAGE-----"));
    }

    #[test]
    fn plain_mail_yields_none() {
        let raw = "From: a@example.com\r\nSubject: t\r\nContent-Type: text/plain\r\n\r\nJust text.";
        assert!(detect(raw.as_bytes()).is_none());
        let multipart = "Content-Type: multipart/alternative; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\nalt\r\n\
--BB\r\nContent-Type: text/html\r\n\r\n<p>alt</p>\r\n\
--BB--\r\n";
        assert!(detect(multipart.as_bytes()).is_none());
    }

    #[test]
    fn garbage_yields_none() {
        assert!(detect(b"not a mime message at all").is_none());
        assert!(detect(b"").is_none());
    }
}
