//! Detection of encrypted/signed structures in a raw RFC822 message.
//!
//! Pure parsing only — no IO, no key access, runs on every platform. The
//! detector finds the payload bytes that a decryption backend needs:
//!
//! - S/MIME enveloped-data and opaque signed-data (`application/pkcs7-mime`,
//!   `smime-type=enveloped-data|signed-data`) — the payload is the decoded
//!   part body (DER `ContentInfo`).
//! - PGP/MIME: an `application/pgp-encrypted` version marker with the
//!   ciphertext in a sibling `application/octet-stream`/text part. Both the
//!   RFC 3156 `multipart/encrypted` shape and the flat sibling variant
//!   inside `multipart/mixed` (seen from ProtonMail in the wild) are
//!   detected.
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
    /// S/MIME clear-signed (`multipart/signed` with a detached pkcs7
    /// signature; the content is visible without any decryption)
    SmimeClearSigned,
    /// PGP/MIME (`multipart/encrypted`)
    PgpMime,
    /// Inline PGP ASCII armor in a text body
    PgpInline,
}

impl CryptoKind {
    /// Scheme label used in the response `crypto` block.
    pub fn scheme(self) -> &'static str {
        match self {
            CryptoKind::SmimeEnveloped | CryptoKind::SmimeSigned | CryptoKind::SmimeClearSigned => {
                "smime"
            }
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
    /// Decoded payload bytes (transfer encoding already undone): the CMS DER
    /// for opaque S/MIME kinds, the PGP ciphertext. Clear-signed mail is
    /// verified over the whole raw message instead (no byte reconstruction).
    pub payload: Vec<u8>,
    /// Outer MIME part id carrying the payload (matches `imap_get_message`
    /// part numbering, e.g. `1` or `1.2`)
    pub part_id: String,
}

/// Detect a decryptable/verifiable crypto structure in a raw message.
///
/// Returns the first match in MIME walk order. `None` for plaintext mail,
/// and unsupported `smime-type` values (e.g. `certs-only`).
pub fn detect(raw: &[u8]) -> Option<Detected> {
    let parsed = mailparse::parse_mail(raw).ok()?;
    walk(&parsed, "1")
}

fn walk(part: &ParsedMail<'_>, part_id: &str) -> Option<Detected> {
    if part.subparts.is_empty() {
        return inspect_leaf(part, part_id);
    }

    // S/MIME clear-signed: `multipart/signed` with a detached pkcs7
    // signature. The content is visible without decryption; the signature
    // is verified over the whole raw message (no byte reconstruction — the
    // sender's MUA assembled it consistently).
    let ctype = part.ctype.mimetype.to_ascii_lowercase();
    if ctype == "multipart/signed"
        && part.subparts.len() >= 2
        && part.ctype.params.get("protocol").is_some_and(|p| {
            p.eq_ignore_ascii_case("application/pkcs7-signature")
                || p.eq_ignore_ascii_case("application/x-pkcs7-signature")
        })
    {
        let payload = part.subparts[1].get_body_raw().ok()?;
        return Some(Detected {
            kind: CryptoKind::SmimeClearSigned,
            payload,
            part_id: format!("{part_id}.2"),
        });
    }

    // RFC 3156 wraps PGP/MIME in `multipart/encrypted` with a protocol
    // parameter, but real-world senders (ProtonMail, verified on a live
    // incoming application mail) also place the version marker and the
    // ciphertext as plain siblings inside a `multipart/mixed`. Detect via
    // the `application/pgp-encrypted` marker part in either shape: the
    // payload is the sibling `application/octet-stream` part.
    let has_pgp_marker = part.subparts.iter().any(|sub| {
        sub.ctype
            .mimetype
            .eq_ignore_ascii_case("application/pgp-encrypted")
    });
    if has_pgp_marker {
        // The ciphertext part is `application/octet-stream` in both shapes.
        // A plain `text/plain` sibling is a body, not the payload — unless it
        // carries armor directly (rare inline fallback).
        for (idx, sub) in part.subparts.iter().enumerate() {
            if sub
                .ctype
                .mimetype
                .eq_ignore_ascii_case("application/octet-stream")
                && let Ok(payload) = sub.get_body_raw()
            {
                return Some(Detected {
                    kind: CryptoKind::PgpMime,
                    payload,
                    part_id: format!("{part_id}.{}", idx + 1),
                });
            }
        }
        for (idx, sub) in part.subparts.iter().enumerate() {
            if sub.ctype.mimetype.eq_ignore_ascii_case("text/plain")
                && let Ok(payload) = sub.get_body_raw()
                && payload.starts_with(b"-----BEGIN PGP MESSAGE-----")
            {
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
    fn detects_smime_clear_signed_minimal() {
        // Same shape the (now removed) negative test used: clear-signed
        // multipart with a pkcs7 signature is detected for verification.
        let raw = "Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=sha-256; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\nvisible body\r\n\
--BB\r\nContent-Type: application/x-pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n\
--BB--\r\n";
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::SmimeClearSigned);
        assert_eq!(hit.part_id, "1.2");
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
    fn detects_pgp_mime_protonmail_flat_siblings() {
        // Real-world shape (verified on a live ProtonMail application mail):
        // no multipart/encrypted wrapper — the version marker and the
        // ciphertext sit as plain siblings inside a multipart/mixed.
        let raw = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\n\r\n\
--BB\r\nContent-Type: application/pgp-encrypted; name=\"PGPMIME version identification\"\r\n\
Content-Disposition: attachment; filename=\"PGPMIME version identification\"\r\n\r\n\
Version: 1\r\n\
--BB\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
Content-Disposition: attachment; filename=\"encrypted.asc\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
h4IBDQ==\r\n\
--BB--\r\n";
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::PgpMime);
        assert_eq!(hit.part_id, "1.3");
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
    fn detects_smime_clear_signed() {
        let raw = "From: a@example.com\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=sha-256; boundary=BB\r\n\r\n\
This is an S/MIME signed message\r\n\
--BB\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nvisible body\r\n\
--BB\r\nContent-Type: application/x-pkcs7-signature; name=\"smime.p7s\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nQUJDREVG\r\n\
--BB--\r\n";
        let hit = detect(raw.as_bytes()).expect("must detect");
        assert_eq!(hit.kind, CryptoKind::SmimeClearSigned);
        assert!(!hit.kind.is_encrypted());
        assert_eq!(hit.part_id, "1.2");
        assert_eq!(hit.payload, b"ABCDEF");
    }

    #[test]
    fn clear_signed_accepts_both_protocol_spellings() {
        for protocol in [
            "application/pkcs7-signature",
            "application/x-pkcs7-signature",
        ] {
            let raw = format!(
                "Content-Type: multipart/signed; protocol=\"{protocol}\"; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\nx\r\n\
--BB\r\nContent-Type: {protocol}\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n\
--BB--\r\n"
            );
            assert!(detect(raw.as_bytes()).is_some(), "protocol {protocol}");
        }
    }

    #[test]
    fn pgp_clear_signed_is_not_detected() {
        // PGP clear-signed mail is out of scope in step 1 (no verification).
        let raw = "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/plain\r\n\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nhi\r\n\
--BB\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\n\
--BB--\r\n";
        assert!(detect(raw.as_bytes()).is_none());
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
