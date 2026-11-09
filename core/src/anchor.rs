//! RFC 3161 request/response encode and parse, attach anchor.
//!
//! Spec: Fable_5_1/docs/protocol/evidence-v1.md §8. Hand-written DER (no ASN.1
//! crate). The CMS signature and TSA certificate chain are NOT verified here
//! (ADR-0004, v1 scope); only the TSTInfo imprint and genTime are read.

use crate::error::{Error, ErrorCode};
use crate::evidence::{Anchor, Evidence};

/// sha256 OID 2.16.840.1.101.3.4.2.1, content bytes.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-signedData 1.2.840.113549.1.7.2.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// id-ct-TSTInfo 1.2.840.113549.1.9.16.1.4.
const OID_TST_INFO: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04];

const T_BOOL: u8 = 0x01;
const T_INT: u8 = 0x02;
const T_OCTET: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_GENTIME: u8 = 0x18;
const T_SEQ: u8 = 0x30;
const T_SET: u8 = 0x31;
const T_CTX0: u8 = 0xa0;

/// Parsed RFC 3161 token. `token_der` is the whole TimeStampToken (ContentInfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaToken {
    pub token_der: Vec<u8>,
    pub imprint: [u8; 32],
    pub gen_time_rfc3339: String,
}

fn bad(m: &str) -> Error {
    Error::new(ErrorCode::BadAnchor, m)
}

// ---------- encode ----------

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Unsigned big-endian bytes as positive DER INTEGER content (minimal form).
fn uint_content(b: &[u8]) -> Vec<u8> {
    let skip = b.iter().take_while(|x| **x == 0).count();
    let rest = if skip == b.len() { &[0u8][..] } else { &b[skip..] };
    let mut v = Vec::with_capacity(rest.len() + 1);
    if rest[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(rest);
    v
}

/// TimeStampReq DER (RFC 3161 §2.4.1): version 1, sha256 imprint of
/// `anchor_subject`, optional nonce (unsigned big-endian), certReq TRUE.
pub fn tsa_request_der(anchor_subject: &[u8; 32], nonce: Option<&[u8]>) -> Vec<u8> {
    let mut alg = tlv(T_OID, OID_SHA256);
    alg.extend(tlv(T_NULL, &[]));
    let mut mi = tlv(T_SEQ, &alg);
    mi.extend(tlv(T_OCTET, anchor_subject));
    let mut body = tlv(T_INT, &[1]);
    body.extend(tlv(T_SEQ, &mi));
    if let Some(n) = nonce {
        body.extend(tlv(T_INT, &uint_content(n)));
    }
    body.extend(tlv(T_BOOL, &[0xff]));
    tlv(T_SEQ, &body)
}

// ---------- decode ----------

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    full: &'a [u8],
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn next(&mut self) -> Result<Tlv<'a>, Error> {
        let b = self.buf;
        if b.len() < 2 {
            return Err(bad("DER: truncated"));
        }
        let tag = b[0];
        if tag & 0x1f == 0x1f {
            return Err(bad("DER: high tag numbers are not supported"));
        }
        let (len, hl) = match b[1] {
            l if l < 0x80 => (l as usize, 2),
            0x80 => return Err(bad("DER: indefinite length")),
            l => {
                let n = (l & 0x7f) as usize;
                if n > 4 || b.len() < 2 + n {
                    return Err(bad("DER: bad length"));
                }
                let len = b[2..2 + n].iter().fold(0usize, |a, x| (a << 8) | *x as usize);
                (len, 2 + n)
            }
        };
        let end = hl.checked_add(len).filter(|e| *e <= b.len()).ok_or_else(|| bad("DER: length past end"))?;
        self.buf = &b[end..];
        Ok(Tlv { tag, content: &b[hl..end], full: &b[..end] })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>, Error> {
        let t = self.next()?;
        if t.tag != tag {
            return Err(bad(&format!("DER: expected {what}")));
        }
        Ok(t)
    }
}

/// "YYYYMMDDHHMMSS[.f*]Z" -> "YYYY-MM-DDTHH:MM:SSZ" (fraction dropped).
fn gen_time(c: &[u8]) -> Result<String, Error> {
    let s = std::str::from_utf8(c).map_err(|_| bad("genTime is not ASCII"))?;
    let core = s.strip_suffix('Z').ok_or_else(|| bad("genTime must end in Z"))?;
    let (main, frac) = core.split_once('.').unwrap_or((core, "0"));
    if main.len() != 14
        || !main.bytes().all(|b| b.is_ascii_digit())
        || frac.is_empty()
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad("genTime is not YYYYMMDDHHMMSS[.f]Z"));
    }
    Ok(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &main[0..4],
        &main[4..6],
        &main[6..8],
        &main[8..10],
        &main[10..12],
        &main[12..14]
    ))
}

fn tst_info(der: &[u8]) -> Result<([u8; 32], String), Error> {
    let seq = Reader::new(der).expect(T_SEQ, "TSTInfo SEQUENCE")?;
    let mut r = Reader::new(seq.content);
    r.expect(T_INT, "TSTInfo version")?;
    r.expect(T_OID, "TSTInfo policy")?;
    let mi = r.expect(T_SEQ, "messageImprint")?;
    let mut m = Reader::new(mi.content);
    let alg = m.expect(T_SEQ, "hashAlgorithm")?;
    if Reader::new(alg.content).expect(T_OID, "hash OID")?.content != OID_SHA256 {
        return Err(bad("messageImprint hash is not sha256"));
    }
    let h = m.expect(T_OCTET, "hashedMessage")?;
    let imprint: [u8; 32] = h.content.try_into().map_err(|_| bad("hashedMessage is not 32 bytes"))?;
    r.expect(T_INT, "serialNumber")?;
    let t = r.expect(T_GENTIME, "genTime")?;
    Ok((imprint, gen_time(t.content)?))
}

/// Parse a TimeStampToken (ContentInfo, the bytes stored in `token_b64`).
/// Returns the TSTInfo imprint and genTime. Does not verify the CMS signature.
pub fn tsa_parse_token(der: &[u8]) -> Result<TsaToken, Error> {
    let mut top = Reader::new(der);
    let ci = top.expect(T_SEQ, "ContentInfo SEQUENCE")?;
    if !top.is_empty() {
        return Err(bad("trailing bytes after ContentInfo"));
    }
    let mut r = Reader::new(ci.content);
    if r.expect(T_OID, "contentType")?.content != OID_SIGNED_DATA {
        return Err(bad("contentType is not id-signedData"));
    }
    let sd_wrap = r.expect(T_CTX0, "[0] content")?;
    let sd = Reader::new(sd_wrap.content).expect(T_SEQ, "SignedData SEQUENCE")?;
    let mut s = Reader::new(sd.content);
    s.expect(T_INT, "SignedData version")?;
    s.expect(T_SET, "digestAlgorithms")?;
    let eci = s.expect(T_SEQ, "encapContentInfo")?;
    let mut e = Reader::new(eci.content);
    if e.expect(T_OID, "eContentType")?.content != OID_TST_INFO {
        return Err(bad("eContentType is not id-ct-TSTInfo"));
    }
    let ec = e.expect(T_CTX0, "[0] eContent")?;
    let oct = Reader::new(ec.content).expect(T_OCTET, "eContent OCTET STRING")?;
    let (imprint, gen_time_rfc3339) = tst_info(oct.content)?;
    Ok(TsaToken { token_der: ci.full.to_vec(), imprint, gen_time_rfc3339 })
}

/// Parse a TimeStampResp. Only status granted(0) or grantedWithMods(1) is accepted.
pub fn tsa_parse_response(der: &[u8]) -> Result<TsaToken, Error> {
    let resp = Reader::new(der).expect(T_SEQ, "TimeStampResp SEQUENCE")?;
    let mut r = Reader::new(resp.content);
    let st = r.expect(T_SEQ, "PKIStatusInfo")?;
    let status = Reader::new(st.content).expect(T_INT, "PKIStatus")?;
    if status.content != [0] && status.content != [1] {
        return Err(bad("TSA did not grant the request (PKIStatus not 0 or 1)"));
    }
    let tok = r.next().map_err(|_| bad("TimeStampResp has no timeStampToken"))?;
    tsa_parse_token(tok.full)
}

/// Append an anchor (§8.2). Existing anchors are never removed.
pub fn attach_anchor(ev: &mut Evidence, anchor: Anchor) {
    ev.anchors.push(anchor);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FREETSA: &[u8] = include_bytes!("../tests/fixtures/tsa-response-freetsa.der");
    const DIGICERT: &[u8] = include_bytes!("../tests/fixtures/tsa-response-digicert.der");
    /// SHA-256("x"), the imprint both fixtures were requested for.
    const X_SHA256: &str = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn x_subject() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::from_str_radix(&X_SHA256[2 * i..2 * i + 2], 16).unwrap();
        }
        s
    }

    #[test]
    fn request_matches_openssl_no_nonce() {
        // `openssl ts -query -data x.txt -sha256 -cert -no_nonce` (59 bytes), x.txt = "x".
        let want = "30390201013031300d060960864801650304020105000420".to_string() + X_SHA256 + "0101ff";
        assert_eq!(hex(&tsa_request_der(&x_subject(), None)), want);
    }

    #[test]
    fn request_matches_openssl_with_nonce() {
        // openssl output with nonce 0x756A374058D0654E (69 bytes, SEQUENCE length 67).
        let nonce = [0x75, 0x6a, 0x37, 0x40, 0x58, 0xd0, 0x65, 0x4e];
        let want =
            "30430201013031300d060960864801650304020105000420".to_string() + X_SHA256 + "0208756a374058d0654e0101ff";
        assert_eq!(hex(&tsa_request_der(&x_subject(), Some(&nonce))), want);
        // Leading zeros stripped; high bit set gets 0x00 so the INTEGER stays positive.
        let r = tsa_request_der(&x_subject(), Some(&[0x00, 0x80, 0x01]));
        assert_eq!(hex(&r[r.len() - 8..]), "02030080010101ff");
        let r = tsa_request_der(&x_subject(), Some(&[0, 0]));
        assert_eq!(hex(&r[r.len() - 6..]), "0201000101ff");
    }

    #[test]
    fn long_form_length() {
        assert_eq!(&tlv(T_OCTET, &[0u8; 300])[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(&tlv(T_OCTET, &[0u8; 200])[..3], &[0x04, 0x81, 0xc8]);
        assert_eq!(&tlv(T_OCTET, &[0u8; 127])[..2], &[0x04, 0x7f]);
    }

    #[test]
    fn parse_real_responses() {
        for der in [FREETSA, DIGICERT] {
            let tok = tsa_parse_response(der).unwrap();
            assert_eq!(hex(&tok.imprint), X_SHA256);
            // `openssl ts -reply -text`: "Time stamp: Nov  9 04:14:30 2026 GMT" for both.
            assert_eq!(tok.gen_time_rfc3339, "2026-11-09T04:14:30Z");
            // token_der is the ContentInfo and parses on its own to the same result.
            assert_eq!(tsa_parse_token(&tok.token_der).unwrap(), tok);
            assert!(tok.token_der.len() < der.len());
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(tsa_parse_response(&[]).unwrap_err().code, ErrorCode::BadAnchor);
        assert!(tsa_parse_response(&FREETSA[..FREETSA.len() - 1]).is_err());
        // status rejection(2), no token.
        assert!(tsa_parse_response(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]).is_err());
        // A full response is not a token.
        assert!(tsa_parse_token(FREETSA).is_err());
    }

    #[test]
    fn gen_time_formats() {
        assert_eq!(gen_time(b"20261109041430Z").unwrap(), "2026-11-09T04:14:30Z");
        assert_eq!(gen_time(b"20261109041430.123Z").unwrap(), "2026-11-09T04:14:30Z");
        assert!(gen_time(b"20261109041430").is_err());
        assert!(gen_time(b"202611090414Z").is_err());
        assert!(gen_time(b"20261109041430.Z").is_err());
    }
}
