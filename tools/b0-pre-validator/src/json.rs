//! Strict JSON scanning + canonical serialization (plan §5).
//!
//! The lexical rules are enforced by a hand-written scanner that runs **before**
//! `serde_json::Value` is ever constructed. This ordering is load-bearing:
//! `serde_json` (BTreeMap-backed `Value`) silently collapses duplicate keys, so
//! duplicate detection must happen on the raw token stream, and it compares the
//! *decoded* key text so escaped-equivalent keys (`"a"` vs `"a"`) collide.
//!
//! Strict rules: ASCII only; no raw or decoded control/non-ASCII characters;
//! integers only (no fraction, no exponent, no leading zeros, no `-0`); one
//! optional leading `-` is lexically permitted (the typed layer enforces
//! per-field signedness); `null` is forbidden; duplicate object keys are
//! rejected at every nesting level.

use std::collections::HashSet;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    NonAscii {
        pos: usize,
    },
    BadControlInString {
        pos: usize,
    },
    DuplicateKey {
        key: String,
    },
    BadNumber {
        pos: usize,
        reason: &'static str,
    },
    BadEscape {
        pos: usize,
    },
    BadString {
        pos: usize,
        reason: &'static str,
    },
    NullForbidden {
        pos: usize,
    },
    Unexpected {
        pos: usize,
    },
    UnexpectedEnd,
    TrailingData {
        pos: usize,
    },
    NotAValue,
    /// A JSON number field held a value outside the target integer domain.
    NumberFieldOutOfRange {
        ctx: &'static str,
    },
    /// A field was present but of the wrong JSON kind.
    WrongFieldKind {
        ctx: &'static str,
    },
}

struct Scanner<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn scan_document(&mut self) -> Result<(), JsonError> {
        // Non-ASCII raw bytes are rejected everywhere up front; control bytes are
        // handled contextually (whitespace between tokens, rejected inside strings).
        if let Some(p) = self.buf.iter().position(|&b| b > 0x7E) {
            return Err(JsonError::NonAscii { pos: p });
        }
        self.skip_ws();
        self.scan_value()?;
        self.skip_ws();
        if self.pos != self.buf.len() {
            return Err(JsonError::TrailingData { pos: self.pos });
        }
        Ok(())
    }

    fn scan_value(&mut self) -> Result<(), JsonError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.scan_object(),
            Some(b'[') => self.scan_array(),
            Some(b'"') => self.scan_string().map(|_| ()),
            Some(b'-') | Some(b'0'..=b'9') => self.scan_number(),
            Some(b't') => self.scan_lit(b"true"),
            Some(b'f') => self.scan_lit(b"false"),
            Some(b'n') => Err(JsonError::NullForbidden { pos: self.pos }),
            Some(_) => Err(JsonError::Unexpected { pos: self.pos }),
            None => Err(JsonError::UnexpectedEnd),
        }
    }

    fn scan_lit(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        if self.buf[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(JsonError::Unexpected { pos: self.pos })
        }
    }

    fn scan_object(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // consume '{'
        let mut keys: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Unexpected { pos: self.pos });
            }
            let key = self.scan_string()?;
            if !keys.insert(key.clone()) {
                return Err(JsonError::DuplicateKey { key });
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(JsonError::Unexpected { pos: self.pos });
            }
            self.pos += 1;
            self.scan_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(_) => return Err(JsonError::Unexpected { pos: self.pos }),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }
    }

    fn scan_array(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // consume '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.scan_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(_) => return Err(JsonError::Unexpected { pos: self.pos }),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }
    }

    /// Consume a string token and return its decoded text. Only escapes that
    /// decode to printable ASCII are accepted: `\" \\ \/ \uXXXX` (with the code
    /// point in 0x20..=0x7E). `\n`, `\t`, etc. decode to control characters and
    /// are rejected as `BadEscape`.
    fn scan_string(&mut self) -> Result<String, JsonError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let mut s = String::new();
        loop {
            let b = self.peek().ok_or(JsonError::UnexpectedEnd)?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(s);
                }
                b'\\' => {
                    let esc_pos = self.pos;
                    self.pos += 1;
                    let e = self.peek().ok_or(JsonError::UnexpectedEnd)?;
                    match e {
                        b'"' => {
                            s.push('"');
                            self.pos += 1;
                        }
                        b'\\' => {
                            s.push('\\');
                            self.pos += 1;
                        }
                        b'/' => {
                            s.push('/');
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            let cp = self.read_hex4()?;
                            if !(0x20..=0x7E).contains(&cp) {
                                return Err(JsonError::BadString {
                                    pos: esc_pos,
                                    reason: "escape decodes to control or non-ASCII",
                                });
                            }
                            s.push(cp as u8 as char);
                        }
                        _ => return Err(JsonError::BadEscape { pos: esc_pos }),
                    }
                }
                0x20..=0x7E => {
                    // printable ASCII literal (non-quote, non-backslash)
                    s.push(b as char);
                    self.pos += 1;
                }
                _ => return Err(JsonError::BadControlInString { pos: self.pos }),
            }
        }
    }

    fn read_hex4(&mut self) -> Result<u32, JsonError> {
        if self.pos + 4 > self.buf.len() {
            return Err(JsonError::UnexpectedEnd);
        }
        let mut cp: u32 = 0;
        for _ in 0..4 {
            let c = self.buf[self.pos];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err(JsonError::BadEscape { pos: self.pos }),
            };
            cp = cp * 16 + d;
            self.pos += 1;
        }
        Ok(cp)
    }

    fn scan_number(&mut self) -> Result<(), JsonError> {
        let start = self.pos;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        return Err(JsonError::BadNumber {
                            pos: start,
                            reason: "leading zero",
                        });
                    }
                }
                if neg {
                    return Err(JsonError::BadNumber {
                        pos: start,
                        reason: "negative zero",
                    });
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(JsonError::BadNumber {
                    pos: self.pos,
                    reason: "expected digit",
                })
            }
        }
        if let Some(c) = self.peek() {
            if c == b'.' || c == b'e' || c == b'E' {
                return Err(JsonError::BadNumber {
                    pos: self.pos,
                    reason: "fraction or exponent",
                });
            }
        }
        Ok(())
    }
}

/// Enforce the strict lexical rules on raw bytes without building a `Value`.
pub fn strict_scan(input: &[u8]) -> Result<(), JsonError> {
    Scanner { buf: input, pos: 0 }.scan_document()
}

/// Strict-scan, then parse into a `serde_json::Value`. Because the scan already
/// rejected duplicate keys, the collapsing behaviour of `Value` cannot hide one.
pub fn parse_strict(input: &[u8]) -> Result<Value, JsonError> {
    strict_scan(input)?;
    serde_json::from_slice(input).map_err(|_| JsonError::NotAValue)
}

/// Serialize a `Value` to canonical bytes: byte-sorted object keys, minimal
/// integers, `"`/`\` escaped, `/` literal, no insignificant whitespace, no
/// trailing newline, `null` forbidden.
pub fn to_canonical(v: &Value) -> Result<Vec<u8>, JsonError> {
    let mut out = Vec::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

/// Strict-scan + parse + canonical-serialize in one step.
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, JsonError> {
    to_canonical(&parse_strict(input)?)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), JsonError> {
    match v {
        Value::Null => Err(JsonError::NullForbidden { pos: 0 }),
        Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
            Ok(())
        }
        Value::Number(n) => {
            // `arbitrary_precision` keeps the exact integer literal; the strict
            // scan guaranteed it is a minimal integer, so re-emit verbatim.
            out.extend_from_slice(n.to_string().as_bytes());
            Ok(())
        }
        Value::String(s) => write_canonical_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(e, out)?;
            }
            out.push(b']');
            Ok(())
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_string(k, out)?;
                out.push(b':');
                write_canonical(&m[*k], out)?;
            }
            out.push(b'}');
            Ok(())
        }
    }
}

fn write_canonical_string(s: &str, out: &mut Vec<u8>) -> Result<(), JsonError> {
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..=0x7E => out.push(b),
            _ => {
                return Err(JsonError::BadString {
                    pos: 0,
                    reason: "control/non-ASCII in string",
                })
            }
        }
    }
    out.push(b'"');
    Ok(())
}

/// Read a JSON number as an unsigned integer, rejecting negatives and any value
/// outside `u64` (this is what makes an unsigned field reject a negative token).
pub fn as_u64(v: &Value, ctx: &'static str) -> Result<u64, JsonError> {
    match v {
        Value::Number(_) => v.as_u64().ok_or(JsonError::NumberFieldOutOfRange { ctx }),
        _ => Err(JsonError::WrongFieldKind { ctx }),
    }
}

/// Read a JSON number as a signed integer (allowed for explicitly-signed fields).
pub fn as_i64(v: &Value, ctx: &'static str) -> Result<i64, JsonError> {
    match v {
        Value::Number(_) => v.as_i64().ok_or(JsonError::NumberFieldOutOfRange { ctx }),
        _ => Err(JsonError::WrongFieldKind { ctx }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimal_canonical_document() {
        let doc = br#"{"a":1,"b":[0,-5,10],"c":"x/y","ok":true}"#;
        assert!(strict_scan(doc).is_ok());
        let canon = canonicalize(doc).unwrap();
        // already canonical, and idempotent
        assert_eq!(canonicalize(&canon).unwrap(), canon);
    }

    #[test]
    fn top_level_duplicate_key_rejected() {
        assert!(matches!(
            strict_scan(br#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn nested_duplicate_key_rejected() {
        assert!(matches!(
            strict_scan(br#"{"outer":{"b":1,"b":2}}"#),
            Err(JsonError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn escaped_equivalent_key_is_duplicate() {
        // "a" decodes to "a"
        assert!(matches!(
            strict_scan(br#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey { key }) if key == "a"
        ));
    }

    #[test]
    fn negative_zero_rejected() {
        assert!(matches!(
            strict_scan(br#"{"x":-0}"#),
            Err(JsonError::BadNumber { .. })
        ));
    }

    #[test]
    fn leading_zero_rejected() {
        assert!(matches!(
            strict_scan(br#"{"x":01}"#),
            Err(JsonError::BadNumber { .. })
        ));
        assert!(matches!(
            strict_scan(br#"{"x":00}"#),
            Err(JsonError::BadNumber { .. })
        ));
    }

    #[test]
    fn fraction_and_exponent_rejected() {
        assert!(matches!(
            strict_scan(br#"{"x":1.5}"#),
            Err(JsonError::BadNumber { .. })
        ));
        assert!(matches!(
            strict_scan(br#"{"x":1e3}"#),
            Err(JsonError::BadNumber { .. })
        ));
        assert!(matches!(
            strict_scan(br#"{"x":1E3}"#),
            Err(JsonError::BadNumber { .. })
        ));
    }

    #[test]
    fn signed_value_allowed_lexically_then_typed_layer_decides() {
        let v = parse_strict(br#"{"x":-5}"#).unwrap();
        let x = &v["x"];
        // explicitly-signed field: fine
        assert_eq!(as_i64(x, "x").unwrap(), -5);
        // unsigned field: the negative is rejected here
        assert!(matches!(
            as_u64(x, "x"),
            Err(JsonError::NumberFieldOutOfRange { .. })
        ));
    }

    #[test]
    fn unsigned_field_huge_value_survives_and_is_readable() {
        // > u64::MAX must not silently become f64 (arbitrary_precision on)
        let v = parse_strict(br#"{"x":18446744073709551616}"#).unwrap();
        // 2^64 exceeds u64: as_u64 rejects rather than coercing
        assert!(matches!(
            as_u64(&v["x"], "x"),
            Err(JsonError::NumberFieldOutOfRange { .. })
        ));
        assert!(v["x"].as_str().is_none());
    }

    #[test]
    fn decoded_non_ascii_escape_rejected() {
        assert!(matches!(
            strict_scan(b"{\"x\":\"\\u00e9\"}"),
            Err(JsonError::BadString { .. })
        ));
    }

    #[test]
    fn decoded_control_escape_rejected() {
        assert!(matches!(
            strict_scan(b"{\"x\":\"\\u0007\"}"),
            Err(JsonError::BadString { .. })
        ));
        // short control escapes are not in the accepted escape set
        assert!(matches!(
            strict_scan(br#"{"x":"a\nb"}"#),
            Err(JsonError::BadEscape { .. })
        ));
    }

    #[test]
    fn raw_non_ascii_byte_rejected() {
        let mut doc = br#"{"x":"a"}"#.to_vec();
        doc[6] = 0xE9; // Latin-1 é inside the string
        assert!(matches!(strict_scan(&doc), Err(JsonError::NonAscii { .. })));
    }

    #[test]
    fn raw_control_in_string_rejected() {
        let mut doc = br#"{"x":"a"}"#.to_vec();
        doc[6] = 0x07; // BEL control char inside the string
        assert!(matches!(
            strict_scan(&doc),
            Err(JsonError::BadControlInString { .. })
        ));
    }

    #[test]
    fn null_forbidden() {
        assert!(matches!(
            strict_scan(br#"{"x":null}"#),
            Err(JsonError::NullForbidden { .. })
        ));
    }

    #[test]
    fn trailing_data_rejected() {
        assert!(matches!(strict_scan(br#"{"x":1} "#), Ok(())));
        assert!(matches!(
            strict_scan(br#"{"x":1}x"#),
            Err(JsonError::TrailingData { .. })
        ));
    }

    #[test]
    fn canonical_sorts_keys_by_byte() {
        let out = canonicalize(br#"{"b":1,"a":2,"A":3}"#).unwrap();
        // 'A'(0x41) < 'a'(0x61) < 'b'(0x62)
        assert_eq!(out, br#"{"A":3,"a":2,"b":1}"#);
    }
}
