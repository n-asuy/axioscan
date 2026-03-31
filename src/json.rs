use std::fmt;
use std::fmt::Write as _;

/// Minimal JSON value type. Covers the full JSON spec: objects, arrays,
/// strings, numbers, booleans, and null. No external dependencies.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    /// Entries preserve insertion order.
    Object(Vec<(String, Json)>),
}

// ---------------------------------------------------------------------------
// Public query API
// ---------------------------------------------------------------------------

impl Json {
    /// Parse a JSON document from a string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the input is not valid JSON.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut p = Parser::new(input);
        let value = p.parse_value()?;
        p.skip_ws();
        if p.pos < p.src.len() {
            return Err(p.err("unexpected trailing content"));
        }
        Ok(value)
    }

    /// Look up a key in an object. Returns `None` for non-objects or missing keys.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns `true` if this value is an object containing `key`.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    // -- Builder helpers for constructing output JSON --

    #[must_use]
    pub fn string(s: &str) -> Self {
        Self::String(s.to_string())
    }

    #[must_use]
    pub fn array(items: Vec<Self>) -> Self {
        Self::Array(items)
    }

    #[must_use]
    pub fn object(entries: Vec<(&str, Self)>) -> Self {
        Self::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// Serialize to a pretty-printed JSON string (2-space indent).
    #[must_use]
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        write_pretty(&mut out, self, 0);
        out
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_pretty_string())
    }
}

// ---------------------------------------------------------------------------
// Parse error
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ParseError {
    pub pos: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON parse error at byte {}: {}", self.pos, self.message)
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Recursive-descent parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    src: &'a [u8],
    text: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            src: input.as_bytes(),
            text: input,
            pos: 0,
        }
    }

    fn err(&self, msg: &str) -> ParseError {
        ParseError {
            pos: self.pos,
            message: msg.to_string(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.src.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), ParseError> {
        match self.advance() {
            Some(b) if b == expected => Ok(()),
            Some(b) => Err(self.err(&format!(
                "expected '{}', found '{}'",
                expected as char, b as char
            ))),
            None => Err(self.err(&format!("expected '{}', found EOF", expected as char))),
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() {
            match self.src[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    // -- Value dispatch --

    fn parse_value(&mut self) -> Result<Json, ParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(Json::String),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b't') => self.parse_keyword("true", Json::Bool(true)),
            Some(b'f') => self.parse_keyword("false", Json::Bool(false)),
            Some(b'n') => self.parse_keyword("null", Json::Null),
            Some(b) if b == b'-' || b.is_ascii_digit() => self.parse_number(),
            Some(b) => Err(self.err(&format!("unexpected character '{}'", b as char))),
            None => Err(self.err("unexpected end of input")),
        }
    }

    // -- String --

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect_byte(b'"')?;
        let mut buf = String::new();

        loop {
            match self.advance() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => return Ok(buf),
                Some(b'\\') => self.parse_escape(&mut buf)?,
                Some(b) => {
                    let start = self.pos - 1;
                    let len = utf8_seq_len(b);
                    if len == 1 {
                        buf.push(b as char);
                    } else {
                        let end = start + len;
                        if end > self.src.len() {
                            return Err(self.err("invalid UTF-8 sequence"));
                        }
                        match std::str::from_utf8(&self.src[start..end]) {
                            Ok(s) => buf.push_str(s),
                            Err(_) => return Err(self.err("invalid UTF-8 sequence")),
                        }
                        self.pos = end;
                    }
                }
            }
        }
    }

    fn parse_escape(&mut self, buf: &mut String) -> Result<(), ParseError> {
        match self.advance() {
            Some(b'"') => buf.push('"'),
            Some(b'\\') => buf.push('\\'),
            Some(b'/') => buf.push('/'),
            Some(b'n') => buf.push('\n'),
            Some(b'r') => buf.push('\r'),
            Some(b't') => buf.push('\t'),
            Some(b'b') => buf.push('\u{0008}'),
            Some(b'f') => buf.push('\u{000C}'),
            Some(b'u') => {
                let cp = self.parse_hex4()?;
                if (0xD800..=0xDBFF).contains(&cp) {
                    // High surrogate — expect \uXXXX low surrogate
                    if self.advance() != Some(b'\\') || self.advance() != Some(b'u') {
                        return Err(self.err("expected low surrogate after high surrogate"));
                    }
                    let low = self.parse_hex4()?;
                    if !(0xDC00..=0xDFFF).contains(&low) {
                        return Err(self.err("invalid low surrogate value"));
                    }
                    let combined = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    buf.push(
                        char::from_u32(combined)
                            .ok_or_else(|| self.err("invalid surrogate codepoint"))?,
                    );
                } else {
                    buf.push(
                        char::from_u32(cp).ok_or_else(|| self.err("invalid unicode codepoint"))?,
                    );
                }
            }
            Some(b) => {
                return Err(self.err(&format!("invalid escape '\\{}'", b as char)));
            }
            None => return Err(self.err("unexpected end of escape sequence")),
        }
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u32, ParseError> {
        let mut val = 0u32;
        for _ in 0..4 {
            let d = match self.advance() {
                Some(b) if b.is_ascii_hexdigit() => {
                    if b.is_ascii_digit() {
                        u32::from(b - b'0')
                    } else {
                        u32::from(b.to_ascii_lowercase() - b'a') + 10
                    }
                }
                _ => return Err(self.err("expected hex digit in \\uXXXX")),
            };
            val = val * 16 + d;
        }
        Ok(val)
    }

    // -- Number --

    fn parse_number(&mut self) -> Result<Json, ParseError> {
        let start = self.pos;

        // Optional minus
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        // Integer part
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b) if b.is_ascii_digit() => {
                self.consume_digits();
            }
            _ => return Err(self.err("expected digit")),
        }

        // Fraction
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err("expected digit after '.'"));
            }
            self.consume_digits();
        }

        // Exponent
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err("expected digit in exponent"));
            }
            self.consume_digits();
        }

        self.text[start..self.pos]
            .parse::<f64>()
            .map(Json::Number)
            .map_err(|_| self.err("invalid number"))
    }

    fn consume_digits(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
    }

    // -- Object --

    fn parse_object(&mut self) -> Result<Json, ParseError> {
        self.expect_byte(b'{')?;
        let mut entries = Vec::new();

        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':')?;
            let value = self.parse_value()?;
            entries.push((key, value));

            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    // -- Array --

    fn parse_array(&mut self) -> Result<Json, ParseError> {
        self.expect_byte(b'[')?;
        let mut items = Vec::new();

        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }

        loop {
            items.push(self.parse_value()?);

            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    // -- Keyword --

    fn parse_keyword(&mut self, word: &str, value: Json) -> Result<Json, ParseError> {
        let end = self.pos + word.len();
        if end <= self.src.len() && &self.text[self.pos..end] == word {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.err(&format!("expected '{word}'")))
        }
    }
}

fn utf8_seq_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// Pretty-printer
// ---------------------------------------------------------------------------

fn write_pretty(out: &mut String, value: &Json, depth: usize) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => {
            // Print integers without trailing ".0"
            #[allow(
                clippy::float_cmp,
                clippy::cast_possible_truncation,
                clippy::cast_precision_loss
            )]
            if *n == (*n as i64) as f64 && n.is_finite() {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let _ = write!(out, "{n}");
            }
        }
        Json::String(s) => write_escaped_string(out, s),
        Json::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                indent(out, depth + 1);
                write_pretty(out, item, depth + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push(']');
        }
        Json::Object(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (key, val)) in entries.iter().enumerate() {
                indent(out, depth + 1);
                write_escaped_string(out, key);
                out.push_str(": ");
                write_pretty(out, val, depth + 1);
                if i + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push('}');
        }
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_escaped_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Primitives --

    #[test]
    fn parse_null() {
        assert_eq!(Json::parse("null").unwrap(), Json::Null);
    }

    #[test]
    fn parse_booleans() {
        assert_eq!(Json::parse("true").unwrap(), Json::Bool(true));
        assert_eq!(Json::parse("false").unwrap(), Json::Bool(false));
    }

    #[test]
    fn parse_integers() {
        assert_eq!(Json::parse("0").unwrap(), Json::Number(0.0));
        assert_eq!(Json::parse("42").unwrap(), Json::Number(42.0));
        assert_eq!(Json::parse("-7").unwrap(), Json::Number(-7.0));
    }

    #[test]
    fn parse_floats() {
        assert_eq!(Json::parse("3.14").unwrap(), Json::Number(3.14));
        assert_eq!(Json::parse("-0.5").unwrap(), Json::Number(-0.5));
    }

    #[test]
    fn parse_exponent() {
        assert_eq!(Json::parse("1e10").unwrap(), Json::Number(1e10));
        assert_eq!(Json::parse("2.5E-3").unwrap(), Json::Number(2.5e-3));
        assert_eq!(Json::parse("-1e+2").unwrap(), Json::Number(-1e2));
    }

    // -- Strings --

    #[test]
    fn parse_simple_string() {
        assert_eq!(
            Json::parse(r#""hello""#).unwrap(),
            Json::String("hello".into())
        );
    }

    #[test]
    fn parse_string_with_spaces() {
        assert_eq!(
            Json::parse(r#""hello world  spaces""#).unwrap().as_str(),
            Some("hello world  spaces"),
        );
    }

    #[test]
    fn parse_string_escapes() {
        let j = Json::parse(r#""a\"b\\c\/d\ne\rf\tg\bh\fi""#).unwrap();
        assert_eq!(j.as_str(), Some("a\"b\\c/d\ne\rf\tg\u{0008}h\u{000C}i"));
    }

    #[test]
    fn parse_unicode_bmp() {
        assert_eq!(
            Json::parse(r#""\u0041\u0042\u0043""#).unwrap().as_str(),
            Some("ABC"),
        );
    }

    #[test]
    fn parse_unicode_surrogate_pair() {
        // U+1F600 GRINNING FACE
        assert_eq!(
            Json::parse(r#""\uD83D\uDE00""#).unwrap().as_str(),
            Some("\u{1F600}"),
        );
    }

    #[test]
    fn parse_multibyte_utf8() {
        assert_eq!(Json::parse("\"日本語\"").unwrap().as_str(), Some("日本語"),);
    }

    // -- Objects --

    #[test]
    fn parse_empty_object() {
        assert_eq!(Json::parse("{}").unwrap(), Json::Object(vec![]));
    }

    #[test]
    fn parse_simple_object() {
        let j = Json::parse(r#"{"name": "test", "version": "1.0"}"#).unwrap();
        assert_eq!(j.get("name").and_then(Json::as_str), Some("test"));
        assert_eq!(j.get("version").and_then(Json::as_str), Some("1.0"));
        assert!(j.get("missing").is_none());
    }

    #[test]
    fn parse_nested_objects() {
        let j = Json::parse(r#"{"a": {"b": {"c": "deep"}}}"#).unwrap();
        assert_eq!(
            j.get("a")
                .and_then(|v| v.get("b"))
                .and_then(|v| v.get("c"))
                .and_then(Json::as_str),
            Some("deep"),
        );
    }

    #[test]
    fn contains_key_works() {
        let j = Json::parse(r#"{"a": 1, "b": 2}"#).unwrap();
        assert!(j.contains_key("a"));
        assert!(!j.contains_key("c"));
        // Non-objects always return false
        assert!(!Json::Null.contains_key("x"));
    }

    // -- Arrays --

    #[test]
    fn parse_empty_array() {
        assert_eq!(Json::parse("[]").unwrap(), Json::Array(vec![]));
    }

    #[test]
    fn parse_mixed_array() {
        let j = Json::parse(r#"[1, "two", true, null]"#).unwrap();
        let items = j.as_array().unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(items[1].as_str(), Some("two"));
    }

    // -- Whitespace handling --

    #[test]
    fn parse_with_abundant_whitespace() {
        let input = "  {  \n  \"key\"  :  \"value\"  \n  }  ";
        let j = Json::parse(input).unwrap();
        assert_eq!(j.get("key").and_then(Json::as_str), Some("value"));
    }

    // -- Real-world package.json --

    #[test]
    fn parse_real_package_json() {
        let input = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "axios": "^1.14.0",
                "react": "^19.0.0"
            },
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }"#;
        let j = Json::parse(input).unwrap();
        assert_eq!(j.get("name").and_then(Json::as_str), Some("my-app"));
        let deps = j.get("dependencies").unwrap();
        assert_eq!(deps.get("axios").and_then(Json::as_str), Some("^1.14.0"));
        assert!(deps.contains_key("react"));
    }

    // -- Error cases --

    #[test]
    fn parse_error_cases() {
        assert!(Json::parse("").is_err());
        assert!(Json::parse("{invalid}").is_err());
        assert!(Json::parse(r#"{"key": }"#).is_err());
        assert!(Json::parse(r#"{"key" "val"}"#).is_err());
        assert!(Json::parse("[1, 2,]").is_err()); // trailing comma
    }

    // -- Pretty printer --

    #[test]
    fn pretty_print_roundtrip() {
        let input = r#"{"name": "test", "deps": {"a": "1"}, "list": [1, 2]}"#;
        let j = Json::parse(input).unwrap();
        let pretty = j.to_pretty_string();
        let reparsed = Json::parse(&pretty).unwrap();
        assert_eq!(j, reparsed);
    }

    #[test]
    fn pretty_print_escapes() {
        let j = Json::String("line1\nline2\t\"quoted\"".into());
        let s = j.to_pretty_string();
        assert_eq!(s, r#""line1\nline2\t\"quoted\"""#);
    }

    #[test]
    fn pretty_print_integers_without_decimal() {
        let j = Json::Number(42.0);
        assert_eq!(j.to_pretty_string(), "42");
    }

    #[test]
    fn pretty_print_empty_containers() {
        assert_eq!(Json::Array(vec![]).to_pretty_string(), "[]");
        assert_eq!(Json::Object(vec![]).to_pretty_string(), "{}");
    }

    // -- Builder helpers --

    #[test]
    fn builder_produces_valid_json() {
        let j = Json::object(vec![
            ("status", Json::string("compromised")),
            (
                "findings",
                Json::array(vec![Json::object(vec![
                    ("path", Json::string("package.json")),
                    ("detail", Json::string("test")),
                ])]),
            ),
        ]);
        let s = j.to_pretty_string();
        let reparsed = Json::parse(&s).unwrap();
        assert_eq!(j, reparsed);
    }
}
