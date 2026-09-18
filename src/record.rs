use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx { preference: u16, exchange: String },
    Txt(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Debug)]
pub enum ParseError {
    MissingField(&'static str),
    BadTtl(String),
    UnsupportedClass(String),
    UnknownType(String),
    BadName(String),
    BadAddress(String),
    BadMxPreference(String),
    BadTxt(String),
    BadSoaField(&'static str, String),
    BadSrvField(&'static str, String),
    TrailingData(String),
    BadOrigin(String),
}

#[derive(Debug)]
pub enum ZoneIssue {
    NoSoa,
    MultipleSoa(Vec<String>),
    CnameConflict(String),
}

impl fmt::Display for ZoneIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneIssue::NoSoa => write!(f, "zone: no SOA record found"),
            ZoneIssue::MultipleSoa(names) => {
                write!(f, "zone: multiple SOA records ({})", names.join(", "))
            }
            ZoneIssue::CnameConflict(name) => write!(
                f,
                "zone: '{name}' has a CNAME alongside other records at the same name"
            ),
        }
    }
}

/// Checks properties that only make sense across the whole zone, as
/// opposed to `parse_line`'s per-line syntax checks: exactly one SOA
/// record, and no name that mixes a CNAME with anything else (RFC 1035
/// 3.6.2 forbids that combination since a CNAME redirects the whole name).
pub fn check_zone(records: &[Record]) -> Vec<ZoneIssue> {
    let mut issues = Vec::new();

    let soa_names: Vec<String> = records
        .iter()
        .filter(|r| matches!(r.data, RecordData::Soa { .. }))
        .map(|r| r.name.clone())
        .collect();
    match soa_names.len() {
        0 => issues.push(ZoneIssue::NoSoa),
        1 => {}
        _ => issues.push(ZoneIssue::MultipleSoa(soa_names)),
    }

    let mut by_name: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for record in records {
        by_name.entry(record.name.as_str()).or_default().push(record);
    }
    for (name, recs) in by_name {
        let has_cname = recs.iter().any(|r| matches!(r.data, RecordData::Cname(_)));
        if has_cname && recs.len() > 1 {
            issues.push(ZoneIssue::CnameConflict(name.to_string()));
        }
    }

    issues
}

/// Tracks the state that `$ORIGIN` and `$TTL` directives carry forward to
/// later lines in the same zone file.
#[derive(Debug, Clone, Default)]
pub struct ZoneContext {
    pub origin: Option<String>,
    pub default_ttl: Option<u32>,
}

pub fn set_origin(ctx: &mut ZoneContext, arg: &str) -> Result<(), ParseError> {
    let arg = arg.trim();
    if arg.is_empty() || !is_valid_name(arg) {
        return Err(ParseError::BadOrigin(arg.to_string()));
    }
    ctx.origin = Some(qualify(arg.to_string(), &ctx.origin));
    Ok(())
}

pub fn set_default_ttl(ctx: &mut ZoneContext, arg: &str) -> Result<(), ParseError> {
    let arg = arg.trim();
    let ttl: u32 = arg.parse().map_err(|_| ParseError::BadTtl(arg.to_string()))?;
    ctx.default_ttl = Some(ttl);
    Ok(())
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingField(field) => write!(f, "missing {field} field"),
            ParseError::BadTtl(s) => write!(f, "invalid ttl '{s}'"),
            ParseError::UnsupportedClass(s) => write!(f, "unsupported class '{s}' (only IN is handled)"),
            ParseError::UnknownType(s) => write!(f, "unknown record type '{s}'"),
            ParseError::BadName(s) => write!(f, "invalid domain name '{s}'"),
            ParseError::BadAddress(s) => write!(f, "invalid address '{s}'"),
            ParseError::BadMxPreference(s) => write!(f, "invalid MX preference '{s}'"),
            ParseError::BadTxt(s) => write!(f, "invalid TXT data '{s}' (expected a quoted string)"),
            ParseError::BadSoaField(field, s) => write!(f, "invalid SOA {field} '{s}'"),
            ParseError::BadSrvField(field, s) => write!(f, "invalid SRV {field} '{s}'"),
            ParseError::TrailingData(s) => write!(f, "unexpected trailing data '{s}'"),
            ParseError::BadOrigin(s) => write!(f, "invalid $ORIGIN value '{s}'"),
        }
    }
}

// Pulls one whitespace-delimited token off the front of `s`, collapsing
// any run of whitespace before it. Returns the remainder unconsumed.
fn take_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    // underscore is not part of the RFC 1035 label alphabet, but it's
    // standard practice for SRV and other "underscore records" (_sip._tcp, _dmarc, ...)
    bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_valid_name(name: &str) -> bool {
    if name == "@" {
        return true;
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return false;
    }
    trimmed.split('.').all(is_valid_label)
}

fn is_record_type(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "A" | "AAAA" | "CNAME" | "NS" | "PTR" | "MX" | "TXT" | "SOA" | "SRV"
    )
}

// A name ending in '.' is already absolute. '@' stands for the current
// origin. Anything else is relative and gets the origin appended, same as
// BIND does when reading a zone file.
fn qualify(name: String, origin: &Option<String>) -> String {
    if name == "@" {
        return origin.clone().unwrap_or(name);
    }
    if name.ends_with('.') {
        return name;
    }
    match origin {
        Some(o) => format!("{name}.{o}"),
        None => name,
    }
}

fn parse_target(rdata: &str, ctx: &ZoneContext) -> Result<String, ParseError> {
    if rdata.is_empty() || !is_valid_name(rdata) {
        return Err(ParseError::BadName(rdata.to_string()));
    }
    Ok(qualify(rdata.to_string(), &ctx.origin))
}

// TXT data is a double-quoted string; `\"` is the only recognized escape.
fn parse_txt(rdata: &str) -> Result<String, ParseError> {
    let bytes = rdata.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(ParseError::BadTxt(rdata.to_string()));
    }
    let inner = &rdata[1..rdata.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => return Err(ParseError::BadTxt(rdata.to_string())),
            }
        } else if c == '"' {
            // an unescaped quote before the closing one means the string
            // was malformed
            return Err(ParseError::BadTxt(rdata.to_string()));
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Parses one zone-file style record line, e.g.
/// `example.com. 3600 IN A 192.0.2.1`
///
/// The ttl and class fields are both optional and may appear in either
/// order, matching standard zone-file grammar. A missing ttl falls back to
/// `ctx.default_ttl` (set by a preceding `$TTL` directive); a missing class
/// is always treated as `IN`, the only class this tool supports.
pub fn parse_line(line: &str, ctx: &ZoneContext) -> Result<Record, ParseError> {
    let (name, mut rest) = take_token(line).ok_or(ParseError::MissingField("name"))?;
    if !is_valid_name(name) {
        return Err(ParseError::BadName(name.to_string()));
    }

    let mut ttl: Option<u32> = None;
    let mut saw_class = false;
    let rtype = loop {
        let (tok, remainder) = take_token(rest).ok_or(ParseError::MissingField("type"))?;
        if is_record_type(tok) {
            rest = remainder;
            break tok;
        } else if tok.eq_ignore_ascii_case("IN") {
            if saw_class {
                return Err(ParseError::TrailingData(tok.to_string()));
            }
            saw_class = true;
            rest = remainder;
        } else if tok.as_bytes().first().is_some_and(|b| b.is_ascii_digit() || *b == b'-') {
            if ttl.is_some() {
                return Err(ParseError::TrailingData(tok.to_string()));
            }
            ttl = Some(tok.parse().map_err(|_| ParseError::BadTtl(tok.to_string()))?);
            rest = remainder;
        } else {
            return Err(ParseError::UnsupportedClass(tok.to_string()));
        }
    };
    let rdata = rest.trim();

    let ttl = match ttl.or(ctx.default_ttl) {
        Some(ttl) => ttl,
        None => return Err(ParseError::MissingField("ttl")),
    };
    let name = qualify(name.to_string(), &ctx.origin);

    let data = match rtype.to_ascii_uppercase().as_str() {
        "A" => rdata
            .parse::<Ipv4Addr>()
            .map(RecordData::A)
            .map_err(|_| ParseError::BadAddress(rdata.to_string()))?,
        "AAAA" => rdata
            .parse::<Ipv6Addr>()
            .map(RecordData::Aaaa)
            .map_err(|_| ParseError::BadAddress(rdata.to_string()))?,
        "CNAME" => RecordData::Cname(parse_target(rdata, ctx)?),
        "NS" => RecordData::Ns(parse_target(rdata, ctx)?),
        "PTR" => RecordData::Ptr(parse_target(rdata, ctx)?),
        "MX" => {
            let (pref_s, exchange_s) = take_token(rdata).ok_or(ParseError::MissingField("mx preference"))?;
            let preference: u16 = pref_s
                .parse()
                .map_err(|_| ParseError::BadMxPreference(pref_s.to_string()))?;
            let exchange = parse_target(exchange_s.trim(), ctx)?;
            RecordData::Mx { preference, exchange }
        }
        "TXT" => RecordData::Txt(parse_txt(rdata)?),
        "SOA" => {
            let (mname_s, rest) = take_token(rdata).ok_or(ParseError::MissingField("soa mname"))?;
            let mname = parse_target(mname_s, ctx)?;
            let (rname_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa rname"))?;
            let rname = parse_target(rname_s, ctx)?;
            let (serial_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa serial"))?;
            let serial: u32 = serial_s
                .parse()
                .map_err(|_| ParseError::BadSoaField("serial", serial_s.to_string()))?;
            let (refresh_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa refresh"))?;
            let refresh: u32 = refresh_s
                .parse()
                .map_err(|_| ParseError::BadSoaField("refresh", refresh_s.to_string()))?;
            let (retry_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa retry"))?;
            let retry: u32 = retry_s
                .parse()
                .map_err(|_| ParseError::BadSoaField("retry", retry_s.to_string()))?;
            let (expire_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa expire"))?;
            let expire: u32 = expire_s
                .parse()
                .map_err(|_| ParseError::BadSoaField("expire", expire_s.to_string()))?;
            let (minimum_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa minimum"))?;
            let minimum: u32 = minimum_s
                .parse()
                .map_err(|_| ParseError::BadSoaField("minimum", minimum_s.to_string()))?;
            let trailing = rest.trim();
            if !trailing.is_empty() {
                return Err(ParseError::TrailingData(trailing.to_string()));
            }
            RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }
        }
        "SRV" => {
            let (priority_s, rest) = take_token(rdata).ok_or(ParseError::MissingField("srv priority"))?;
            let priority: u16 = priority_s
                .parse()
                .map_err(|_| ParseError::BadSrvField("priority", priority_s.to_string()))?;
            let (weight_s, rest) = take_token(rest).ok_or(ParseError::MissingField("srv weight"))?;
            let weight: u16 = weight_s
                .parse()
                .map_err(|_| ParseError::BadSrvField("weight", weight_s.to_string()))?;
            let (port_s, rest) = take_token(rest).ok_or(ParseError::MissingField("srv port"))?;
            let port: u16 = port_s
                .parse()
                .map_err(|_| ParseError::BadSrvField("port", port_s.to_string()))?;
            let target = parse_target(rest.trim(), ctx)?;
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        other => return Err(ParseError::UnknownType(other.to_string())),
    };

    Ok(Record { name, ttl, data })
}

// Minimal JSON string escaping: the domain names and rdata this tool
// produces are almost always plain ASCII, but TXT records can carry
// arbitrary decoded text, so control characters and quotes still need
// escaping to keep the output valid.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Record {
    /// Renders one record as a single-line JSON object, for `--json` output.
    pub fn to_json(&self) -> String {
        let name = json_escape(&self.name);
        let (rtype, data) = match &self.data {
            RecordData::A(addr) => ("A", format!(r#"{{"address":{}}}"#, json_escape(&addr.to_string()))),
            RecordData::Aaaa(addr) => ("AAAA", format!(r#"{{"address":{}}}"#, json_escape(&addr.to_string()))),
            RecordData::Cname(target) => ("CNAME", format!(r#"{{"target":{}}}"#, json_escape(target))),
            RecordData::Ns(target) => ("NS", format!(r#"{{"target":{}}}"#, json_escape(target))),
            RecordData::Ptr(target) => ("PTR", format!(r#"{{"target":{}}}"#, json_escape(target))),
            RecordData::Mx { preference, exchange } => (
                "MX",
                format!(r#"{{"preference":{},"exchange":{}}}"#, preference, json_escape(exchange)),
            ),
            RecordData::Txt(text) => ("TXT", format!(r#"{{"text":{}}}"#, json_escape(text))),
            RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => (
                "SOA",
                format!(
                    r#"{{"mname":{},"rname":{},"serial":{serial},"refresh":{refresh},"retry":{retry},"expire":{expire},"minimum":{minimum}}}"#,
                    json_escape(mname),
                    json_escape(rname),
                ),
            ),
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => (
                "SRV",
                format!(
                    r#"{{"priority":{priority},"weight":{weight},"port":{port},"target":{}}}"#,
                    json_escape(target)
                ),
            ),
        };
        format!(
            r#"{{"name":{name},"ttl":{},"type":"{rtype}","data":{data}}}"#,
            self.ttl
        )
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (rtype, rdata) = match &self.data {
            RecordData::A(addr) => ("A", addr.to_string()),
            RecordData::Aaaa(addr) => ("AAAA", addr.to_string()),
            RecordData::Cname(target) => ("CNAME", target.clone()),
            RecordData::Ns(target) => ("NS", target.clone()),
            RecordData::Ptr(target) => ("PTR", target.clone()),
            RecordData::Mx { preference, exchange } => ("MX", format!("{preference} {exchange}")),
            RecordData::Txt(text) => ("TXT", format!("\"{}\"", text.replace('"', "\\\""))),
            RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => (
                "SOA",
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
            ),
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => ("SRV", format!("{priority} {weight} {port} {target}")),
        };
        write!(f, "{:<24} {:<7} IN  {:<6} {}", self.name, self.ttl, rtype, rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soa_record(name: &str) -> Record {
        Record {
            name: name.to_string(),
            ttl: 3600,
            data: RecordData::Soa {
                mname: "ns1.example.com.".to_string(),
                rname: "admin.example.com.".to_string(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 3600,
            },
        }
    }

    #[test]
    fn parses_a_record() {
        let record = parse_line("example.com. 3600 IN A 192.0.2.1", &ZoneContext::default()).unwrap();
        assert_eq!(record.name, "example.com.");
        assert_eq!(record.ttl, 3600);
        assert_eq!(record.data, RecordData::A("192.0.2.1".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn parses_mx_record_with_preference() {
        let record = parse_line("example.com. 3600 IN MX 10 mail.example.com.", &ZoneContext::default()).unwrap();
        assert_eq!(
            record.data,
            RecordData::Mx {
                preference: 10,
                exchange: "mail.example.com.".to_string(),
            }
        );
    }

    #[test]
    fn rejects_missing_name() {
        let err = parse_line("   ", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::MissingField("name")));
    }

    #[test]
    fn rejects_missing_ttl_with_no_default() {
        let err = parse_line("example.com. A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::MissingField("ttl")));
    }

    #[test]
    fn falls_back_to_default_ttl_directive() {
        let mut ctx = ZoneContext::default();
        set_default_ttl(&mut ctx, "1800").unwrap();
        let record = parse_line("example.com. A 192.0.2.1", &ctx).unwrap();
        assert_eq!(record.ttl, 1800);
    }

    #[test]
    fn rejects_negative_ttl() {
        let err = parse_line("example.com. -5 IN A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadTtl(s) if s == "-5"));
    }

    #[test]
    fn rejects_ttl_overflowing_u32() {
        let err = parse_line("example.com. 4294967296 IN A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadTtl(s) if s == "4294967296"));
    }

    #[test]
    fn rejects_duplicate_ttl() {
        let err = parse_line("example.com. 3600 1800 IN A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::TrailingData(s) if s == "1800"));
    }

    #[test]
    fn rejects_duplicate_class() {
        let err = parse_line("example.com. 3600 IN IN A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::TrailingData(s) if s == "IN"));
    }

    #[test]
    fn rejects_unsupported_class() {
        let err = parse_line("example.com. 3600 CH A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedClass(s) if s == "CH"));
    }

    #[test]
    fn rejects_name_with_leading_hyphen_label() {
        let err = parse_line("-bad-.example.com. 3600 IN A 192.0.2.1", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadName(s) if s == "-bad-.example.com."));
    }

    #[test]
    fn rejects_cname_target_with_invalid_label() {
        let err = parse_line("www.example.com. 3600 IN CNAME -bad-.example.com.", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadName(s) if s == "-bad-.example.com."));
    }

    #[test]
    fn rejects_bad_ipv4_address() {
        let err = parse_line("example.com. 3600 IN A not-an-ip", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadAddress(s) if s == "not-an-ip"));
    }

    #[test]
    fn rejects_bad_ipv6_address() {
        let err = parse_line("example.com. 3600 IN AAAA not-an-ip", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadAddress(s) if s == "not-an-ip"));
    }

    #[test]
    fn rejects_non_numeric_mx_preference() {
        let err = parse_line("example.com. 3600 IN MX ten mail.example.com.", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadMxPreference(s) if s == "ten"));
    }

    #[test]
    fn rejects_mx_with_no_exchange() {
        let err = parse_line("example.com. 3600 IN MX 10", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadName(s) if s.is_empty()));
    }

    #[test]
    fn rejects_txt_without_quotes() {
        let err = parse_line("example.com. 3600 IN TXT hello", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadTxt(s) if s == "hello"));
    }

    #[test]
    fn rejects_txt_missing_closing_quote() {
        let err = parse_line("example.com. 3600 IN TXT \"unterminated", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadTxt(s) if s == "\"unterminated"));
    }

    #[test]
    fn rejects_txt_with_unescaped_inner_quote() {
        let err = parse_line("example.com. 3600 IN TXT \"foo\"bar\"", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadTxt(_)));
    }

    #[test]
    fn rejects_soa_with_missing_fields() {
        let err = parse_line(
            "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 7200 3600",
            &ZoneContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::MissingField("soa expire")));
    }

    #[test]
    fn rejects_soa_with_non_numeric_serial() {
        let err = parse_line(
            "example.com. 3600 IN SOA ns1.example.com. admin.example.com. abc 7200 3600 1209600 3600",
            &ZoneContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::BadSoaField("serial", s) if s == "abc"));
    }

    #[test]
    fn rejects_soa_with_trailing_data() {
        let err = parse_line(
            "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600 extra",
            &ZoneContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::TrailingData(s) if s == "extra"));
    }

    #[test]
    fn rejects_srv_with_non_numeric_priority() {
        let err = parse_line(
            "_sip._tcp.example.com. 3600 IN SRV abc 60 5060 sipserver.example.com.",
            &ZoneContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::BadSrvField("priority", s) if s == "abc"));
    }

    #[test]
    fn rejects_srv_with_no_target() {
        let err = parse_line("_sip._tcp.example.com. 3600 IN SRV 10 60 5060", &ZoneContext::default()).unwrap_err();
        assert!(matches!(err, ParseError::BadName(s) if s.is_empty()));
    }

    #[test]
    fn rejects_empty_origin_directive() {
        let mut ctx = ZoneContext::default();
        let err = set_origin(&mut ctx, "   ").unwrap_err();
        assert!(matches!(err, ParseError::BadOrigin(s) if s.is_empty()));
    }

    #[test]
    fn rejects_origin_with_invalid_label() {
        let mut ctx = ZoneContext::default();
        let err = set_origin(&mut ctx, "-bad-").unwrap_err();
        assert!(matches!(err, ParseError::BadOrigin(s) if s == "-bad-"));
    }

    #[test]
    fn rejects_non_numeric_ttl_directive() {
        let mut ctx = ZoneContext::default();
        let err = set_default_ttl(&mut ctx, "abc").unwrap_err();
        assert!(matches!(err, ParseError::BadTtl(s) if s == "abc"));
    }

    #[test]
    fn origin_qualifies_relative_names() {
        let mut ctx = ZoneContext::default();
        set_origin(&mut ctx, "example.com.").unwrap();
        let record = parse_line("www 3600 IN A 192.0.2.1", &ctx).unwrap();
        assert_eq!(record.name, "www.example.com.");
    }

    #[test]
    fn zone_flags_missing_soa() {
        let records = vec![Record {
            name: "example.com.".to_string(),
            ttl: 3600,
            data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }];
        assert!(matches!(check_zone(&records).as_slice(), [ZoneIssue::NoSoa]));
    }

    #[test]
    fn zone_flags_multiple_soa() {
        let records = vec![soa_record("example.com."), soa_record("example.org.")];
        let issues = check_zone(&records);
        assert!(matches!(issues.as_slice(), [ZoneIssue::MultipleSoa(names)] if names.len() == 2));
    }

    #[test]
    fn zone_flags_cname_conflict() {
        let records = vec![
            soa_record("example.com."),
            Record {
                name: "www.example.com.".to_string(),
                ttl: 3600,
                data: RecordData::Cname("example.com.".to_string()),
            },
            Record {
                name: "www.example.com.".to_string(),
                ttl: 3600,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
            },
        ];
        let issues = check_zone(&records);
        assert!(matches!(issues.as_slice(), [ZoneIssue::CnameConflict(name)] if name == "www.example.com."));
    }

    #[test]
    fn zone_with_soa_and_no_conflicts_has_no_issues() {
        let records = vec![
            soa_record("example.com."),
            Record {
                name: "www.example.com.".to_string(),
                ttl: 3600,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
            },
        ];
        assert!(check_zone(&records).is_empty());
    }
}
