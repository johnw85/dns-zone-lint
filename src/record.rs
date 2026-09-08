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
