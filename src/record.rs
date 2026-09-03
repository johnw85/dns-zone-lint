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

fn parse_target(rdata: &str) -> Result<String, ParseError> {
    if rdata.is_empty() || !is_valid_name(rdata) {
        return Err(ParseError::BadName(rdata.to_string()));
    }
    Ok(rdata.to_string())
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
pub fn parse_line(line: &str) -> Result<Record, ParseError> {
    let (name, rest) = take_token(line).ok_or(ParseError::MissingField("name"))?;
    let (ttl_s, rest) = take_token(rest).ok_or(ParseError::MissingField("ttl"))?;
    let (class, rest) = take_token(rest).ok_or(ParseError::MissingField("class"))?;
    let (rtype, rest) = take_token(rest).ok_or(ParseError::MissingField("type"))?;
    let rdata = rest.trim();

    if !is_valid_name(name) {
        return Err(ParseError::BadName(name.to_string()));
    }
    let ttl: u32 = ttl_s.parse().map_err(|_| ParseError::BadTtl(ttl_s.to_string()))?;
    if !class.eq_ignore_ascii_case("IN") {
        return Err(ParseError::UnsupportedClass(class.to_string()));
    }

    let data = match rtype.to_ascii_uppercase().as_str() {
        "A" => rdata
            .parse::<Ipv4Addr>()
            .map(RecordData::A)
            .map_err(|_| ParseError::BadAddress(rdata.to_string()))?,
        "AAAA" => rdata
            .parse::<Ipv6Addr>()
            .map(RecordData::Aaaa)
            .map_err(|_| ParseError::BadAddress(rdata.to_string()))?,
        "CNAME" => RecordData::Cname(parse_target(rdata)?),
        "NS" => RecordData::Ns(parse_target(rdata)?),
        "PTR" => RecordData::Ptr(parse_target(rdata)?),
        "MX" => {
            let (pref_s, exchange_s) = take_token(rdata).ok_or(ParseError::MissingField("mx preference"))?;
            let preference: u16 = pref_s
                .parse()
                .map_err(|_| ParseError::BadMxPreference(pref_s.to_string()))?;
            let exchange = parse_target(exchange_s.trim())?;
            RecordData::Mx { preference, exchange }
        }
        "TXT" => RecordData::Txt(parse_txt(rdata)?),
        "SOA" => {
            let (mname_s, rest) = take_token(rdata).ok_or(ParseError::MissingField("soa mname"))?;
            let mname = parse_target(mname_s)?;
            let (rname_s, rest) = take_token(rest).ok_or(ParseError::MissingField("soa rname"))?;
            let rname = parse_target(rname_s)?;
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
            let target = parse_target(rest.trim())?;
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        other => return Err(ParseError::UnknownType(other.to_string())),
    };

    Ok(Record {
        name: name.to_string(),
        ttl,
        data,
    })
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
