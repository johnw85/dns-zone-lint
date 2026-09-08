mod record;

use record::{check_zone, parse_line, set_default_ttl, set_origin, ZoneContext};
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    let lines: Vec<String> = match args.get(1) {
        Some(path) => match fs::read_to_string(path) {
            Ok(content) => content.lines().map(str::to_string).collect(),
            Err(e) => {
                eprintln!("failed to read {path}: {e}");
                process::exit(1);
            }
        },
        None => io::stdin().lock().lines().filter_map(Result::ok).collect(),
    };

    let mut ctx = ZoneContext::default();
    let mut had_error = false;
    let mut records = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        let mut fields = line.splitn(2, char::is_whitespace);
        let keyword = fields.next().unwrap_or("");
        let arg = fields.next().unwrap_or("").trim();

        let directive_result = match keyword.to_ascii_uppercase().as_str() {
            "$ORIGIN" => Some(set_origin(&mut ctx, arg)),
            "$TTL" => Some(set_default_ttl(&mut ctx, arg)),
            _ => None,
        };
        if let Some(result) = directive_result {
            if let Err(e) = result {
                had_error = true;
                eprintln!("line {}: {e}", i + 1);
            }
            continue;
        }

        match parse_line(line, &ctx) {
            Ok(record) => records.push(record),
            Err(e) => {
                had_error = true;
                eprintln!("line {}: {e}", i + 1);
            }
        }
    }

    for record in &records {
        println!("{record}");
    }

    for issue in check_zone(&records) {
        had_error = true;
        eprintln!("{issue}");
    }

    if had_error {
        process::exit(1);
    }
}
