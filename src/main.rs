mod record;

use record::parse_line;
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

    let mut had_error = false;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        match parse_line(line) {
            Ok(record) => println!("{record}"),
            Err(e) => {
                had_error = true;
                eprintln!("line {}: {e}", i + 1);
            }
        }
    }

    if had_error {
        process::exit(1);
    }
}
