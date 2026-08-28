# dns-zone-lint

Zone files get edited by hand over years by different people, and the
formatting drifts: inconsistent spacing, tabs vs. spaces, trailing dots
that come and go. Nothing catches a typo'd IP address or a record type
that doesn't exist until a resolver somewhere chokes on it. This is a
small parser that reads zone-file style DNS record lines, validates
them, and reprints them in one consistent format so a diff actually
shows you what changed.

It understands A, AAAA, CNAME, NS, PTR, MX, and TXT records. That
covers most of what you'll find in a typical zone file. SOA, SRV, and
the `$ORIGIN`/`$TTL` directives aren't handled yet.

## Usage

Build it with cargo:

```
cargo build --release
```

Feed it a file, or pipe lines on stdin:

```
$ cat zone.txt
example.com.      3600 IN A     192.0.2.1
www.example.com.  3600 IN CNAME example.com.
example.com.      3600 IN MX    10 mail.example.com.
example.com.      3600 IN TXT   "v=spf1 -all"

$ dns-zone-lint zone.txt
example.com.             3600    IN  A      192.0.2.1
www.example.com.         3600    IN  CNAME  example.com.
example.com.             3600    IN  MX     10 mail.example.com.
example.com.             3600    IN  TXT    "v=spf1 -all"
```

Bad input is reported with a line number and left off the printed
output:

```
$ echo 'example.com. 3600 IN A not-an-ip' | dns-zone-lint
line 1: invalid address 'not-an-ip'
```

The exit code is nonzero if any line failed to parse, so this is
usable as a pre-commit check on a zone file.

## Record format

Each line is `name ttl class type rdata`, matching standard zone-file
syntax:

- `name` — a domain name, or `@` for the zone origin
- `ttl` — seconds, as an unsigned 32-bit integer
- `class` — only `IN` is supported
- `type` — one of `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `MX`, `TXT`
- `rdata` — type-specific data (an IP address, a target name, an `MX`
  preference plus target, or a quoted string for `TXT`)

## License

MIT, see LICENSE.
