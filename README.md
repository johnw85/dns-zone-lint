# dns-zone-lint

Zone files get edited by hand over years by different people, and the
formatting drifts: inconsistent spacing, tabs vs. spaces, trailing dots
that come and go. Nothing catches a typo'd IP address or a record type
that doesn't exist until a resolver somewhere chokes on it. This is a
small parser that reads zone-file style DNS record lines, validates
them, and reprints them in one consistent format so a diff actually
shows you what changed.

It understands A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, and SRV records.
That covers most of what you'll find in a typical zone file. The
`$ORIGIN`/`$TTL` directives aren't handled yet.

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
example.com.      3600 IN SOA   ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600
_sip._tcp.example.com. 3600 IN SRV 10 60 5060 sipserver.example.com.

$ dns-zone-lint zone.txt
example.com.             3600    IN  A      192.0.2.1
www.example.com.         3600    IN  CNAME  example.com.
example.com.             3600    IN  MX     10 mail.example.com.
example.com.             3600    IN  TXT    "v=spf1 -all"
example.com.             3600    IN  SOA    ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600
_sip._tcp.example.com.   3600    IN  SRV    10 60 5060 sipserver.example.com.
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
- `type` — one of `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `MX`, `TXT`, `SOA`,
  `SRV`
- `rdata` — type-specific data: an IP address for `A`/`AAAA`, a target
  name for `CNAME`/`NS`/`PTR`, a preference plus target for `MX`, a
  quoted string for `TXT`, `mname rname serial refresh retry expire
  minimum` for `SOA`, or `priority weight port target` for `SRV`

## License

MIT, see LICENSE.
