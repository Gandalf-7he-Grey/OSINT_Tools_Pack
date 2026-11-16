# OSINT Tools Pack

A small set of Bash reconnaissance scripts for the information-gathering phase of a penetration test. Each tool is a single self-contained script in its own folder, prints a colourised report to the terminal, and saves a plain-text copy of its results to disk.

| Tool | Folder | What it does | Touches the target? |
|---|---|---|---|
| Subdomain enumeration | [`subdomain_enum/`](subdomain_enum) | Lists subdomains seen in public certificate transparency logs (crt.sh) | No (passive) |
| DNS enumeration | [`dns_enum/`](dns_enum) | Pulls A, AAAA, MX, NS, TXT, CNAME, SOA and CAA records, and tries a zone transfer | Yes (DNS queries to its nameservers) |
| HTTP header audit | [`http_headers_audit/`](http_headers_audit) | Fetches HTTP/HTTPS headers, checks the HTTP to HTTPS redirect, audits security headers | Yes (a few HTTP requests) |
| Whois / IP info | [`whois_enum/`](whois_enum) | Domain and IP whois plus ipinfo.io details; discovers the IP or domain you did not supply | No direct contact (third-party lookups) |

> **Authorized use only.** Run these tools only against systems you own or have written permission to test. The DNS zone-transfer attempt and the HTTP requests are visible in the target's logs.

## Requirements

Tested on Kali Linux. All scripts need Bash 4+ (associative arrays, `mapfile`).

| Script | Dependencies |
|---|---|
| `subdomain_enum.sh` | `curl`, `jq`, `awk` |
| `dns_enum.sh` | `dig`, `host` (package `dnsutils` / `bind9-dnsutils`), `awk` |
| `http_headers_audit.sh` | `curl`; `dig` is optional (used for IP and domain discovery) |
| `whois_enum.sh` | `whois`; `curl` and `python3` for the ipinfo.io part (optional) |

```bash
sudo apt install curl jq dnsutils whois python3
```

## Installation

```bash
git clone https://github.com/Gandalf-7he-Grey/OSINT_Tools_Pack.git
cd OSINT_Tools_Pack
chmod +x */*.sh
```

Every script supports `-h` / `--help` for the full option list.

## Usage

### Subdomain enumeration

```bash
./subdomain_enum/subdomain_enum.sh                   # interactive
./subdomain_enum/subdomain_enum.sh example.com       # asks only where to save
./subdomain_enum/subdomain_enum.sh example.com raw   # no prompts
```

Queries `crt.sh` for every certificate issued to `*.<domain>`, then removes wildcards, lower-cases names, drops entries outside the target domain and de-duplicates. Failed or empty crt.sh responses are retried because the service is often overloaded. Nothing is sent to the target, but only names that appeared on a public certificate are found, so the list is never complete.

Output (default folder `raw/`): `subdomains.txt` (one per line), `report.txt`, `crtsh_raw.json`.

### DNS enumeration

```bash
./dns_enum/dns_enum.sh                          # interactive
./dns_enum/dns_enum.sh example.com              # asks only where to save
./dns_enum/dns_enum.sh example.com raw/dns      # no prompts
TARGET=example.com ./dns_enum/dns_enum.sh
```

Queries A, AAAA, MX, NS, TXT, CNAME, SOA and CAA, runs `host -t any` and `dig ANY`, then attempts an AXFR zone transfer against every authoritative nameserver. Every record line is prefixed with its type (`A:`, `MX:` and so on), which makes the output easy to `grep`. Domain names only; IP addresses are rejected.

Output (default folder `raw/dns/`): `records.txt`, `report.txt`, `host_all.txt`, `dig_any.txt`.

A successful AXFR is a serious misconfiguration: it hands out the entire zone. Most servers refuse it, and the report says so per nameserver.

### HTTP header audit

```bash
./http_headers_audit/http_headers_audit.sh                     # asks for domain and/or IP
./http_headers_audit/http_headers_audit.sh example.com
./http_headers_audit/http_headers_audit.sh -i 203.0.113.10     # finds domains on that IP
./http_headers_audit/http_headers_audit.sh -d example.com -i 203.0.113.10
./http_headers_audit/http_headers_audit.sh -L -o report.txt example.com
```

| Option | Meaning |
|---|---|
| `-d, --domain NAME` | Target domain |
| `-i, --ip ADDR` | Target IP address |
| `-o, --output FILE` | Report file (default `raw/headers/<target>_headers_report.txt`) |
| `-L, --follow` | Audit the final page after following redirects |
| `-t, --timeout SEC` | Request timeout, default 10 |
| `-k, --insecure` | Ignore TLS certificate errors (always on for IP targets) |

The report has four sections: HTTPS response headers, HTTP response headers, the HTTP to HTTPS redirect verdict (301/308 good, 302/307 temporary, 200 means no HTTPS enforcement), and an audit of eight security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP) with a risk rating and impact for each missing one.

Note: the IP to domain lookup sends the IP to `api.hackertarget.com`. On shared or CDN IPs it can return many unrelated domains. When run non-interactively (piped, cron) no questions are asked.

### Whois / IP info

```bash
./whois_enum/whois_enum.sh                    # interactive
./whois_enum/whois_enum.sh example.com
./whois_enum/whois_enum.sh 8.8.8.8
./whois_enum/whois_enum.sh -d example.com -i 93.184.216.34 -o ~/recon/example
```

| Option | Meaning |
|---|---|
| `-d, --domain NAME` / `-i, --ip ADDR` | Domain and/or IP (a bare argument is auto-detected) |
| `-o, --output DIR` | Output directory (default `raw/whois`) |
| `--summary-only` | Do not print raw whois output (it is still saved) |
| `--no-ipinfo` | Skip ipinfo.io, so nothing is sent to it |
| `-n, --no-color` | Disable colours (also off when piped or `NO_COLOR` is set) |

Give a domain, an IP, or both. With a domain only, it resolves up to four IPv4 addresses and enumerates them. With an IP only, it uses reverse DNS (or the ipinfo.io hostname) to guess the domain. The registrable-domain guess has no public-suffix list, so treat it as a hint.

Output: `whois_domain.txt`, `whois_ip.txt`, `ipinfo.json` (with several IPs: `whois_ip_<ip>.txt`, `ipinfo_<ip>.json`).

## Output and colours

Colours appear only when writing to a terminal. Set `NO_COLOR=1` to turn them off. Saved reports never contain colour codes.

## Privacy notes

`subdomain_enum.sh` sends the domain to crt.sh. `http_headers_audit.sh` may send an IP to api.hackertarget.com. `whois_enum.sh` sends IPs to ipinfo.io unless you pass `--no-ipinfo`. Keep this in mind for sensitive engagements.

## License

GPL-3.0, see [LICENSE](LICENSE).
