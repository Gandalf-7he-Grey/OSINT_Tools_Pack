#!/usr/bin/env bash
# DNS enumeration for a domain - every output line is prefixed with its record type.
# Usage: ./dns_enum.sh [domain] [output_dir]      (see --help)
set -u

usage() {
  cat <<'EOF'
dns_enum.sh - DNS enumeration for a domain.
Every record line is prefixed with its record type, e.g.:
  A: example.com. IN A 93.184.216.34

USAGE
  ./dns_enum.sh [options] [target] [output_dir]

ARGUMENTS
  target       Domain name (example.com). A pasted URL is cleaned automatically.
               IP addresses are not accepted. If omitted, the script asks for
               the domain (the TARGET environment variable is also honoured).
  output_dir   Folder to save results in. If omitted, the script asks for the
               folder and a filename; pressing Enter on both uses the defaults
               (raw/dns and records.txt).

OPTIONS
  -h, --help   Show this help and exit.

WHAT IT DOES
  Queries A AAAA MX NS TXT CNAME SOA CAA, runs host/dig ANY, and attempts a
  zone transfer (AXFR) against each nameserver.

SCREEN OUTPUT
  A grouped, colourised report (records by type, plus a summary line).
  Colours are used only on a terminal; set NO_COLOR=1 to disable them.

OUTPUT FILES (in the output folder)
  <filename>     Plain prefixed records, easy to grep (default: records.txt)
  report.txt     The same readable report shown on screen, without colours
  host_all.txt   Raw output of the host command
  dig_any.txt    Raw output of dig ANY

EXAMPLES
  ./dns_enum.sh                          # interactive
  ./dns_enum.sh example.com              # asks only where to save
  ./dns_enum.sh example.com raw/dns      # no prompts at all
  TARGET=example.com ./dns_enum.sh

Requires: dig, host, awk. Only run against targets you are authorized to test.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -*) echo "Unknown option: $1 (see --help)" >&2; exit 1 ;;
esac

is_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]]
}

TARGET="${1:-${TARGET:-}}"
OUT="${2:-raw/dns}"
DOMAIN_TYPES=(A AAAA MX NS TXT CNAME SOA CAA)
ALL_TYPES="A AAAA MX NS TXT CNAME SOA CAA AXFR"
REPORT_WIDTH=64

for bin in dig host awk; do
  command -v "$bin" >/dev/null || { echo "Missing dependency: $bin" >&2; exit 1; }
done

if [[ -z "$TARGET" ]]; then
  read -rp "Target domain: " TARGET
fi
# Normalise: drop scheme, path and whitespace
TARGET="${TARGET#*://}"; TARGET="${TARGET%%/*}"; TARGET="${TARGET//[[:space:]]/}"
if [[ -z "$TARGET" ]]; then
  echo "No target given." >&2
  exit 1
fi
if is_ip "$TARGET"; then
  echo "Error: '$TARGET' is an IP address. This script accepts domain names only." >&2
  exit 1
fi

# Ask where to save (Enter = defaults: raw/dns and records.txt); skipped if output_dir was passed as an argument
RECORDS_NAME="records.txt"
if [[ -z "${2:-}" ]]; then
  read -rp "Save output to which folder? [${OUT}]: " ans_dir || ans_dir=""
  read -rp "Output filename? [${RECORDS_NAME}]: " ans_name || ans_name=""
  [[ -n "$ans_dir" ]] && OUT="${ans_dir/#\~/$HOME}"
  [[ -n "$ans_name" ]] && RECORDS_NAME="${ans_name##*/}"
fi

# ---------------------------------------------------------------- colours
set_colors() {   # $1 = on|off
  if [[ "$1" == on ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'
    BLU=$'\e[34m'; MAG=$'\e[35m'; CYN=$'\e[36m'; RST=$'\e[0m'
  else
    BOLD=""; DIM=""; RED=""; GRN=""; YEL=""; BLU=""; MAG=""; CYN=""; RST=""
  fi
}

# ---------------------------------------------------------------- collection
# dig answer lines -> "TYPE: name IN TYPE rdata" (TTL dropped)
fmt_answer() {
  awk -v t="$1" '$4 == t { rd = $5; for (i = 6; i <= NF; i++) rd = rd " " $i
                           print t ": " $1 " " $3 " " $4 " " rd }'
}

progress() {   # live status line, only on a terminal
  [[ -t 1 ]] && printf '\r\e[K  %s…' "$1"
  return 0
}

query_type() {   # $1 = record type, $2 = name to query
  local lines
  progress "querying $1 $2"
  lines=$(dig "$2" "$1" +noall +answer | fmt_answer "$1")
  [[ -n "$lines" ]] && echo "$lines" >> "$RECORDS"
  return 0
}

enum_domain() {
  host -t any "$TARGET" > "$OUT/host_all.txt" 2>&1
  dig "$TARGET" ANY > "$OUT/dig_any.txt" 2>&1   # often NOTIMP; raw evidence only

  local t ns out
  for t in "${DOMAIN_TYPES[@]}"; do query_type "$t" "$TARGET"; done

  # Zone transfer attempt against each authoritative nameserver (usually refused)
  for ns in $(dig "$TARGET" NS +short); do
    progress "AXFR attempt against $ns"
    out=$(dig "@${ns%.}" "$TARGET" AXFR +noall +answer 2>&1 | grep -v '^;')
    if [[ -z "$out" ]]; then
      echo "AXFR: ${ns%.} - refused / not allowed" >> "$RECORDS"
    else
      awk '{ print "AXFR: " $0 }' <<<"$out" >> "$RECORDS"
    fi
  done
}

# ---------------------------------------------------------------- rendering
rule() {   # $1 = character, $2 = width (multibyte-safe, no tr)
  local c="${1:-─}" w="${2:-$REPORT_WIDTH}" s="" i
  for ((i = 0; i < w; i++)); do s+="$c"; done
  printf '%s\n' "$s"
}

render_report() {   # reads $RECORDS; colours follow current set_colors state
  echo
  printf '%s' "$CYN$BOLD"; rule '━'; printf '%s' "$RST"
  printf '  %sDNS ENUMERATION REPORT%s\n' "$BOLD" "$RST"
  printf '  %sTarget%s  %s\n' "$DIM" "$RST" "$TARGET"
  printf '  %sDate%s    %s\n' "$DIM" "$RST" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  printf '%s' "$CYN$BOLD"; rule '━'; printf '%s' "$RST"

  awk -v order="$ALL_TYPES" -v sub_rule="$(rule '─' $((REPORT_WIDTH - 4)))" \
      -v B="$BOLD" -v D="$DIM" -v G="$GRN" -v Y="$YEL" -v C="$CYN" -v M="$MAG" -v R="$RST" '
    {
      t = $1; sub(/:$/, "", t)
      if ($3 == "IN" && t != "AXFR") {
        name = $2; val = $5
        for (i = 6; i <= NF; i++) val = val " " $i
      } else {
        name = ""; val = substr($0, length($1) + 2)
      }
      n[t]++; nm[t, n[t]] = name; vl[t, n[t]] = val
      if (length(name) > nw && length(name) <= 40) nw = length(name)
      total++
    }
    function color(t) {
      if (t == "A" || t == "AAAA") return G
      if (t == "MX" || t == "NS") return Y
      if (t == "TXT" || t == "CAA") return M
      return C
    }
    END {
      split(order, ord, " ")
      for (k = 1; k in ord; k++) {
        t = ord[k]
        if (!n[t]) continue
        printf "\n%s%s ▌ %-6s%s %s%d record%s%s\n", B, color(t), t, R, D, n[t], (n[t] > 1 ? "s" : ""), R
        printf "%s  %s%s\n", D, sub_rule, R
        for (i = 1; i <= n[t]; i++) {
          if (nm[t, i] != "") printf "   %s%-*s%s  %s\n", D, nw, nm[t, i], R, vl[t, i]
          else                printf "   %s\n", vl[t, i]
        }
      }
      if (!total) printf "\n  %sNo records found.%s\n", Y, R
      printf "\n"
      for (k = 1; k in ord; k++) {
        t = ord[k]
        if (t == "AXFR") continue
        if (n[t]) printf "  %s%s%s %s%d%s", color(t), B t, R, B, n[t], R
        else      printf "  %s%s 0%s", D, t, R
        printf "  "
      }
      printf "\n"
    }' "$RECORDS"

  printf '\n%s' "$CYN"; rule '━'; printf '%s' "$RST"
}

# ---------------------------------------------------------------- main
mkdir -p "$OUT" || { echo "Cannot create $OUT" >&2; exit 1; }
RECORDS="$OUT/$RECORDS_NAME"
: > "$RECORDS"

enum_domain
[[ -t 1 ]] && printf '\r\e[K'

set_colors off
render_report > "$OUT/report.txt"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then set_colors on; fi
render_report

printf '  Saved to %s/\n    %s   plain prefixed records\n    report.txt   readable report\n    host_all.txt, dig_any.txt   raw output\n\n' \
  "$OUT" "$RECORDS_NAME"
