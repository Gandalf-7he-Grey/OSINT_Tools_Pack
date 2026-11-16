#!/usr/bin/env bash
# whois_enum.sh - Domain + IP whois / ipinfo enumeration.
#
# Give a domain, an IP, or both. Whatever is missing is discovered:
#   domain only -> resolved to IP(s), which are then enumerated
#   IP only     -> reverse DNS / ipinfo hostname gives a domain, which is then enumerated
#   both        -> both are used as given

set -uo pipefail

DEFAULT_DIR="raw/whois"

DOMAIN_FIELDS='registrar|creat|updated|expir|registrant|e-?mail|organi[sz]ation|country|status|name.?server'
IP_FIELDS='netname|org-?name|country|abuse|cidr|netrange|inetnum'
MAX_RESOLVED_IPS=4

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] [TARGET]

Enumerates a domain and/or an IP address using whois and ipinfo.io.
With no arguments you are asked for a domain and an IP address; leave
either one empty and the script discovers it from the other:

  Domain only  Resolves the domain to IPv4 address(es) (max ${MAX_RESOLVED_IPS}) and
               runs the IP whois + ipinfo.io enumeration on them.
  IP only      Runs the IP enumeration, then finds a domain through reverse DNS
               (or the ipinfo.io hostname) and runs the domain whois on it.
  Both         Uses both exactly as given.

Arguments:
  TARGET             A domain or an IP (auto-detected). Same as -d / -i.

Options:
  -d, --domain NAME  Domain to enumerate
  -i, --ip ADDR      IP address (IPv4/IPv6) to enumerate
  -o, --output DIR   Directory for saved files (created if missing).
                     If omitted you are asked; Enter uses '${DEFAULT_DIR}'.
  --summary-only     Do not print the raw whois output (it is still saved)
  --no-ipinfo        Skip ipinfo.io (nothing is sent to ipinfo.io)
  -n, --no-color     Disable colors (also off when piped or NO_COLOR is set)
  -h, --help         Show this help message and exit

Saved files (in the output directory):
  whois_domain.txt   whois_ip.txt   ipinfo.json
  (with several IPs: whois_ip_<ip>.txt and ipinfo_<ip>.json)

Examples:
  $(basename "$0")                         # interactive
  $(basename "$0") example.com
  $(basename "$0") 8.8.8.8
  $(basename "$0") -d example.com -i 93.184.216.34 -o ~/recon/example
EOF
}

DOMAIN=""; IP=""; OUT_DIR=""
USE_COLOR=1; DO_IPINFO=1; SHOW_RAW=1

die() { echo "Error: $*" >&2; exit 1; }

# ---------- validation ----------
is_ip() {
  local a="$1" o
  if [[ "$a" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
    return 0
  fi
  [[ "$a" == *:* && "$a" =~ ^[0-9A-Fa-f:.]+$ ]]
}
is_domain() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]
}
set_domain() { is_domain "$1" || die "invalid domain '$1'"; DOMAIN="${1,,}"; }
set_ip()     { is_ip "$1"     || die "invalid IP address '$1'"; IP="$1"; }

# ---------- arguments ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -n|--no-color) USE_COLOR=0; shift ;;
    --no-ipinfo) DO_IPINFO=0; shift ;;
    --summary-only) SHOW_RAW=0; shift ;;
    -d|--domain) [[ $# -ge 2 ]] || die "$1 requires a value"; set_domain "$2"; shift 2 ;;
    -i|--ip)     [[ $# -ge 2 ]] || die "$1 requires a value"; set_ip "$2"; shift 2 ;;
    -o|--output) [[ $# -ge 2 ]] || die "$1 requires a directory"; OUT_DIR="$2"; shift 2 ;;
    -*) die "unknown option '$1' (try --help)" ;;
    *)
      if is_ip "$1"; then set_ip "$1"
      elif is_domain "$1"; then set_domain "$1"
      else die "'$1' is neither a valid domain nor an IP address"; fi
      shift ;;
  esac
done

command -v whois >/dev/null 2>&1 || die "'whois' not installed (sudo apt install whois)"

# ---------- interactive prompts ----------
if [[ -z "$DOMAIN" && -z "$IP" ]]; then
  [[ -t 0 ]] || die "no target given (see --help)"
  read -r -p "Enter domain (leave empty if unknown): " in_domain
  read -r -p "Enter IP address (leave empty if unknown): " in_ip
  [[ -n "$in_domain" ]] && set_domain "$in_domain"
  [[ -n "$in_ip" ]] && set_ip "$in_ip"
  [[ -z "$DOMAIN" && -z "$IP" ]] && die "you must enter a domain, an IP, or both"
fi

if [[ -z "$OUT_DIR" ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Save output to directory [${DEFAULT_DIR}]: " OUT_DIR
  fi
  OUT_DIR="${OUT_DIR:-$DEFAULT_DIR}"
fi
OUT_DIR="${OUT_DIR/#\~/$HOME}"
[[ "$OUT_DIR" == *.txt || "$OUT_DIR" == *.json ]] && OUT_DIR="$(dirname "$OUT_DIR")"
OUT_DIR="${OUT_DIR%/}"; OUT_DIR="${OUT_DIR:-/}"
mkdir -p "$OUT_DIR" 2>/dev/null && [[ -w "$OUT_DIR" ]] || die "cannot create or write to '$OUT_DIR'"

# ---------- colors & layout ----------
if [[ $USE_COLOR -eq 1 && -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; CYAN=$'\e[36m'; GREEN=$'\e[32m'
  YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
  BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RESET=""
fi

WIDTH=64
rule() {  # rule [char] - multibyte-safe horizontal line
  local i out=""
  for ((i = 0; i < WIDTH; i++)); do out+="${1:-─}"; done
  printf '%s\n' "$out"
}
section() {  # section "Title"
  echo
  printf '%s%s%s\n' "$BOLD$CYAN" "$1" "$RESET"
  printf '%s%s%s\n' "$DIM" "$(rule '─')" "$RESET"
}
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
kv_table() {  # stdin: "key<TAB>value" lines -> aligned table
  local data key val w
  data="$(cat)"
  w="$(printf '%s\n' "$data" | awk -F'\t' '{ if (length($1) > m) m = length($1) } END { print m + 0 }')"
  while IFS=$'\t' read -r key val; do
    printf '  %s%-*s%s %s│%s %s\n' "$BOLD$CYAN" "$w" "$key" "$RESET" "$DIM" "$RESET" "$val"
  done <<< "$data"
}

# ---------- discovery helpers ----------
registrable() {  # best-effort registrable domain from a hostname (no public-suffix list)
  local h="${1,,}" n tld sld
  local -a p
  h="${h%.}"
  IFS=. read -ra p <<< "$h"
  n=${#p[@]}
  (( n <= 2 )) && { echo "$h"; return; }
  tld="${p[n-1]}"; sld="${p[n-2]}"
  if [[ ${#tld} -eq 2 && "$sld" =~ ^(co|com|org|net|gov|edu|ac|or|ne|go|gob|mil)$ ]]; then
    echo "${p[n-3]}.${p[n-2]}.${p[n-1]}"
  else
    echo "${p[n-2]}.${p[n-1]}"
  fi
}

declare -A IPINFO_JSON=() IPINFO_ERR=()
IPINFO_OK=0
if [[ $DO_IPINFO -eq 1 ]] && command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  IPINFO_OK=1
fi

ipinfo_fetch() {  # ipinfo_fetch IP -> fills IPINFO_JSON / IPINFO_ERR
  local ip="$1" out
  if out="$(curl -fsS --max-time 10 "https://ipinfo.io/${ip}" 2>&1)" \
     && printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    IPINFO_JSON["$ip"]="$out"
  else
    IPINFO_ERR["$ip"]="${out:-unexpected response}"
  fi
}

json_get() {  # json_get JSON KEY
  printf '%s' "$1" | python3 -c '
import json, sys
print(json.load(sys.stdin).get(sys.argv[1], ""))' "$2" 2>/dev/null
}

# ---------- gather (resolve / discover) ----------
declare -a IPS=()
IP_SRC=""; DOMAIN_SRC=""

if [[ -n "$IP" ]]; then
  IPS=("$IP"); IP_SRC="provided"
elif [[ -n "$DOMAIN" ]]; then
  mapfile -t IPS < <(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | head -n "$MAX_RESOLVED_IPS")
  IP_SRC="resolved from ${DOMAIN}"
fi
[[ -n "$DOMAIN" && -n "$IP" ]] && DOMAIN_SRC="provided"
[[ -n "$DOMAIN" && -z "$DOMAIN_SRC" ]] && DOMAIN_SRC="provided"

# ---------- banner ----------
printf '%s%s%s\n' "$BOLD$CYAN" "$(rule '═')" "$RESET"
printf '  %sWHOIS LOOKUP%s  %s│%s  domain: %s%s%s  %s│%s  ip: %s%s%s\n' \
  "$BOLD" "$RESET" "$DIM" "$RESET" "$BOLD$GREEN" "${DOMAIN:-auto-detect}" "$RESET" \
  "$DIM" "$RESET" "$BOLD$GREEN" "${IP:-auto-detect}" "$RESET"
printf '%s%s%s\n' "$BOLD$CYAN" "$(rule '═')" "$RESET"

for ip in "${IPS[@]}"; do
  [[ $IPINFO_OK -eq 1 ]] && ipinfo_fetch "$ip"
done

# IP given but no domain: reverse DNS first, then the ipinfo.io hostname
if [[ -z "$DOMAIN" && ${#IPS[@]} -gt 0 ]]; then
  host="$(getent hosts "${IPS[0]}" 2>/dev/null | awk '{print $2; exit}')"
  via="reverse DNS"
  if [[ -z "$host" && -n "${IPINFO_JSON[${IPS[0]}]:-}" ]]; then
    host="$(json_get "${IPINFO_JSON[${IPS[0]}]}" hostname)"; via="ipinfo.io hostname"
  fi
  if [[ -n "$host" ]]; then
    cand="$(registrable "$host")"
    if is_domain "$cand"; then DOMAIN="$cand"; DOMAIN_SRC="${via}: ${host}"; fi
  fi
fi

# ---------- discovery summary ----------
section "TARGETS"
{
  if [[ -n "$DOMAIN" ]]; then printf 'domain\t%s  (%s)\n' "$DOMAIN" "$DOMAIN_SRC"
  else printf 'domain\tnone found  (no reverse DNS / hostname for the IP)\n'; fi
  if [[ ${#IPS[@]} -gt 0 ]]; then
    for ip in "${IPS[@]}"; do printf 'ip\t%s  (%s)\n' "$ip" "$IP_SRC"; done
  else
    printf 'ip\tnone found  (%s did not resolve)\n' "$DOMAIN"
  fi
} | kv_table

# ---------- enumeration blocks ----------
SAVED_FILES=()

strip_legal() {  # drop "TERMS OF USE" / "NOTICE" boilerplate paragraphs (display only)
  printf '%s\n' "$1" | awk '
    skip && /^[[:space:]]*$/ { skip = 0 }
    skip { next }
    tolower($0) ~ /^[[:space:]]*(terms of use|terms and conditions|notice|disclaimer)[[:space:]]*:/ { skip = 1; next }
    { print }'
}

declare -A WHOIS_RESULT=()

whois_collect() {  # whois_collect TARGET FILE - query once, save, remember
  local target="$1" file="$2" result
  result="$(whois "$target" 2>&1)" || warn "whois exited non-zero for $target"
  WHOIS_RESULT["$target"]="$result"
  printf '%s\n' "$result" > "$file"
  SAVED_FILES+=("$file")
}

raw_section() {  # raw_section TARGET
  local target="$1" line
  section "RAW WHOIS  ·  ${target}"
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*[%#] ]]; then
      printf '%s%s%s\n' "$DIM" "$line" "$RESET"
    else
      printf '%s\n' "$line"
    fi
  done <<< "$(strip_legal "${WHOIS_RESULT[$target]}")"
}

summary_section() {  # summary_section Domain|IP TARGET
  local kind="$1" target="$2" fields summary result="${WHOIS_RESULT[$2]}"
  if [[ "$kind" == "IP" ]]; then fields="$IP_FIELDS"; else fields="$DOMAIN_FIELDS"; fi

  section "${kind^^} WHOIS SUMMARY  ·  ${target}"
  summary="$(printf '%s\n' "$result" \
    | grep -iE "^[[:space:]]*[^:]{0,25}(${fields})[^:]{0,25}:[[:space:]]*[^[:space:]]" \
    | grep -vE '^[[:space:]]*[%#>]' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+# Filtered$//' \
    | sort -u \
    | sed -E 's/^([^:]+):[[:space:]]*/\1\t/')"
  if [[ -z "$summary" ]]; then warn "No matching fields found."
  else printf '%s\n' "$summary" | kv_table; fi
}

ipinfo_section() {  # ipinfo_section IP
  local ip="$1" file rows
  section "IPINFO.IO  ·  ${ip}"
  if [[ -z "${IPINFO_JSON[$ip]:-}" ]]; then
    warn "ipinfo.io lookup failed: ${IPINFO_ERR[$ip]:-no data}"
    return
  fi
  if [[ ${#IPS[@]} -gt 1 ]]; then file="${OUT_DIR}/ipinfo_${ip//:/_}.json"
  else file="${OUT_DIR}/ipinfo.json"; fi
  printf '%s\n' "${IPINFO_JSON[$ip]}" > "$file"
  SAVED_FILES+=("$file")
  rows="$(printf '%s' "${IPINFO_JSON[$ip]}" | python3 -c '
import json, sys
for k, v in json.load(sys.stdin).items():
    if k != "readme":
        print(f"{k}\t{v}")')"
  printf '%s\n' "$rows" | kv_table
}

# 1) run every whois query (saves the raw files)
[[ -n "$DOMAIN" ]] && whois_collect "$DOMAIN" "${OUT_DIR}/whois_domain.txt"
for ip in "${IPS[@]}"; do
  if [[ ${#IPS[@]} -gt 1 ]]; then f="${OUT_DIR}/whois_ip_${ip//:/_}.txt"
  else f="${OUT_DIR}/whois_ip.txt"; fi
  whois_collect "$ip" "$f"
done

# 2) raw outputs
if [[ $SHOW_RAW -eq 1 ]]; then
  [[ -n "$DOMAIN" ]] && raw_section "$DOMAIN"
  for ip in "${IPS[@]}"; do raw_section "$ip"; done
fi

# 3) summaries last: domain, then each IP (whois summary + ipinfo.io)
[[ -n "$DOMAIN" ]] && summary_section Domain "$DOMAIN"
for ip in "${IPS[@]}"; do
  summary_section IP "$ip"
  if [[ $DO_IPINFO -eq 1 ]]; then
    if [[ $IPINFO_OK -eq 1 ]]; then ipinfo_section "$ip"
    else section "IPINFO.IO  ·  ${ip}"; warn "Skipped: curl and python3 are required."; fi
  fi
done

# ---------- footer ----------
echo
printf '%s%s%s\n' "$DIM" "$(rule '─')" "$RESET"
for f in "${SAVED_FILES[@]}"; do
  printf '%s[+]%s Saved: %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$f" "$RESET"
done
