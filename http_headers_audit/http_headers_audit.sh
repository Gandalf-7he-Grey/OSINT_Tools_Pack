#!/usr/bin/env bash
# http_headers_audit.sh — passive HTTP(S) header fingerprinting, redirect check
# and security-header audit. Accepts a domain, an IP, or both. If only one is
# given it can discover the other (IP -> domains, domain -> IPs) and ask which
# one to use. Saves ONE report file.

set -uo pipefail

VERSION="3.0"
OUTFILE=""
FOLLOW=0
TIMEOUT=10
DOMAIN=""
IP=""
INSECURE=()
TARGETS=()   # hosts to audit, in order
NOTES=()     # discovery notes shown in the report

# header | risk | impact if missing
SECURITY_HEADERS=(
  "Strict-Transport-Security|Medium|HTTP downgrade, cookie interception"
  "Content-Security-Policy|Medium|Increased XSS impact, data exfiltration"
  "X-Frame-Options|Low-Medium|Clickjacking attacks"
  "X-Content-Type-Options|Low|MIME sniffing, content injection"
  "Referrer-Policy|Low|Sensitive URL leakage to third parties"
  "Permissions-Policy|Informational|Unnecessary browser API access"
  "Cross-Origin-Opener-Policy|Low|Cross-window attacks (XS-Leaks, Spectre-style)"
  "Cross-Origin-Embedder-Policy|Informational|No cross-origin isolation"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] [domain-or-ip]

Passive HTTP fingerprinting. Performs:
  1. Fetch HTTPS and HTTP response headers
  2. Check whether HTTP redirects to HTTPS (and how)
  3. Audit security headers (present / missing + risk and impact)
Everything is saved to a single report file.

Interactive mode (no target given):
  You are asked for a Domain and an IP. Fill in one or both.
  - Only IP     -> the tool looks up domains hosted on that IP (reverse DNS +
                   reverse-IP lookup), asks if you want to continue with a
                   domain, and lets you pick one from a numbered list.
  - Only domain -> the tool resolves the domain's IP address(es), asks if you
                   want to audit the IP too, and lets you pick if several.

Options:
  -d, --domain NAME   Target domain
  -i, --ip ADDR       Target IP address
  -o, --output FILE   Report file (default: raw/headers/<target>_headers_report.txt)
  -L, --follow        Audit the final page after following redirects
  -t, --timeout SEC   Request timeout in seconds (default: $TIMEOUT)
  -k, --insecure      Ignore TLS certificate errors (always on for IP targets)
  -h, --help          Show this help and exit
  -V, --version       Show version and exit

A bare positional argument is auto-detected as an IP or a domain.

Notes:
  - The IP -> domain step sends the IP to api.hackertarget.com (free reverse-IP
    lookup). Shared/CDN IPs can return many unrelated domains.
  - Without a terminal (piped/cron) no questions are asked; only the targets you
    supplied are audited.

Examples:
  $(basename "$0")                      # asks for domain and IP
  $(basename "$0") example.com
  $(basename "$0") -i 203.0.113.10      # finds domains on that IP, asks which
  $(basename "$0") -d example.com -i 203.0.113.10
  $(basename "$0") -L -o report.txt example.com

Only run against targets you are authorized to test.
EOF
}

die() { echo "[!] $*" >&2; exit 1; }

# ─── validation helpers ────────────────────────────────────────────────────
is_ip() {
  local v4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  [[ "$1" =~ $v4 ]] || [[ "$1" =~ ^[0-9A-Fa-f:]+$ && "$1" == *:*:* ]]
}
is_domain() {
  local re='^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
  [[ "$1" =~ $re ]]
}
clean_host() {
  local h="$1"
  h="${h#http://}"; h="${h#https://}"; h="${h%%/*}"; h="${h//[[:space:]]/}"
  printf '%s' "$h"
}

# ─── argument parsing ──────────────────────────────────────────────────────
set_target() {
  local h; h="$(clean_host "$1")"
  if is_ip "$h"; then
    [[ -z "$IP" ]] || die "Only one IP allowed."; IP="$h"
  elif is_domain "$h"; then
    [[ -z "$DOMAIN" ]] || die "Only one domain allowed."; DOMAIN="$h"
  else
    die "'$1' is not a valid domain or IP."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    -V|--version) echo "$(basename "$0") $VERSION"; exit 0 ;;
    -d|--domain)  [[ $# -ge 2 ]] || die "$1 needs a value"
                  DOMAIN="$(clean_host "$2")"; is_domain "$DOMAIN" || die "Invalid domain: $2"; shift 2 ;;
    -i|--ip)      [[ $# -ge 2 ]] || die "$1 needs a value"
                  IP="$(clean_host "$2")"; is_ip "$IP" || die "Invalid IP: $2"; shift 2 ;;
    -o|--output)  [[ $# -ge 2 ]] || die "$1 needs a value"; OUTFILE="$2"; shift 2 ;;
    -t|--timeout) [[ $# -ge 2 ]] || die "$1 needs a value"; TIMEOUT="$2"; shift 2 ;;
    -L|--follow)  FOLLOW=1; shift ;;
    -k|--insecure) INSECURE=(-k); shift ;;
    -*) usage >&2; die "Unknown option: $1" ;;
    *)  set_target "$1"; shift ;;
  esac
done

[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout must be an integer."
command -v curl >/dev/null || die "curl is required."

# ─── terminal styling (report file is always stripped of colors) ───────────
if [[ -t 1 ]]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; D=""; R=""; G=""; Y=""; C=""; N=""
fi
INTERACTIVE=0; [[ -t 0 && -t 1 ]] && INTERACTIVE=1

# ─── interactive helpers ───────────────────────────────────────────────────
confirm() {   # confirm "question"  -> 0 if yes (default: no)
  local ans
  read -rp "$1 [y/N]: " ans
  [[ "$ans" =~ ^[Yy] ]]
}

menu() {      # menu "title" items...  -> sets CHOICE (empty = skipped)
  local title="$1"; shift
  local items=("$@") i ans shown=${#items[@]} max=30
  (( shown > max )) && shown=$max
  CHOICE=""
  echo
  echo "${B}${title}${N}"
  for ((i = 0; i < shown; i++)); do
    printf '  %s[%d]%s %s\n' "$C" "$((i + 1))" "$N" "${items[$i]}"
  done
  if (( ${#items[@]} > shown )); then
    printf '  %s… %d more not shown — type a name from the list to pick it directly%s\n' \
      "$D" "$(( ${#items[@]} - shown ))" "$N"
  fi
  printf '  %s[0]%s Skip\n' "$D" "$N"
  while true; do
    read -rp "Choose 0-${shown}: " ans
    if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans <= shown )); then
      (( ans == 0 )) || CHOICE="${items[$((ans - 1))]}"
      return 0
    fi
    for i in "${items[@]}"; do
      [[ "$ans" == "$i" ]] && { CHOICE="$i"; return 0; }
    done
    echo "${R}Invalid choice.${N}"
  done
}

# ─── discovery ─────────────────────────────────────────────────────────────
domains_for_ip() {
  local ip="$1"
  {
    command -v dig >/dev/null && dig +short -x "$ip" 2>/dev/null
    curl -s --max-time 20 "https://api.hackertarget.com/reverseiplookup/?q=${ip}" 2>/dev/null
  } | tr -d '\r' | sed 's/\.$//' | tr 'A-Z' 'a-z' \
    | grep -E '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$' | sort -u
}

ips_for_domain() {
  local d="$1"
  {
    if command -v dig >/dev/null; then dig +short "$d" A "$d" AAAA 2>/dev/null
    else getent ahosts "$d" 2>/dev/null | awk '{print $1}'; fi
  } | tr -d '\r' | while read -r line; do is_ip "$line" && echo "$line"; done | sort -u
}

# ─── gather targets ────────────────────────────────────────────────────────
if [[ -z "$DOMAIN" && -z "$IP" ]]; then
  [[ $INTERACTIVE -eq 1 ]] || die "No target provided. Use -h for help."
  echo "${B}Enter a domain, an IP, or both (leave one empty to skip it).${N}"
  read -rp "Domain: " d_in; read -rp "IP address: " i_in
  d_in="$(clean_host "$d_in")"; i_in="$(clean_host "$i_in")"
  [[ -z "$d_in" || -n "$(is_domain "$d_in" && echo ok)" ]] || die "Invalid domain: $d_in"
  [[ -z "$i_in" || -n "$(is_ip "$i_in" && echo ok)" ]] || die "Invalid IP: $i_in"
  DOMAIN="$d_in"; IP="$i_in"
  [[ -n "$DOMAIN" || -n "$IP" ]] || die "You must enter a domain or an IP."
fi

[[ -n "$DOMAIN" ]] && TARGETS+=("$DOMAIN")
[[ -n "$IP" ]] && TARGETS+=("$IP")

if [[ -n "$IP" && -z "$DOMAIN" ]]; then
  # Only IP given -> offer to find domains on it
  if [[ $INTERACTIVE -eq 1 ]]; then
    echo
    if confirm "Look up domains registered on $IP and audit one of them?"; then
      echo "${D}Searching (reverse DNS + reverse-IP lookup)...${N}"
      mapfile -t found < <(domains_for_ip "$IP")
      if (( ${#found[@]} == 0 )); then
        echo "${Y}No domains found for $IP.${N}"
      else
        NOTES+=("Domains found on $IP: ${#found[@]}")
        if (( ${#found[@]} == 1 )); then
          echo "Found 1 domain: ${B}${found[0]}${N}"
          confirm "Audit ${found[0]} too?" && CHOICE="${found[0]}" || CHOICE=""
        else
          (( ${#found[@]} > 1 )) && echo "${Y}Note: shared/CDN IPs may list unrelated domains.${N}"
          menu "Found ${#found[@]} domains on $IP — pick one to audit:" "${found[@]}"
        fi
        if [[ -n "$CHOICE" ]]; then
          DOMAIN="$CHOICE"; TARGETS=("$DOMAIN" "$IP")
          NOTES+=("Domain selected for audit: $DOMAIN")
        fi
      fi
    fi
  else
    echo "[i] Non-interactive: skipping domain discovery for $IP." >&2
  fi
elif [[ -n "$DOMAIN" && -z "$IP" ]]; then
  # Only domain given -> offer to find its IP(s)
  if [[ $INTERACTIVE -eq 1 ]]; then
    echo
    if confirm "Resolve the IP address of $DOMAIN and audit it too?"; then
      mapfile -t found < <(ips_for_domain "$DOMAIN")
      if (( ${#found[@]} == 0 )); then
        echo "${Y}Could not resolve $DOMAIN.${N}"
      else
        NOTES+=("IPs resolved for $DOMAIN: ${found[*]}")
        if (( ${#found[@]} == 1 )); then
          echo "Resolved: ${B}${found[0]}${N}"; CHOICE="${found[0]}"
        else
          menu "$DOMAIN resolves to ${#found[@]} IPs — pick one to audit:" "${found[@]}"
        fi
        if [[ -n "$CHOICE" ]]; then
          IP="$CHOICE"; TARGETS+=("$IP")
          NOTES+=("IP selected for audit: $IP")
        fi
      fi
    fi
  else
    echo "[i] Non-interactive: skipping IP resolution for $DOMAIN." >&2
  fi
fi

BASE="${DOMAIN:-$IP}"
[[ -n "$OUTFILE" ]] || OUTFILE="raw/headers/${BASE//:/_}_headers_report.txt"
mkdir -p "$(dirname "$OUTFILE")" || die "Cannot create directory for $OUTFILE"

# ─── report ────────────────────────────────────────────────────────────────
LINE="────────────────────────────────────────────────────────────────────────"
section() { printf '\n%s%s%s\n%s %s%s\n%s%s%s\n' "$C" "$LINE" "$N" "$B" "$1" "$N" "$C" "$LINE" "$N"; }

risk_color() {
  case "$1" in
    Medium) printf '%s' "$R" ;;
    Low-Medium) printf '%s' "$Y" ;;
    *) printf '%s' "$D" ;;
  esac
}

audit_host() {
  local host="$1" url_host="$1" https_hdrs http_hdrs audit_src status location code verdict
  local present=0 missing=0 opts
  [[ "$host" == *:* ]] && url_host="[$host]"
  opts=(-sI --max-time "$TIMEOUT" "${INSECURE[@]}")
  is_ip "$host" && opts+=(-k)   # IP targets rarely match the certificate

  https_hdrs=$(curl "${opts[@]}" "https://$url_host" | tr -d '\r') || true
  http_hdrs=$(curl "${opts[@]}" "http://$url_host" | tr -d '\r') || true

  printf '\n%s▶ TARGET: %s%s\n' "$B" "$host" "$N"

  section "1. HTTPS response headers  (https://$host)"
  if [[ -n "$https_hdrs" ]]; then printf '%s\n' "$https_hdrs" | sed '/^$/d;s/^/  /'
  else printf '  %sNo response%s\n' "$R" "$N"; fi

  section "2. HTTP response headers  (http://$host)"
  if [[ -n "$http_hdrs" ]]; then printf '%s\n' "$http_hdrs" | sed '/^$/d;s/^/  /'
  else printf '  %sNo response%s\n' "$R" "$N"; fi

  section "3. HTTP → HTTPS redirect check"
  if [[ -z "$http_hdrs" ]]; then
    printf '  HTTP not reachable (no response).\n'
  else
    status=$(head -n1 <<<"$http_hdrs")
    location=$(grep -i '^location:' <<<"$http_hdrs" | head -n1)
    code=$(awk 'NR==1{print $2}' <<<"$status")
    case "$code" in
      301|308) verdict="${G}Permanent redirect (good if it points to HTTPS)${N}" ;;
      302|303|307) verdict="${Y}Temporary redirect (prefer 301/308 + HSTS)${N}" ;;
      200) verdict="${R}HTTP served without redirect (no HTTPS enforcement)${N}" ;;
      *) verdict="${Y}Unexpected status $code — review manually${N}" ;;
    esac
    printf '  Status   : %s\n  Location : %s\n  Verdict  : %s\n' "$status" "${location:-<none>}" "$verdict"
  fi

  section "4. Security headers audit"
  if [[ $FOLLOW -eq 1 ]]; then
    audit_src=$(curl -L "${opts[@]}" "https://$url_host" | tr -d '\r') || true
    audit_src=$(awk 'BEGIN{RS="\n\n"; ORS="\n"} NF{last=$0} END{print last}' <<<"$audit_src")
    printf '  %s(following redirects; auditing the final response)%s\n\n' "$D" "$N"
  else
    audit_src="$https_hdrs"
    printf '  %s(auditing the first HTTPS response; use -L to follow redirects)%s\n\n' "$D" "$N"
  fi

  if [[ -z "$audit_src" ]]; then
    printf '  %sNo HTTPS response — cannot audit.%s\n' "$R" "$N"
  else
    local entry name risk impact value
    for entry in "${SECURITY_HEADERS[@]}"; do
      IFS='|' read -r name risk impact <<<"$entry"
      value=$(grep -i "^${name}:" <<<"$audit_src" | head -n1)
      if [[ -n "$value" ]]; then
        printf '  %s✔ PRESENT%s  %s\n' "$G" "$N" "$value"
        present=$((present + 1))
      else
        printf '  %s✘ MISSING%s  %s%-29s%s %s%-16s%s %s\n' \
          "$R" "$N" "$B" "$name" "$N" "$(risk_color "$risk")" "[$risk]" "$N" "$impact"
        missing=$((missing + 1))
      fi
    done
    printf '\n  %s✔ Present: %d%s    %s✘ Missing: %d%s    Total checked: %d\n' \
      "$G" "$present" "$N" "$R" "$missing" "$N" "${#SECURITY_HEADERS[@]}"
  fi
}

report() {
  local t n
  printf '%s╔══════════════════════════════════════════════════════════════════════╗%s\n' "$B" "$N"
  printf '%s║  HTTP SECURITY HEADER REPORT%-41s║%s\n' "$B" "" "$N"
  printf '%s╚══════════════════════════════════════════════════════════════════════╝%s\n' "$B" "$N"
  printf '  Targets : %s\n' "${TARGETS[*]}"
  printf '  Date    : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  for n in "${NOTES[@]+"${NOTES[@]}"}"; do printf '  Note    : %s\n' "$n"; done

  for t in "${TARGETS[@]}"; do audit_host "$t"; done

  section "Done"
  printf '  Report saved to: %s\n\n' "$OUTFILE"
}

tmp=$(mktemp) || die "mktemp failed"
trap 'rm -f "$tmp"' EXIT

report | tee "$tmp"
sed $'s/\x1b\\[[0-9;]*m//g' "$tmp" > "$OUTFILE"
