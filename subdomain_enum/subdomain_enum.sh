#!/usr/bin/env bash
# Subdomain enumeration for a domain via certificate transparency logs (crt.sh).
# Core: curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u
# Usage: ./subdomain_enum.sh [domain] [output_dir]      (see --help)
set -u

usage() {
  cat <<'EOF'
subdomain_enum.sh - Subdomain enumeration for a domain (passive, crt.sh).

USAGE
  ./subdomain_enum.sh [options] [target] [output_dir]

ARGUMENTS
  target       Domain name (example.com). A pasted URL is cleaned automatically.
               If omitted, the script asks for the domain (the TARGET
               environment variable is also honoured).
  output_dir   Folder to save results in. If omitted, the script asks for the
               folder and a filename; pressing Enter on both uses the defaults
               (raw and subdomains.txt).

OPTIONS
  -h, --help   Show this help and exit.

WHAT IT DOES
  Queries the certificate transparency search at crt.sh for every certificate
  issued to *.<domain>, then cleans the result: wildcards (*.) removed, names
  lower-cased, entries outside the target domain dropped, duplicates removed.
  Failed or empty crt.sh responses are retried (crt.sh is often overloaded).
  This is passive: nothing is sent to the target itself. It only finds names
  that appeared on a public certificate, so it will not list every subdomain.

SCREEN OUTPUT
  A report with the unique subdomains and a summary line. Colours are used
  only on a terminal; set NO_COLOR=1 to disable them.

OUTPUT FILES (in the output folder)
  <filename>        One subdomain per line, sorted (default: subdomains.txt)
  report.txt        The same readable report shown on screen, without colours
  crtsh_raw.json    Raw crt.sh response

EXAMPLES
  ./subdomain_enum.sh                          # interactive
  ./subdomain_enum.sh example.com              # asks only where to save
  ./subdomain_enum.sh example.com raw          # no prompts at all
  TARGET=example.com ./subdomain_enum.sh

Requires: curl, jq, awk. Only run against targets you are authorized to test.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -*) echo "Unknown option: $1 (see --help)" >&2; exit 1 ;;
esac

TARGET="${1:-${TARGET:-}}"
OUT="${2:-raw}"
REPORT_WIDTH=64
MAX_ATTEMPTS=4
CURL_TIMEOUT=60

for bin in curl jq awk; do
  command -v "$bin" >/dev/null || { echo "Missing dependency: $bin" >&2; exit 1; }
done

if [[ -z "$TARGET" ]]; then
  read -rp "Target domain: " TARGET
fi
# Normalise: drop scheme, path, port and whitespace; lower-case
TARGET="${TARGET#*://}"; TARGET="${TARGET%%/*}"; TARGET="${TARGET%%:*}"
TARGET="${TARGET//[[:space:]]/}"; TARGET="${TARGET,,}"
if [[ -z "$TARGET" ]]; then
  echo "No target given." >&2
  exit 1
fi
if [[ ! "$TARGET" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
  echo "Error: '$TARGET' is not a valid domain name (e.g. example.com)." >&2
  exit 1
fi

# Ask where to save (Enter = defaults: raw and subdomains.txt); skipped if output_dir was passed as an argument
RESULT_NAME="subdomains.txt"
if [[ -z "${2:-}" ]]; then
  read -rp "Save output to which folder? [${OUT}]: " ans_dir || ans_dir=""
  read -rp "Output filename? [${RESULT_NAME}]: " ans_name || ans_name=""
  [[ -n "$ans_dir" ]] && OUT="${ans_dir/#\~/$HOME}"
  [[ -n "$ans_name" ]] && RESULT_NAME="${ans_name##*/}"
fi

# ---------------------------------------------------------------- colours
set_colors() {   # $1 = on|off
  if [[ "$1" == on ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; YEL=$'\e[33m'; GRN=$'\e[32m'; CYN=$'\e[36m'; RST=$'\e[0m'
  else
    BOLD=""; DIM=""; YEL=""; GRN=""; CYN=""; RST=""
  fi
}

progress() {   # live status line, only on a terminal
  [[ -t 1 ]] && printf '\r\e[K  %s…' "$1"
  return 0
}

# ---------------------------------------------------------------- collection
# Fetch crt.sh JSON with retries. Returns 0 on valid JSON, 1 otherwise.
fetch_crtsh() {
  local attempt
  for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
    progress "querying crt.sh for %.$TARGET (attempt $attempt/$MAX_ATTEMPTS)"
    if curl -s --max-time "$CURL_TIMEOUT" "https://crt.sh/?q=%25.${TARGET}&output=json" \
         -o "$RAW_JSON" && jq -e 'type == "array"' "$RAW_JSON" >/dev/null 2>&1; then
      return 0
    fi
    [[ $attempt -lt $MAX_ATTEMPTS ]] && sleep $((attempt * 2))
  done
  return 1
}

# name_value may hold several names separated by newlines (and e-mail SANs)
extract_subdomains() {
  jq -r '.[].name_value' "$RAW_JSON" \
    | sed 's/\*\.//' \
    | tr 'A-Z' 'a-z' \
    | awk -v d="$TARGET" '$0 == d || (length($0) > length(d) && substr($0, length($0) - length(d)) == "." d)' \
    | sort -u
}

# ---------------------------------------------------------------- rendering
rule() {   # $1 = character, $2 = width (multibyte-safe, no tr)
  local c="${1:-─}" w="${2:-$REPORT_WIDTH}" s="" i
  for ((i = 0; i < w; i++)); do s+="$c"; done
  printf '%s\n' "$s"
}

render_report() {   # reads $RESULT; colours follow current set_colors state
  local total
  total=$(wc -l < "$RESULT")

  echo
  printf '%s' "$CYN$BOLD"; rule '━'; printf '%s' "$RST"
  printf '  %sSUBDOMAIN ENUMERATION REPORT%s\n' "$BOLD" "$RST"
  printf '  %sTarget%s  %s\n' "$DIM" "$RST" "$TARGET"
  printf '  %sSource%s  crt.sh (certificate transparency)\n' "$DIM" "$RST"
  printf '  %sDate%s    %s\n' "$DIM" "$RST" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  printf '%s' "$CYN$BOLD"; rule '━'; printf '%s' "$RST"

  if (( total == 0 )); then
    printf '\n  %sNo subdomains found.%s\n' "$YEL" "$RST"
  else
    printf '\n%s%s ▌ SUBDOMAINS%s %s%d unique%s\n' "$BOLD" "$GRN" "$RST" "$DIM" "$total" "$RST"
    printf '%s  %s%s\n' "$DIM" "$(rule '─' $((REPORT_WIDTH - 4)))" "$RST"
    awk -v w="${#total}" -v D="$DIM" -v R="$RST" '{ printf "   %s%*d%s  %s\n", D, w, NR, R, $0 }' "$RESULT"
  fi

  printf '\n  %sTotal%s %s%d%s\n' "$DIM" "$RST" "$BOLD" "$total" "$RST"
  printf '\n%s' "$CYN"; rule '━'; printf '%s' "$RST"
}

# ---------------------------------------------------------------- main
mkdir -p "$OUT" || { echo "Cannot create $OUT" >&2; exit 1; }
RESULT="$OUT/$RESULT_NAME"
RAW_JSON="$OUT/crtsh_raw.json"

if ! fetch_crtsh; then
  [[ -t 1 ]] && printf '\r\e[K'
  echo "Error: crt.sh did not return valid data after $MAX_ATTEMPTS attempts (service busy or unreachable). Try again later." >&2
  exit 1
fi

progress "processing results"
extract_subdomains > "$RESULT"
[[ -t 1 ]] && printf '\r\e[K'

set_colors off
render_report > "$OUT/report.txt"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then set_colors on; fi
render_report

printf '  Saved to %s/\n    %s   one subdomain per line\n    report.txt   readable report\n    crtsh_raw.json   raw crt.sh response\n\n' \
  "$OUT" "$RESULT_NAME"
