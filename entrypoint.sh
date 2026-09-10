#!/usr/bin/env bash
# ==============================================================================
# Script:      entrypoint.sh (Wiz SBOM Version Gate)
# Description: Generates a CycloneDX SBOM using WizCLI and gates CI/CD pipelines
#              by evaluating detected package/library versions against custom rules.
#
# Disclaimer:  This is an independent community project and not an officially
#              supported Wiz product or feature. Provided "as-is" under MIT.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCAN_TYPE="dir"
TARGET_PATH="."
SBOM_OUTPUT_FILE="wiz-sbom.json"
RULES_FILE=""
RULE_PKG=""
RULE_OPERATOR=""
RULE_VER=""
KEEP_SBOM=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type) SCAN_TYPE="$2"; shift 2 ;;
        -s|--target) TARGET_PATH="$2"; shift 2 ;;
        -f|--sbom-file) SBOM_OUTPUT_FILE="$2"; shift 2 ;;
        -p|--package) RULE_PKG="$2"; shift 2 ;;
        -o|--operator) RULE_OPERATOR="$2"; shift 2 ;;
        -v|--version) RULE_VER="$2"; shift 2 ;;
        -r|--rules-file) RULES_FILE="$2"; shift 2 ;;
        --keep-sbom) KEEP_SBOM=true; shift ;;
        *) echo -e "${RED}[ERROR] Unknown option: $1${NC}" >&2; exit 2 ;;
    esac
done

cleanup() {
    if [[ "$KEEP_SBOM" == "false" && -f "$SBOM_OUTPUT_FILE" ]]; then
        rm -f "$SBOM_OUTPUT_FILE"
    fi
}
trap cleanup EXIT

echo -e "${BLUE}==> [1/3] Generating CycloneDX SBOM via WizCLI...${NC}"
echo "    Scan Type : $SCAN_TYPE"
echo "    Target    : $TARGET_PATH"

if [[ "$SCAN_TYPE" == "dir" ]]; then
    wizcli scan dir "$TARGET_PATH" \
        --sbom-format=cyclonedx-json \
        --sbom-output-file="$SBOM_OUTPUT_FILE" || true
elif [[ "$SCAN_TYPE" == "container-image" ]]; then
    wizcli scan container-image "$TARGET_PATH" \
        --sbom-format=cyclonedx-json \
        --sbom-output-file="$SBOM_OUTPUT_FILE" || true
else
    echo -e "${RED}[ERROR] Invalid scan type: $SCAN_TYPE. Choose 'dir' or 'container-image'.${NC}" >&2
    exit 2
fi

if [[ ! -s "$SBOM_OUTPUT_FILE" ]]; then
    echo -e "${RED}[ERROR] SBOM file missing or empty: $SBOM_OUTPUT_FILE${NC}" >&2
    exit 2
fi

compare_versions() {
    local actual="$1" op="$2" target="$3"
    if [[ "$actual" == "$target" ]]; then
        case "$op" in eq|le|ge) return 0 ;; *) return 1 ;; esac
    fi
    local lowest
    lowest=$(printf '%s\n%s\n' "$actual" "$target" | sort -V | head -n1)
    case "$op" in
        lt) [[ "$lowest" == "$actual" && "$actual" != "$target" ]] && return 0 || return 1 ;;
        le) [[ "$lowest" == "$actual" ]] && return 0 || return 1 ;;
        gt) [[ "$lowest" == "$target" && "$actual" != "$target" ]] && return 0 || return 1 ;;
        ge) [[ "$lowest" == "$target" ]] && return 0 || return 1 ;;
        eq) [[ "$actual" == "$target" ]] && return 0 || return 1 ;;
        ne) [[ "$actual" != "$target" ]] && return 0 || return 1 ;;
        *) echo -e "${RED}[ERROR] Invalid operator: $op${NC}" >&2; return 1 ;;
    esac
}

echo -e "${BLUE}==> [2/3] Evaluating packages against version rules...${NC}"

declare -a RULES=()
if [[ -n "$RULES_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue
        RULES+=("$line")
    done < "$RULES_FILE"
else
    RULES+=("${RULE_PKG}:${RULE_OPERATOR}:${RULE_VER}")
fi

VIOLATIONS_FOUND=0

for rule in "${RULES[@]}"; do
    IFS=":" read -r target_pkg target_op target_ver <<< "$rule"
    target_pkg=$(echo "$target_pkg" | xargs)
    target_op=$(echo "$target_op" | xargs)
    target_ver=$(echo "$target_ver" | xargs)

    echo -e "\n${YELLOW}Rule check: '${target_pkg}' must NOT be (${target_op} ${target_ver})${NC}"

    FOUND_VERSIONS=$(jq -r --arg pkg "$target_pkg" '
        [ .. | objects | select(.name? == $pkg) | .version? ] | unique | .[]
    ' "$SBOM_OUTPUT_FILE" 2>/dev/null || true)

    if [[ -z "$FOUND_VERSIONS" ]]; then
        echo -e "  └── Status: ${GREEN}PASS${NC} (Package not detected in SBOM)"
        continue
    fi

    while IFS= read -r ver; do
        if [[ -z "$ver" ]]; then continue; fi
        if compare_versions "$ver" "$target_op" "$target_ver"; then
            echo -e "  └── ${RED}[FAIL] Violation!${NC} Found ${target_pkg}@${ver} (${target_op} ${target_ver})"
            VIOLATIONS_FOUND=$((VIOLATIONS_FOUND + 1))
        else
            echo -e "  └── ${GREEN}[OK] Allowed:${NC} Found ${target_pkg}@${ver} (Complies with policy)"
        fi
    done <<< "$FOUND_VERSIONS"
done

echo -e "\n${BLUE}==> [3/3] Gate Verdict${NC}"
if [[ $VIOLATIONS_FOUND -gt 0 ]]; then
    echo -e "${RED}FAILED: $VIOLATIONS_FOUND package violation(s) detected. Pipeline blocked.${NC}"
    exit 1
fi

echo -e "${GREEN}PASSED: All detected library versions satisfy policy.${NC}"
exit 0
