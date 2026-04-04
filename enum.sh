#!/bin/bash

# =============================================================
#  Steve's Lazy Enumeration Script
#  Usage: ./enum.sh <target_ip> [output_dir]
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() {
    echo -e "${CYAN}"
    echo "  ███████╗███╗   ██╗██╗   ██╗███╗   ███╗"
    echo "  ██╔════╝████╗  ██║██║   ██║████╗ ████║"
    echo "  █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║"
    echo "  ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║"
    echo "  ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║"
    echo "  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"
    echo -e "  Steve's Lazy Enumeration Script${NC}"
    echo ""
}

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 <target_ip> [output_dir]"
    echo ""
    echo "  target_ip   - IP address of the target"
    echo "  output_dir  - Directory to store results (default: ./enum_<ip>)"
    echo ""
    echo "Examples:"
    echo "  $0 10.10.10.1"
    echo "  $0 192.168.1.100 /tmp/target_results"
    exit 1
}

check_deps() {
    echo -e "${CYAN}[*] Checking dependencies...${NC}"
    for cmd in nmap; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}[-] '$cmd' not found. Please install it.${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}[+] All dependencies found.${NC}"
}

run_scan() {
    local name="$1"
    local description="$2"
    local outfile="$3"
    shift 3
    local cmd=("$@")

    echo ""
    echo -e "${YELLOW}[*] Running: ${description}${NC}"
    echo -e "    ${cmd[*]}"
    echo -e "    Output: ${outfile}"

    "${cmd[@]}" -oN "${outfile}.nmap" -oG "${outfile}.gnmap" -oX "${outfile}.xml" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] ${name} complete.${NC}"
    else
        echo -e "${RED}[-] ${name} encountered an error.${NC}"
    fi
}

# ---- Main ----

banner

if [ -z "$1" ]; then
    usage
fi

TARGET="$1"
OUTPUT_DIR="${2:-./enum_${TARGET}}"

# Validate IP (basic check)
if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo -e "${RED}[-] Invalid IP address: ${TARGET}${NC}"
    exit 1
fi

check_deps

mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}[+] Output directory: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}[+] Target: ${TARGET}${NC}"
echo -e "${GREEN}[+] Start time: $(date)${NC}"

LOG_FILE="${OUTPUT_DIR}/enum.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ============================================================
# STAGE 1 — Fast TCP ping sweep / host check
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 1: Host Discovery${NC}"
echo -e "${CYAN}========================================${NC}"

run_scan \
    "Host Discovery" \
    "ICMP + TCP SYN host check" \
    "${OUTPUT_DIR}/01_host_discovery" \
    nmap -sn -PE -PS22,80,443 -PA80 --reason "$TARGET"

# ============================================================
# STAGE 2 — Fast TCP top-ports scan
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 2: Quick TCP Top 1000 Ports${NC}"
echo -e "${CYAN}========================================${NC}"

run_scan \
    "Quick TCP Scan" \
    "Top 1000 TCP ports (no version, no scripts)" \
    "${OUTPUT_DIR}/02_tcp_quick" \
    nmap -sS -T4 --open --reason "$TARGET"

# ============================================================
# STAGE 3 — Full TCP port scan (all 65535)
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 3: Full TCP Port Scan (all ports)${NC}"
echo -e "${CYAN}========================================${NC}"

run_scan \
    "Full TCP Scan" \
    "All 65535 TCP ports" \
    "${OUTPUT_DIR}/03_tcp_full" \
    nmap -sS -T4 -p- --open --reason "$TARGET"

# Extract open ports for targeted scan
OPEN_PORTS=$(grep "open" "${OUTPUT_DIR}/03_tcp_full.gnmap" 2>/dev/null \
    | grep -oP '\d+/open' \
    | cut -d'/' -f1 \
    | sort -un \
    | tr '\n' ',' \
    | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo -e "${YELLOW}[!] No open ports found in full scan. Falling back to common OSCP ports.${NC}"
    # Common OSCP/CTF ports as fallback
    OPEN_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,512,513,514,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017"
fi

echo ""
echo -e "${GREEN}[+] Open ports identified: ${OPEN_PORTS}${NC}"

# ============================================================
# STAGE 4 — Service version + default scripts on open ports
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 4: Service & Version Detection${NC}"
echo -e "${CYAN}========================================${NC}"

run_scan \
    "Version + Scripts" \
    "Service versions + default NSE scripts on open ports" \
    "${OUTPUT_DIR}/04_tcp_versions" \
    nmap -sS -sV -sC -T4 -p "$OPEN_PORTS" --open --reason "$TARGET"

# ============================================================
# STAGE 5 — UDP top-20 common ports
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 5: UDP Common Ports${NC}"
echo -e "${CYAN}========================================${NC}"

COMMON_UDP="53,67,68,69,111,123,137,138,139,161,162,500,514,520,623,1194,1900,4500,5353,49152"

run_scan \
    "UDP Scan" \
    "Top UDP ports (requires root)" \
    "${OUTPUT_DIR}/05_udp_common" \
    nmap -sU -T4 -p "$COMMON_UDP" --open --reason "$TARGET"

# ============================================================
# STAGE 6 — Vuln scripts on open ports
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 6: Vulnerability Scripts${NC}"
echo -e "${CYAN}========================================${NC}"

run_scan \
    "Vuln Scan" \
    "NSE vuln category scripts on open ports" \
    "${OUTPUT_DIR}/06_vuln_scripts" \
    nmap -sV --script vuln -T4 -p "$OPEN_PORTS" "$TARGET"

# ============================================================
# STAGE 7 — HTTP-specific enumeration (if 80/443/8080 open)
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 7: HTTP Enumeration${NC}"
echo -e "${CYAN}========================================${NC}"

for PORT in 80 443 8080 8443 8888; do
    if echo "$OPEN_PORTS" | grep -qw "$PORT"; then
        echo -e "${YELLOW}[*] HTTP service detected on port ${PORT}${NC}"
        run_scan \
            "HTTP Enum port ${PORT}" \
            "http-enum + http-headers + http-methods on port ${PORT}" \
            "${OUTPUT_DIR}/07_http_port${PORT}" \
            nmap -sV --script "http-enum,http-headers,http-methods,http-title,http-robots.txt" \
            -p "$PORT" -T4 "$TARGET"
    fi
done

# ============================================================
# STAGE 8 — SMB enumeration (if 139/445 open)
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  STAGE 8: SMB Enumeration${NC}"
echo -e "${CYAN}========================================${NC}"

if echo "$OPEN_PORTS" | grep -qE '(^|,)(139|445)(,|$)'; then
    echo -e "${YELLOW}[*] SMB detected. Running SMB scripts...${NC}"
    run_scan \
        "SMB Enum" \
        "SMB share/version/vuln scripts" \
        "${OUTPUT_DIR}/08_smb" \
        nmap --script "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067" \
        -p 139,445 -T4 "$TARGET"
else
    echo -e "${YELLOW}[!] SMB ports (139/445) not open. Skipping.${NC}"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  SUMMARY${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}[+] Target:       ${TARGET}${NC}"
echo -e "${GREEN}[+] Output dir:   ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}[+] Open ports:   ${OPEN_PORTS}${NC}"
echo -e "${GREEN}[+] End time:     $(date)${NC}"
echo ""
echo -e "${YELLOW}[*] Next steps to consider:${NC}"
echo "    - gobuster/feroxbuster for HTTP directories"
echo "    - enum4linux / crackmapexec for SMB/RPC"
echo "    - nikto for web app scanning"
echo "    - searchsploit on identified versions"
echo "    - hydra for login brute-forcing"
echo ""
echo -e "${GREEN}[+] All results saved to: ${OUTPUT_DIR}/${NC}"
