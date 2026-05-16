#!/bin/bash
# ============================================================
# check_user_services.sh
# Uses NetExec (nxc) to check which services a user can log in to
# ============================================================

# ---------- CONFIG ----------
TARGET=""
USERNAME=""
PASSWORD=""
DOMAIN=""
HASH=""

# ---------- USAGE ----------
usage() {
    echo "Usage: $0 -t <target> -u <username> [-p <password>] [-H <hash>] [-d <domain>]"
    echo ""
    echo "  -t  Target IP or range (e.g. 192.168.1.10 or 192.168.1.0/24)"
    echo "  -u  Username"
    echo "  -p  Password"
    echo "  -H  NTLM hash (instead of password)"
    echo "  -d  Domain (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.10 -u jsmith -p 'Password123' -d corp.local"
    echo "  $0 -t 192.168.1.0/24 -u jsmith -H aad3b435b51404eeaad3b435b51404ee:abc123..."
    exit 1
}

# ---------- PARSE ARGS ----------
while getopts "t:u:p:H:d:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) HASH="$OPTARG" ;;
        d) DOMAIN="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ---------- VALIDATE ----------
if [[ -z "$TARGET" || -z "$USERNAME" ]]; then
    echo "[!] Target and username are required."
    usage
fi

if [[ -z "$PASSWORD" && -z "$HASH" ]]; then
    echo "[!] Either a password (-p) or NTLM hash (-H) is required."
    usage
fi

# ---------- BUILD CREDENTIAL ARGS ----------
CRED_ARGS="-u '$USERNAME'"
if [[ -n "$DOMAIN" ]]; then
    CRED_ARGS="$CRED_ARGS -d '$DOMAIN'"
fi
if [[ -n "$HASH" ]]; then
    CRED_ARGS="$CRED_ARGS -H '$HASH'"
else
    CRED_ARGS="$CRED_ARGS -p '$PASSWORD'"
fi

# ---------- SERVICES TO CHECK ----------
SERVICES=("smb" "ssh" "winrm" "rdp" "ldap" "mssql" "ftp" "wmi")

# ---------- RUN CHECKS ----------
echo ""
echo "=============================================="
echo "  NXC Service Login Check"
echo "  Target   : $TARGET"
echo "  User     : ${DOMAIN:+$DOMAIN\\}$USERNAME"
echo "=============================================="
echo ""

for SERVICE in "${SERVICES[@]}"; do
    echo -n "[*] Checking $SERVICE ... "

    CMD="nxc $SERVICE $TARGET $CRED_ARGS 2>/dev/null"
    OUTPUT=$(eval "$CMD")

    if echo "$OUTPUT" | grep -q "\[+\]"; then
        echo "✅ SUCCESS"
        echo "$OUTPUT" | grep "\[+\]" | sed 's/^/    /'
    elif echo "$OUTPUT" | grep -q "\[-\]"; then
        echo "❌ FAILED"
    elif echo "$OUTPUT" | grep -q "Error\|error\|refused\|timeout"; then
        echo "⚠️  UNREACHABLE / ERROR"
    else
        echo "⚠️  NO RESPONSE"
    fi
done

echo ""
echo "=============================================="
echo "  Done."
echo "=============================================="
