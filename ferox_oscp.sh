#!/bin/bash
# ferox_oscp.sh - tuned for OSCP boxes

TARGET=$1
OUTPUT_DIR="./ferox_$(echo $TARGET | sed 's|[/:.]|_|g')"

mkdir -p $OUTPUT_DIR

# --- Phase 1: Fast initial scan ---
echo "[1/3] Fast initial scan..."
feroxbuster \
    -u $TARGET \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -x php,html,txt \
    -d 2 \
    -t 100 \
    -o "$OUTPUT_DIR/fast_scan.txt" \
    -C 404 \
    --quiet

# --- Phase 2: Deep recursive scan ---
echo "[2/3] Deep recursive scan..."
feroxbuster \
    -u $TARGET \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,html,txt,asp,aspx,jsp,bak,zip,conf,log \
    -d 4 \
    -t 50 \
    --auto-tune \
    -o "$OUTPUT_DIR/deep_scan.txt" \
    -C 404 \
    --redirects

# --- Phase 3: Scan any discovered dirs with bigger wordlist ---
echo "[3/3] Targeted scans on interesting findings..."
grep " 200 \| 301 \| 302 " "$OUTPUT_DIR/fast_scan.txt" | awk '{print $NF}' | while read url; do
    echo "[*] Targeting: $url"
    feroxbuster \
        -u $url \
        -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
        -x php,txt,bak,zip,conf \
        -d 2 \
        -t 50 \
        -o "$OUTPUT_DIR/targeted_$(echo $url | sed 's|[/:.]|_|g').txt" \
        -C 404 \
        --quiet
done

echo ""
echo "[+] All scans complete!"
echo ""
echo "=== FINAL SUMMARY ==="
echo "Interesting files found:"
grep -h " 200 " $OUTPUT_DIR/*.txt | awk '{print $NF}' | sort -u