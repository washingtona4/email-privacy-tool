#!/usr/bin/env bash
set -euo pipefail

read -rp "Which provider? (gmail/outlook/protonmail/tutanota): " PROVIDER
read -rp "Which phase? (account_creation/idle/active_usage/tracker_test): " PHASE

OUTPUT_DIR="output/$PROVIDER/$PHASE"
mkdir -p "$OUTPUT_DIR"

echo "Starting capture for $PROVIDER - $PHASE"
echo "Configure your browser proxy to 127.0.0.1:8080 if not already done"
echo "Press ENTER when ready..."
read -r

OUTPUT_DIR=$OUTPUT_DIR mitmdump -s capture/mitmproxy_script.py --listen-port 8080 --save-stream-file "$OUTPUT_DIR/capture.mitm"
