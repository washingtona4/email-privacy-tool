#!/usr/bin/env bash
set -euo pipefail

# Check Python 3.9+
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "ERROR: python3 not found. Please install Python 3.9+."
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(sys.version_info.minor if sys.version_info.major == 3 else 0)")
if [ "$PY_VERSION" -lt 9 ]; then
    echo "ERROR: Python 3.9+ required. Found: $($PYTHON --version)"
    exit 1
fi

echo "Python version OK: $($PYTHON --version)"

# Install system dependencies
sudo apt-get install -y wireshark tshark python3-pip

# Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# Create output directory structure
for PROVIDER in gmail outlook protonmail tutanota; do
    for PHASE in account_creation idle active_usage tracker_test; do
        mkdir -p "output/$PROVIDER/$PHASE"
    done
done

# Create config directories
mkdir -p config/tracker_lists

# Download EasyPrivacy list
echo "Downloading EasyPrivacy list..."
curl -fsSL "https://easylist.to/easylist/easyprivacy.txt" -o "config/tracker_lists/easyprivacy.txt"

# Download Disconnect.me tracker database
echo "Downloading Disconnect.me tracker database..."
curl -fsSL "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json" -o "config/tracker_lists/disconnect.json"

echo "Setup complete"
