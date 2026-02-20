#!/bin/bash
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -q -r requirements.txt
else
    source venv/bin/activate
fi

if [ "$EUID" -ne 0 ]; then 
    echo "Warning: Not running as root. Some checks will fail."
    echo "For full audit: sudo venv/bin/python main.py audit linux"
    echo ""
fi

python main.py audit linux
