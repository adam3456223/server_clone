#!/bin/bash
# setup_from_public.sh - Pull setup script from public repo and run

set -e

REPO_URL="https://github.com/adam3456223/server_clone.git"
WORK_DIR="/root/server_setup"

echo "=== Pulling setup files from public repo ==="

# Clean existing setup directory
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

# Clone the public repo
cd "$WORK_DIR"
git clone "$REPO_URL" .

# Make scripts executable
chmod +x setup_client.sh obliterate.sh

echo ""
echo "=== Files ready ==="
echo "Directory: $WORK_DIR"
echo ""
echo "Available scripts:"
echo "  - setup_client.sh: Main setup script"
echo "  - obliterate.sh: Complete cleanup script"
echo ""
echo "To run setup, execute:"
echo "cd $WORK_DIR && ./setup_client.sh"
echo ""
echo "Or run now? (y/n)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    ./setup_client.sh
fi
