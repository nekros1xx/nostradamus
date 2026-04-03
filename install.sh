#!/bin/bash
# Nostradamus installer - Linux/macOS
# Usage: ./install.sh [--uninstall]

set -e

INSTALL_DIR="$HOME/.nostradamus"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$1" = "--uninstall" ]; then
    echo -e "${YELLOW}Uninstalling nostradamus...${NC}"
    rm -f /usr/local/bin/nostradamus 2>/dev/null || rm -f "$HOME/.local/bin/nostradamus" 2>/dev/null
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}Uninstalled.${NC}"
    exit 0
fi

echo -e "${YELLOW}"
echo " _  _         _               _"
echo '| \| |___ ___| |_ _ _ __ _ __| |__ _ _ __ _  _ ___'
echo "| .\` / _ (_-<|  _| '_/ _\` / _\` / _\` | '  \ || (_-<"
echo '|_|\_\___/__/ \__|_| \__,_\__,_\__,_|_|_|_\_,_/__/'
echo -e "${NC}"
echo "Installing nostradamus..."
echo ""

# Check Python
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(sys.version_info[0])")
if [ "$PY_VERSION" -lt 3 ]; then
    echo -e "${RED}Error: Python 3 is required. Found Python $PY_VERSION.${NC}"
    exit 1
fi

# Copy files to install dir
echo "[1/3] Copying files to $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
cp -r "$SCRIPT_DIR" "$INSTALL_DIR"

# Create launcher script
echo "[2/3] Creating launcher..."

LAUNCHER='#!/bin/bash
exec PYTHON_PLACEHOLDER "INSTALL_DIR_PLACEHOLDER/nostradamus.py" "$@"'

LAUNCHER=$(echo "$LAUNCHER" | sed "s|PYTHON_PLACEHOLDER|$PYTHON|g" | sed "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g")

# Try /usr/local/bin first, fall back to ~/.local/bin
if [ -w /usr/local/bin ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
fi

echo "$LAUNCHER" > "$BIN_DIR/nostradamus"
chmod +x "$BIN_DIR/nostradamus"

# Verify PATH
echo "[3/3] Verifying installation..."

if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    SHELL_RC=""
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    fi

    if [ -n "$SHELL_RC" ]; then
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
        echo -e "${YELLOW}Added $BIN_DIR to PATH in $SHELL_RC${NC}"
        echo -e "${YELLOW}Run: source $SHELL_RC${NC}"
    else
        echo -e "${YELLOW}Add this to your shell config:${NC}"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
    fi
fi

echo ""
echo -e "${GREEN}Installed successfully!${NC}"
echo -e "  Location: $INSTALL_DIR"
echo -e "  Command:  ${GREEN}nostradamus${NC}"
echo ""
echo "Try it:"
echo "  nostradamus --version"
echo "  nostradamus -u \"http://target.com/page?id=1\" --batch --dbs"
