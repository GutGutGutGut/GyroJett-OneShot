#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

BINARY_NAME="GyroJett-OneShot2"

TORRC="/etc/tor/torrc"
TOR_SERVICE="[tor@default.service](mailto:tor@default.service)"

echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃    GyroJett-OneShot2 Installer    ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo

# --------------------------------------------------

# Root / sudo

# --------------------------------------------------

if ! command -v sudo >/dev/null 2>&1; then
echo "Error: sudo is not installed."
exit 1
fi

if ! sudo -v; then
echo "Error: sudo authentication failed."
exit 1
fi

# --------------------------------------------------

# Dependencies

# --------------------------------------------------

echo "Checking dependencies..."
echo

PACKAGES=(
gcc
binutils
cmake
ninja-build
tor
libssl-dev
libxeddsa-dev
)

MISSING=()

for package in "${PACKAGES[@]}"; do

if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
    VERSION="$(dpkg-query -W -f='${Version}' "$package")"

    echo "  $package $VERSION [OK]"

else

    echo "  $package [MISSING]"
    MISSING+=("$package")

fi

done

echo

if [ "${#MISSING[@]}" -gt 0 ]; then

echo "Installing missing dependencies..."
echo

sudo apt update
sudo apt install "${MISSING[@]}"

else

echo "All dependencies are already installed."

fi

# --------------------------------------------------

# Build

# --------------------------------------------------

echo
echo "[1/5] Configuring build..."
echo

BUILD_DIR="$PROJECT_DIR/build"

cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -G Ninja

echo
echo "[2/5] Building $BINARY_NAME..."
echo

cmake --build "$BUILD_DIR"

BINARY="$BUILD_DIR/$BINARY_NAME"

if [ ! -x "$BINARY" ]; then

echo
echo "Error: $BINARY_NAME binary was not created."
exit 1

fi

echo
echo "Build completed successfully."
echo

# --------------------------------------------------

# Tor configuration

# --------------------------------------------------

echo "[3/5] Configuring Tor..."
echo

if [ ! -f "$TORRC" ]; then

echo "Error: Tor configuration file was not found:"
echo "  $TORRC"

exit 1

fi

# Backup torrc before modifying it.

BACKUP="$TORRC.gyrojett-backup"

if [ ! -f "$BACKUP" ]; then

echo "Creating Tor configuration backup..."

sudo cp "$TORRC" "$BACKUP"

fi

# ControlPort

if sudo grep -qE '^[[:space:]]*ControlPort[[:space:]]+9051([[:space:]]*)$' "$TORRC"; then


echo "ControlPort 9051 already configured."

else

echo "Adding ControlPort 9051..."

printf '\n# GyroJett-OneShot2\nControlPort 9051\n' |
    sudo tee -a "$TORRC" >/dev/null

fi

# CookieAuthentication

if sudo grep -qE '^[[:space:]]*CookieAuthentication[[:space:]]+1([[:space:]]*)$' "$TORRC"; then

echo "CookieAuthentication 1 already configured."

else

echo "Adding CookieAuthentication 1..."

printf 'CookieAuthentication 1\n' |
    sudo tee -a "$TORRC" >/dev/null

fi

echo
echo "Checking Tor configuration..."

if ! sudo tor --verify-config >/dev/null 2>&1; then

echo
echo "Error: Tor configuration is invalid."
echo
echo "Restoring previous configuration..."

if [ -f "$BACKUP" ]; then
    sudo cp "$BACKUP" "$TORRC"
fi

exit 1

fi

echo "Tor configuration is valid."

# --------------------------------------------------

# Restart Tor

# --------------------------------------------------

echo
echo "Restarting Tor..."

sudo systemctl restart "$TOR_SERVICE"

echo
echo "Waiting for Tor ControlPort 9051..."

TOR_READY=0

for _ in {1..30}; do

if ss -lnt 2>/dev/null |
    grep -qE '127\.0\.0\.1:9051[[:space:]]'; then

    TOR_READY=1
    break

fi

sleep 1

done

if [ "$TOR_READY" -ne 1 ]; then

echo
echo "Error: Tor ControlPort 9051 is not available."
echo

echo "Tor status:"
sudo systemctl status "$TOR_SERVICE" --no-pager || true
echo
echo "Recent Tor log:"
sudo journalctl -u "$TOR_SERVICE" -n 50 --no-pager || true

exit 1

fi

echo "Tor ControlPort is ready."

# --------------------------------------------------

# User permissions

# --------------------------------------------------

echo
echo "[4/5] Configuring user permissions..."
echo

if id -nG "$USER" |
tr ' ' '\n' |
grep -qx "debian-tor"; then

echo "User $USER is already in the debian-tor group."

else

echo "Adding $USER to the debian-tor group..."

sudo usermod -aG debian-tor "$USER"

echo
echo "User $USER was added to the debian-tor group."
echo
echo "You must log out and log back in before"
echo "running GyroJett-OneShot2."

fi

# --------------------------------------------------

# Debian package

# --------------------------------------------------

echo
echo "[5/5] Creating Debian package..."
echo

rm -f "$PROJECT_DIR"/gyrojett-oneshot_*.deb

cpack
--config "$BUILD_DIR/CPackConfig.cmake"

DEB_PACKAGE="$(
find "$PROJECT_DIR" -maxdepth 1 -type f -name 'gyrojett-oneshot_*.deb' -print -quit)"

if [ -z "$DEB_PACKAGE" ]; then

echo
echo "Error: Debian package was not created."
exit 1

fi

echo
echo "Debian package created:"
echo "  $DEB_PACKAGE"

# --------------------------------------------------

# Install Debian package

# --------------------------------------------------

echo
echo "Installing Debian package..."

sudo apt install -y "$DEB_PACKAGE"

echo
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃    GyroJett-OneShot2 Installed!    ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo

echo "Package:"
echo "  $DEB_PACKAGE"

echo
echo "Run with:"
echo "  gyrojett-oneshot2"

echo

if ! id -nG "$USER" |
tr ' ' '\n' |
grep -qx "debian-tor"; then

echo "Important:"
echo "  Log out and log back in so the"
echo "  debian-tor group becomes active."

echo

fi

echo "Installation completed successfully."
echo
