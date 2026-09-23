#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Checking dependencies..."

PACKAGES=(
    gcc
    binutils
    tor
    pkg-config
    libgpgme-dev
    gpg
)

MISSING=()

for package in "${PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        VERSION=$(dpkg-query -W -f='${Version}' "$package")
        echo "  $package $VERSION [OK]"
    else
        echo "  $package [MISSING]"
        MISSING+=("$package")
    fi
done

echo

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Installing missing dependencies..."

    sudo apt update
    sudo apt install -y "${MISSING[@]}"
else
    echo "All dependencies are already installed."
fi

echo
echo "[1/4] Checking source files..."

mkdir -p "$PROJECT_DIR/app"

BINARY="$PROJECT_DIR/app/GyroJett-OneShot"

if [ ! -f "$BINARY" ] ||
   [ "$PROJECT_DIR/src/main.c" -nt "$BINARY" ] ||
   [ "$PROJECT_DIR/src/crypto.c" -nt "$BINARY" ] ||
   [ "$PROJECT_DIR/src/crypto.h" -nt "$BINARY" ]
then
    echo "Source changed or binary does not exist."
    echo "Compiling GyroJett-OneShot..."

    gcc -std=c17 -Wall -Wextra -O2 -pthread \
        "$PROJECT_DIR/src/main.c" \
        "$PROJECT_DIR/src/crypto.c" \
        $(pkg-config --cflags --libs gpgme) \
        -o "$BINARY"

    echo "Compilation complete."
else
    echo "Binary is already up to date. Skipping compilation."
fi

echo "[2/4] Configuring Tor..."

if grep -qF "ControlPort 9051" /etc/tor/torrc &&
   grep -qF "CookieAuthentication 1" /etc/tor/torrc &&
   grep -qF "HiddenServiceDir /var/lib/tor/gyrojet1s/" /etc/tor/torrc &&
   grep -qF "HiddenServicePort 4242 127.0.0.1:4242" /etc/tor/torrc
then
    echo "GyroJett Tor configuration already exists. Nothing to add."
else
    sudo bash -c 'cat >> /etc/tor/torrc <<EOF

# GyroJett-OneShot
ControlPort 9051
CookieAuthentication 1

HiddenServiceDir /var/lib/tor/gyrojet1s/
HiddenServicePort 4242 127.0.0.1:4242
EOF'

    echo "GyroJett Tor configuration added."
fi

echo "[3/4] Restarting Tor..."

sudo systemctl restart tor@default.service

echo "Waiting for Tor Onion Service..."

for i in {1..30}; do
    if sudo test -f /var/lib/tor/gyrojet1s/hostname; then
        break
    fi

    sleep 1
done

if ! sudo test -f /var/lib/tor/gyrojet1s/hostname; then
    echo "Error: Tor Onion Service hostname was not created."
    exit 1
fi

echo "Tor Onion Service is ready."

sudo install -d -m 755 /var/lib/gyrojet-oneshot

sudo cp \
    /var/lib/tor/gyrojet1s/hostname \
    /var/lib/gyrojet-oneshot/hostname

sudo chown "$USER":"$USER" \
    /var/lib/gyrojet-oneshot/hostname

sudo chmod 644 \
    /var/lib/gyrojet-oneshot/hostname

echo "[4/4] Installing GyroJett-OneShot..."

sudo install -m 755 \
    "$BINARY" \
    /usr/local/bin/gyrojett-oneshot

echo
echo "GyroJett-OneShot installed!"
echo "Binary: /usr/local/bin/gyrojett-oneshot"
