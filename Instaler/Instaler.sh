#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Instalando dependências..."
sudo apt install -y gcc binutils tor pkg-config libgpgme-dev gpg

echo "[1/4] Compilando GyroJett-OneShot..."

mkdir -p "$PROJECT_DIR/app/"

gcc -std=c17 -Wall -Wextra -O2 -pthread \
    "$PROJECT_DIR/src/main.c" \
    "$PROJECT_DIR/src/crypto.c" \
    $(pkg-config --cflags --libs gpgme) \
    -o "$PROJECT_DIR/app/GyroJett-OneShot"

echo "[2/4] Configurando Tor..."

sudo bash -c 'cat > /etc/tor/torrc <<EOF
ControlPort 9051
CookieAuthentication 1

HiddenServiceDir /var/lib/tor/gyrojet1s/
HiddenServicePort 4242 127.0.0.1:4242
EOF'

echo "[3/4] Reiniciando Tor..."

sudo systemctl restart tor@default.service

echo "[4/4] Instalando GyroJett-OneShot..."

sudo install -m 755 \
    "$PROJECT_DIR/app/GyroJett-OneShot" \
    /usr/local/bin/gyrojett-oneshot

echo
echo "GyroJett instalado!"
echo "Binário: /usr/local/bin/gyrojett-oneshot"
