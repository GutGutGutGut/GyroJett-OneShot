#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "#####################################"
echo "#    GyroJett-OneShot2 Installer    #"
echo "#####################################"
echo

echo "Checking dependencies..."
echo

PACKAGES=(
gcc
binutils
cmake
ninja-build
tor
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

if [ "${#MISSING[@]}" -gt 0 ]; then
echo "Installing missing dependencies..."

```
sudo apt update
sudo apt install -y "${MISSING[@]}"
```

else
echo "All dependencies are already installed."
fi

echo
echo "[1/4] Configuring build..."

BUILD_DIR="$PROJECT_DIR/build"

cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -G Ninja

echo
echo "[2/4] Building GyroJett-OneShot2..."

cmake --build "$BUILD_DIR"

BINARY="$BUILD_DIR/GyroJett-OneShot2"

if [ ! -x "$BINARY" ]; then
echo
echo "Error: GyroJett-OneShot2 binary was not created."
exit 1
fi

echo
echo "Build completed successfully."

echo
echo "[3/4] Configuring Tor..."

TORRC="/etc/tor/torrc"

if grep -qF "ControlPort 9051" "$TORRC"; then
echo "ControlPort 9051 already configured."
else
sudo bash -c 'printf "\n# GyroJett-OneShot2\nControlPort 9051\n" >> /etc/tor/torrc'

```
echo "ControlPort 9051 added."
```

fi

if grep -qF "CookieAuthentication 1" "$TORRC"; then
echo "CookieAuthentication already configured."
else
sudo bash -c 'printf "CookieAuthentication 1\n" >> /etc/tor/torrc'

```
echo "CookieAuthentication added."
```

fi

echo
echo "Restarting Tor..."

sudo systemctl enable [tor@default.service](mailto:tor@default.service)
sudo systemctl restart [tor@default.service](mailto:tor@default.service)

echo
echo "Checking Tor ControlPort..."

for i in {1..30}; do
if ss -lnt 2>/dev/null | grep -q "127.0.0.1:9051"; then
break
fi

```
sleep 1
```

done

if ! ss -lnt 2>/dev/null | grep -q "127.0.0.1:9051"; then
echo
echo "Error: Tor ControlPort 9051 is not available."
echo
echo "Check:"
echo "  sudo systemctl status [tor@default.service](mailto:tor@default.service)"
echo "  sudo journalctl -u [tor@default.service](mailto:tor@default.service) -n 50 --no-pager"
exit 1
fi

echo "Tor ControlPort is ready."

echo
echo "[4/4] Configuring user permissions..."

if id -nG "$USER" | tr ' ' '\n' | grep -qx "debian-tor"; then
echo "User $USER is already in the debian-tor group."
else
sudo usermod -aG debian-tor "$USER"

```
echo
echo "User $USER was added to the debian-tor group."
echo "Please log out and log back in before running GyroJett-OneShot2."
```

fi

echo
echo "Installing GyroJett-OneShot2..."

sudo install -m 755 "$BINARY" /usr/local/bin/gyrojett-oneshot2

echo
echo "#######################################"
echo "#     GyroJett-OneShot2 installed!    #"
echo "#######################################"
echo
echo "Binary:"
echo "  /usr/local/bin/GyroJett-OneShot2"
echo
echo "Run with:"
echo "  GyroJett-OneShot2"
echo
echo "Important:"
echo "  If you were added to the debian-tor group,"
echo "  log out and log back in before running it."
echo
