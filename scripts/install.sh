#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/trust_roundabout"
USER="trustroundabout"

echo "Installing Trust Roundabout..."

# Install Rust if missing
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Create user
id -u $USER >/dev/null 2>&1 || sudo useradd --system --shell /usr/sbin/nologin $USER

sudo mkdir -p $INSTALL_DIR
sudo cp -r ./* $INSTALL_DIR/
sudo chown -R $USER:$USER $INSTALL_DIR

sudo bash -c "cd $INSTALL_DIR && cargo build --release"

# Install systemd service
sudo cp scripts/trust-roundabout.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable trust-roundabout
sudo systemctl start trust-roundabout

echo "Installation complete. Config at $INSTALL_DIR/config.toml"
echo "Manage service with: sudo systemctl status trust-roundabout"
