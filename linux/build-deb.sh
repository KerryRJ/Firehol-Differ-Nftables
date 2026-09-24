#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)
ARCH=${DEB_HOST_ARCH:-$(dpkg --print-architecture)}
OUTPUT_DIR=${OUTPUT_DIR:-"$REPO_ROOT/target/debian"}
PACKAGE_NAME="firehol-differ-nftables-linux-${ARCH}"
STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

if [ "$(id -u)" -eq 0 ]; then
    echo "Refusing to build packages as root" >&2
    exit 1
fi

cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p linux

install -d \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr/bin" \
    "$STAGE_DIR/usr/lib/systemd/system" \
    "$STAGE_DIR/etc/firehol-differ-nftables"
install -m 0755 "$REPO_ROOT/target/release/firehol-differ-nftables" "$STAGE_DIR/usr/bin/firehol-differ-nftables"
install -m 0644 "$SCRIPT_DIR/firehol-differ-nftables.service" "$STAGE_DIR/usr/lib/systemd/system/firehol-differ-nftables.service"
sed 's|^path = .*|path = "/var/lib/firehol-differ-nftables"|' \
    "$REPO_ROOT/config.toml" > "$STAGE_DIR/etc/firehol-differ-nftables/config.toml"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: firehol-differ-nftables
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: adduser, systemd
Maintainer: Info-Overdrive
Description: FireHOL IP list scheduler service
 Downloads and maintains the configured FireHOL IP lists as a systemd service.
EOF

cat > "$STAGE_DIR/DEBIAN/conffiles" <<'EOF'
/etc/firehol-differ-nftables/config.toml
EOF

cat > "$STAGE_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu

if ! getent passwd firehol-differ-nftables >/dev/null; then
    adduser --system --group --no-create-home firehol-differ-nftables
fi

install -d -o firehol-differ-nftables -g firehol-differ-nftables -m 0750 \
    /var/lib/firehol-differ-nftables

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now firehol-differ-nftables.service >/dev/null
fi

exit 0
EOF

cat > "$STAGE_DIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu

if [ "${1:-}" = remove ] || [ "${1:-}" = upgrade ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now firehol-differ-nftables.service >/dev/null 2>&1 || true
    fi
fi

exit 0
EOF

cat > "$STAGE_DIR/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

exit 0
EOF

chmod 0755 "$STAGE_DIR/DEBIAN/postinst" "$STAGE_DIR/DEBIAN/prerm" "$STAGE_DIR/DEBIAN/postrm"
install -d "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$STAGE_DIR" "$OUTPUT_DIR/$PACKAGE_NAME.deb"
printf '%s\n' "$OUTPUT_DIR/$PACKAGE_NAME.deb"
