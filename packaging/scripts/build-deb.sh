#!/bin/bash
# build-deb.sh - Assembles the phosh-pam-duress .deb package
# Usage: bash packaging/scripts/build-deb.sh <version> <arch>
set -euo pipefail

VERSION="${1:?Version required (e.g. 1.0.0)}"
ARCH="${2:?Architecture required (e.g. arm64)}"
PKG_NAME="phosh-pam-duress"
PKG_DIR="$(mktemp -d)"
DIST_DIR="dist"

STRIP="aarch64-linux-gnu-strip"

echo "==> Building ${PKG_NAME}_${VERSION}_${ARCH}.deb"

# ── Directory layout inside the .deb ──────────────────────────────────────────
LIB_SECURITY="${PKG_DIR}/lib/security"
BIN_DIR="${PKG_DIR}/usr/local/bin"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"
DURESS_D="${PKG_DIR}/etc/duress.d"

mkdir -p "$LIB_SECURITY" "$BIN_DIR" "$DEBIAN_DIR" "$DURESS_D"

# ── Copy build artifacts ───────────────────────────────────────────────────────
echo "==> Copying build artifacts..."
cp bin/pam_duress.so "$LIB_SECURITY/"
cp bin/duress_sign   "$BIN_DIR/"
cp bin/pam_test      "$BIN_DIR/"

$STRIP "$LIB_SECURITY/pam_duress.so" "$BIN_DIR/duress_sign" "$BIN_DIR/pam_test"

# ── Copy example duress scripts ────────────────────────────────────────────────
echo "==> Copying duress scripts..."
cp packaging/etc/duress.d/wipe.sh "$DURESS_D/wipe.sh"
chmod 0500 "$DURESS_D/wipe.sh"

# ── DEBIAN control files ───────────────────────────────────────────────────────
echo "==> Writing DEBIAN control files..."

sed \
  -e "s/VERSION_PLACEHOLDER/${VERSION}/" \
  -e "s/ARCH_PLACEHOLDER/${ARCH}/" \
  packaging/DEBIAN/control > "$DEBIAN_DIR/control"

cp packaging/DEBIAN/postinst "$DEBIAN_DIR/postinst"
cp packaging/DEBIAN/prerm    "$DEBIAN_DIR/prerm"

chmod 0755 "$DEBIAN_DIR/postinst" "$DEBIAN_DIR/prerm"

# ── Set correct permissions ────────────────────────────────────────────────────
chmod 0755 "$LIB_SECURITY/pam_duress.so"
chmod 0755 "$BIN_DIR/duress_sign"
chmod 0755 "$BIN_DIR/pam_test"

# ── Build .deb ─────────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR"
DEB_PATH="${DIST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.deb"

dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_PATH"

echo "==> Package ready: ${DEB_PATH}"
ls -lh "$DEB_PATH"
