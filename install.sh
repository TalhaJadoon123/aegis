#!/usr/bin/env sh
# Install Aegis. No npm account required; the package has zero dependencies.
set -eu

VERSION="${AEGIS_VERSION:-0.1.2}"
ASSET="talhajadoon123-aegis-${VERSION}.tgz"
URL="https://github.com/TalhaJadoon123/aegis/releases/download/v${VERSION}/${ASSET}"

say() { printf '%s\n' "$*"; }
fail() { printf '\n  ERROR: %s\n\n' "$*" >&2; exit 1; }

say ""
say "  Aegis installer"
say "  ---------------"
say ""

command -v node >/dev/null 2>&1 || fail "Node.js is not installed. Install Node.js 22+ from https://nodejs.org and run this script again."
command -v npm  >/dev/null 2>&1 || fail "npm was not found next to Node.js. Reinstall Node.js with npm included."

NODE_VERSION="$(node --version | sed 's/^v//')"
NODE_MAJOR="${NODE_VERSION%%.*}"
[ "$NODE_MAJOR" -ge 22 ] 2>/dev/null || fail "Node.js ${NODE_VERSION} found, but Aegis needs 22 or newer."
say "  Node.js ${NODE_VERSION}  OK"

TMP="${TMPDIR:-/tmp}/aegis-install-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
TARBALL="${TMP}/${ASSET}"

say "  Downloading Aegis ${VERSION} ..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TARBALL" || fail "Could not download ${URL}"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$URL" -O "$TARBALL" || fail "Could not download ${URL}"
else
  fail "Neither curl nor wget is available."
fi

say "  Installing ..."
npm install -g "$TARBALL" --no-audit --no-fund || fail "npm install failed (a permission error usually means you need sudo or a user prefix: https://docs.npmjs.com/resolving-eacces-permissions-errors)."

INSTALLED="$(aegis --version 2>&1)" || fail "Aegis was installed but does not run."
say ""
say "  Installed: ${INSTALLED}"
say ""
say "  Try it:"
say "    aegis scan .                 scan the current project"
say "    aegis desktop                open the dashboard"
say "    aegis report --compliance    compliance attestation"
say ""