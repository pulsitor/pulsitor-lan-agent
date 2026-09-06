#!/bin/sh
#
# Installs the Pulsitor LAN agent as a system service on Linux and macOS.
#
#   curl -fsSL https://github.com/pulsitor/pulsitor-lan-agent/releases/latest/download/install.sh \
#     | sudo sh -s -- --enroll <token>
#
# Or, with a binary already downloaded:
#
#   sudo ./install.sh --binary ./pulsitor-lan-agent --enroll <token>
#
# The script downloads, verifies and places the binary; everything after that — the
# enrollment, the service definition and starting it — is the agent's own
# `service install`, so a hand install and a scripted one cannot drift apart.

set -eu

# The Pulsitor endpoint is compiled into the binary; this script never passes one.
SERVER=""
REPO="${PULSITOR_REPO:-pulsitor/pulsitor-lan-agent}"
VERSION="${PULSITOR_VERSION:-latest}"
TOKEN=""
TOKEN_FILE=""
BINARY=""
STATE=""
LOG=""
VERBOSE=""

fail() {
	echo "install: $*" >&2
	exit 1
}

usage() {
	cat >&2 <<'USAGE'
Usage: install.sh [options]

  --enroll <token>       one-time enrollment token from Pulsitor
  --enroll-file <path>   read the token from a file instead
  --version <tag>        release to install (default: latest)
  --repo <owner/name>    GitHub repository to install from
  --binary <path>        install this file instead of downloading
  --server <url>         development override; the release endpoint is
                         compiled into the binary and needs no flag
  --state <path>         where to keep the identity
  --log-file <path>      where the service writes its log
  --verbose              log every round, not only the ones that carried news
USAGE
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
		--enroll) TOKEN="${2:-}"; shift 2 ;;
		--enroll-file) TOKEN_FILE="${2:-}"; shift 2 ;;
		--server) SERVER="${2:-}"; shift 2 ;;
		--version) VERSION="${2:-}"; shift 2 ;;
		--repo) REPO="${2:-}"; shift 2 ;;
		--binary) BINARY="${2:-}"; shift 2 ;;
		--state) STATE="${2:-}"; shift 2 ;;
		--log-file) LOG="${2:-}"; shift 2 ;;
		--verbose) VERBOSE=1; shift ;;
		-h|--help) usage ;;
		*) fail "unknown option $1" ;;
	esac
done

[ "$(id -u)" = "0" ] || fail "installing a service needs root; re-run under sudo"

# Where the binary is downloaded to, cleaned up however the script exits.
WORK=""
cleanup() { if [ -n "$WORK" ]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT INT TERM

# platform names the release artefact for this machine.
platform() {
	os=$(uname -s)
	arch=$(uname -m)

	case "$os" in
		Linux) os=linux ;;
		Darwin) os=darwin ;;
		*) fail "$os is not supported; run the agent in the foreground instead" ;;
	esac

	case "$arch" in
		x86_64|amd64) arch=amd64 ;;
		aarch64|arm64) arch=arm64 ;;
		armv7l|armv6l|arm) arch=arm ;;
		i386|i686) arch=386 ;;
		*) fail "$arch is not a published architecture" ;;
	esac

	# macOS ships no 32 bit or ARMv7 builds, and never will.
	if [ "$os" = darwin ] && [ "$arch" != amd64 ] && [ "$arch" != arm64 ]; then
		fail "$arch is not supported on macOS"
	fi

	echo "$os-$arch"
}

# fetch downloads one URL, using whichever of curl or wget the machine has.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		fail "neither curl nor wget is available; download the binary yourself and pass --binary"
	fi
}

# verify checks the download against the published checksums.
#
# Not optional: this script runs as root and the thing it downloads is then run as a
# service, so an unverified artefact is a root shell for whoever can answer the request.
verify() {
	artefact="$1"
	sums="$2"

	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$artefact" | cut -d' ' -f1)
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$artefact" | cut -d' ' -f1)
	else
		fail "no sha256sum or shasum to verify the download with"
	fi

	expected=$(grep " \*\{0,1\}$(basename "$artefact")\$" "$sums" | cut -d' ' -f1 | head -n1)

	[ -n "$expected" ] || fail "$(basename "$artefact") is not listed in SHA256SUMS"
	[ "$actual" = "$expected" ] || fail "checksum mismatch for $(basename "$artefact"): got $actual, expected $expected"
}

# release is the GitHub download prefix for the requested version.
#
# GitHub serves "releases/latest/download/<asset>" as a redirect to whatever the newest
# release is, and a tag has its own path — so "latest" needs no API call, no token and
# no JSON parsing, which is what keeps this script to curl and sha256sum.
release() {
	if [ "$VERSION" = "latest" ]; then
		echo "https://github.com/$REPO/releases/latest/download"
	else
		echo "https://github.com/$REPO/releases/download/$VERSION"
	fi
}

if [ -z "$BINARY" ]; then
	NAME="pulsitor-lan-agent-$(platform)"
	BASE=$(release)
	WORK=$(mktemp -d)

	echo "downloading $NAME ($VERSION)"
	fetch "$BASE/$NAME" "$WORK/$NAME"
	fetch "$BASE/SHA256SUMS" "$WORK/SHA256SUMS"
	verify "$WORK/$NAME" "$WORK/SHA256SUMS"

	BINARY="$WORK/$NAME"
	chmod 0755 "$BINARY"
else
	[ -f "$BINARY" ] || fail "$BINARY does not exist"

	# Made executable only if it is not already. The file belongs to whoever passed it
	# and may well sit somewhere we cannot chmod — a read-only mount, or another user's
	# directory — and failing there would abort an install that needed no change at all.
	if [ ! -x "$BINARY" ] && ! chmod 0755 "$BINARY" 2>/dev/null; then
		fail "$BINARY is not executable and its mode could not be changed"
	fi
fi

# Built as positional parameters rather than one string, so a path with a space in it
# survives. `set -e` makes a bare `[ ... ] && ...` fatal the moment the test is false,
# which is why each of these is a full if.
set -- service install

if [ -n "$SERVER" ]; then set -- "$@" --server "$SERVER"; fi
if [ -n "$TOKEN" ]; then set -- "$@" --enroll "$TOKEN"; fi
if [ -n "$TOKEN_FILE" ]; then set -- "$@" --enroll-file "$TOKEN_FILE"; fi
if [ -n "$STATE" ]; then set -- "$@" --state "$STATE"; fi
if [ -n "$LOG" ]; then set -- "$@" --log-file "$LOG"; fi
if [ -n "$VERBOSE" ]; then set -- "$@" --verbose; fi

"$BINARY" "$@"

echo
echo "pulsitor-lan-agent service status   # what it is doing"
echo "pulsitor-lan-agent service uninstall  # to remove it"
