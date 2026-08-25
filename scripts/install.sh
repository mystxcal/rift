#!/usr/bin/env bash
set -Eeuo pipefail

archive=""
repository=""
bundle=""
tag="latest"
prefix="${RIFT_INSTALL_DIR:-$HOME/.local/bin}"
relay=""
ca_cert=""

die() {
  printf 'rift-install: %s\n' "$*" >&2
  exit 1
}

while (( $# > 0 )); do
  case "$1" in
    --archive) archive="${2:-}"; shift 2 ;;
    --repo) repository="${2:-}"; shift 2 ;;
    --bundle) bundle="${2:-}"; shift 2 ;;
    --tag) tag="${2:-}"; shift 2 ;;
    --prefix) prefix="${2:-}"; shift 2 ;;
    --relay) relay="${2:-}"; shift 2 ;;
    --ca-cert) ca_cert="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -z "$archive" && -z "$repository" && -z "$bundle" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/manifest.json" && -f "$script_dir/rift" ]]; then
    bundle="$script_dir"
  fi
fi
sources=0
[[ -z "$archive" ]] || (( sources += 1 ))
[[ -z "$repository" ]] || (( sources += 1 ))
[[ -z "$bundle" ]] || (( sources += 1 ))
(( sources == 1 )) || die 'use exactly one of --archive FILE, --repo OWNER/REPO, or --bundle DIR'
[[ -z "$ca_cert" || -n "$relay" ]] || die '--ca-cert requires --relay'
work=""
if [[ -n "$archive" || -n "$repository" ]]; then
  work="$(mktemp -d)"
fi
cleanup() {
  [[ -z "$work" ]] || rm -rf -- "$work"
}
trap cleanup EXIT

if [[ -n "$repository" ]]; then
  command -v gh >/dev/null 2>&1 || die 'gh is required for a private GitHub release'
  if [[ "$tag" == latest ]]; then
    gh release download --repo "$repository" \
      --pattern '*x86_64-unknown-linux-gnu.tar.gz' \
      --pattern '*x86_64-unknown-linux-gnu.tar.gz.sha256' --dir "$work"
  else
    gh release download "$tag" --repo "$repository" \
      --pattern '*x86_64-unknown-linux-gnu.tar.gz' \
      --pattern '*x86_64-unknown-linux-gnu.tar.gz.sha256' --dir "$work"
  fi
  mapfile -t archives < <(find "$work" -maxdepth 1 -type f -name '*.tar.gz' -print)
  (( ${#archives[@]} == 1 )) || die 'release must contain exactly one Linux archive'
  archive="${archives[0]}"
fi
if [[ -n "$archive" ]]; then
  [[ -f "$archive" ]] || die "archive not found: $archive"
  [[ -f "$archive.sha256" ]] || die "archive checksum not found: $archive.sha256"
  (
    cd "$(dirname "$archive")"
    sha256sum --check "$(basename "$archive").sha256" >/dev/null
  ) || die 'release archive checksum mismatch'

  mapfile -t entries < <(tar -tzf "$archive")
  (( ${#entries[@]} > 0 )) || die 'empty RIFT release archive'
  root="${entries[0]%%/*}"
  [[ "$root" == rift-* && -n "$root" ]] || die 'invalid release root'
  for entry in "${entries[@]}"; do
    [[ "$entry" == "$root" || "$entry" == "$root/" || "$entry" == "$root/"* ]] || \
      die 'release contains entries outside its root'
    [[ "$entry" != /* && "$entry" != *'/../'* && "$entry" != '../'* && "$entry" != *'/..' ]] || \
      die 'release contains an unsafe path'
  done
  if tar -tvzf "$archive" | awk '$1 !~ /^[-d]/ { exit 1 }'; then :; else
    die 'release contains a link or special file'
  fi
  tar -xzf "$archive" -C "$work"
  bundle="$work/$root"
fi
[[ -d "$bundle" ]] || die "bundle not found: $bundle"
actual_files="$(find "$bundle" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
expected_files="$(printf '%s\n' LICENSE README.md SHA256SUMS install.sh manifest.json rift | LC_ALL=C sort)"
[[ "$actual_files" == "$expected_files" ]] || die 'release contains an unexpected file set'
binary="$bundle/rift"
sums="$bundle/SHA256SUMS"
[[ -f "$binary" && -f "$sums" ]] || die 'invalid RIFT release archive'
checksum_files=""
while IFS= read -r line; do
  [[ "$line" =~ ^[0-9a-f]{64}[[:space:]][[:space:]](LICENSE|README\.md|install\.sh|manifest\.json|rift)$ ]] || \
    die 'checksum manifest contains an unsafe or unexpected entry'
  checksum_files+="${BASH_REMATCH[1]}"$'\n'
done < "$sums"
checksum_files="$(printf '%s' "$checksum_files" | LC_ALL=C sort)"
expected_checksum_files="$(printf '%s\n' LICENSE README.md install.sh manifest.json rift | LC_ALL=C sort)"
[[ "$checksum_files" == "$expected_checksum_files" ]] || \
  die 'checksum manifest must name every payload file exactly once'
(
  cd "$bundle"
  sha256sum --check SHA256SUMS >/dev/null
)
mkdir -p "$prefix"
installing="$prefix/.rift.install.$$"
trap 'rm -f -- "$installing"; cleanup' EXIT
"$binary" --json doctor >/dev/null
install -m 0755 "$binary" "$installing"
mv -f "$installing" "$prefix/rift"
if [[ -n "$relay" ]]; then
  installed_ca=""
  if [[ -n "$ca_cert" ]]; then
    [[ -f "$ca_cert" ]] || die "CA certificate not found: $ca_cert"
    installed_ca="$prefix/rift-relay-ca.pem"
    ca_installing="$prefix/.rift-relay-ca.install.$$"
    install -m 0644 "$ca_cert" "$ca_installing"
    mv -f "$ca_installing" "$installed_ca"
  fi
  config=(config set-relay "$relay")
  [[ -z "$installed_ca" ]] || config+=(--ca-cert "$installed_ca")
  "$prefix/rift" "${config[@]}" >/dev/null
fi
printf 'Installed %s\n' "$prefix/rift"
