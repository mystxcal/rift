#!/usr/bin/env bash
set -Eeuo pipefail

# Produce a deterministic, host-target release bundle from one clean commit.

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly OUT_DIR="${1:-$ROOT_DIR/target/dist}"

die() {
  printf 'package-release: %s\n' "$*" >&2
  exit 1
}

cd "$ROOT_DIR"
command -v jq >/dev/null 2>&1 || die 'jq is required'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required'
command -v tar >/dev/null 2>&1 || die 'tar is required'
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || \
  die 'tracked worktree must be clean so the artifact has one exact source identity'

revision="$(git rev-parse HEAD)"
source_epoch="$(git show -s --format=%ct HEAD)"
target="$(rustc -vV | sed -n 's/^host: //p')"
version="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "rift-cli") | .version')"
name="rift-${version}-${target}"
stage="$OUT_DIR/$name"
archive="$OUT_DIR/$name.tar.gz"

[[ ! -e "$stage" && ! -e "$archive" ]] || die "artifact already exists under $OUT_DIR"
mkdir -p "$stage"
cargo build --release --locked -p rift-cli
cp target/release/rift "$stage/rift"
cp scripts/install.sh "$stage/install.sh"
cp README.md "$stage/README.md"
cp LICENSE "$stage/LICENSE"
chmod 755 "$stage/rift" "$stage/install.sh"

binary_sha="$(sha256sum "$stage/rift" | awk '{print $1}')"
jq -n \
  --arg schema rift.release.v1 \
  --arg version "$version" \
  --arg target "$target" \
  --arg revision "$revision" \
  --arg binary_sha256 "$binary_sha" \
  '{schema:$schema,version:$version,target:$target,source_revision:$revision,binary_sha256:$binary_sha256}' \
  > "$stage/manifest.json"
(
  cd "$stage"
  sha256sum LICENSE README.md install.sh manifest.json rift > SHA256SUMS
)
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$OUT_DIR" -cf - "$name" | gzip -n > "$archive"
(
  cd "$(dirname "$archive")"
  sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256"
)
printf '%s\n' "$archive"
