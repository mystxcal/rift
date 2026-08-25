#!/usr/bin/env bash
set -Eeuo pipefail

# One-command, live-only acceptance run. The default managed mode starts one
# ephemeral WSS+UDP relay on this host, copies the exact local release binary
# to an SSH-accessible receiver, transfers one object, independently hashes the
# result, and removes all remote state. `--remote local` rehearses the same
# lifecycle without claiming physical-host evidence.

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly RIFT_BIN="${RIFT_BIN:-$ROOT_DIR/target/release/rift}"

REMOTE=""
REMOTE_RIFT_BIN=""
RELAY_HOST=""
RELAY_PORT=17337
RELAY_URL=""
CA_CERT=""
RELAY_CERT=""
RELAY_KEY=""
SOURCE=""
SIZE_MIB=8
TIMEOUT_SECONDS=300
ARTIFACT_DIR=""
REMOTE_DIR=""
REMOTE_BINARY=""
SENDER_PID=""
RELAY_PID=""

die() {
  printf 'remote-smoke: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage:' \
    '  remote-smoke.sh --remote local --relay-host 127.0.0.1' \
    '  remote-smoke.sh --remote USER@HOST --relay-host PUBLIC_HOST [options]' \
    '  remote-smoke.sh --remote USER@HOST --relay WSS_URL --ca-cert CA [options]' \
    '' \
    'managed relay options:' \
    '  --relay-host HOST       certificate name/address and public relay locator' \
    '  --relay-port PORT       TCP+UDP port; 0 asks the OS (default 17337)' \
    '' \
    'existing relay options:' \
    '  --relay WSS_URL         exact wss://.../rift/v1 endpoint' \
    '  --ca-cert FILE          private CA, omitted for a publicly trusted relay' \
    '' \
    'transfer options:' \
    '  --remote-binary FILE    receiver binary for a different Linux architecture' \
    '  --source FILE           source object (default: generated 8 MiB assay)' \
    '  --size-mib N            generated assay size (default 8)' \
    '  --timeout SECONDS       whole receiver/sender bound (default 300)' \
    '  --artifact-dir DIR      new local evidence directory under ignored target/'
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

kill_if_live() {
  local pid="${1:-}"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

remote_run() {
  local command="$1"
  if [[ "$REMOTE" == local ]]; then
    bash -c "$command"
  else
    ssh -o BatchMode=yes -o ConnectTimeout=15 -- "$REMOTE" "$command"
  fi
}

copy_to_remote() {
  local source="$1"
  local destination="$2"
  if [[ "$REMOTE" == local ]]; then
    cp -- "$source" "$destination"
  else
    scp -q -o BatchMode=yes -o ConnectTimeout=15 -- "$source" "$REMOTE:$destination"
  fi
}

cleanup() {
  set +e
  kill_if_live "$SENDER_PID"
  kill_if_live "$RELAY_PID"
  if [[ "$REMOTE_DIR" =~ ^/tmp/rift-remote\.[A-Za-z0-9]+$ ]]; then
    remote_run "rm -rf -- '$REMOTE_DIR'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

wait_for_json_kind() {
  local file="$1"
  local kind="$2"
  local pid="$3"
  local deadline="$((SECONDS + 15))"
  while (( SECONDS < deadline )); do
    if [[ -s "$file" ]] && jq -e --arg kind "$kind" 'select(.kind == $kind)' "$file" \
      >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    sleep 0.1
  done
  return 1
}

wait_bounded() {
  local pid="$1"
  local role="$2"
  local deadline="$((SECONDS + TIMEOUT_SECONDS))"
  while kill -0 "$pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      kill_if_live "$pid"
      die "$role exceeded the ${TIMEOUT_SECONDS}s transfer bound"
    fi
    sleep 0.1
  done
  wait "$pid" || die "$role failed; inspect $ARTIFACT_DIR"
}

make_ephemeral_pki() {
  local pki="$ARTIFACT_DIR/pki"
  local san
  mkdir -p "$pki"
  if [[ "$RELAY_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$RELAY_HOST" == *:* ]]; then
    san="IP:$RELAY_HOST"
  else
    [[ "$RELAY_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die 'relay host is not a canonical IP or DNS name'
    san="DNS:$RELAY_HOST"
  fi
  CA_CERT="$pki/ca.crt"
  RELAY_CERT="$pki/relay.crt"
  RELAY_KEY="$pki/relay.key"
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=RIFT acceptance CA' \
    -keyout "$pki/ca.key" -out "$pki/ca.csr" >/dev/null 2>&1
  printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid:always' > "$pki/ca.ext"
  openssl x509 -req -days 1 -sha256 -in "$pki/ca.csr" \
    -signkey "$pki/ca.key" -extfile "$pki/ca.ext" -out "$CA_CERT" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=RIFT acceptance relay' \
    -keyout "$RELAY_KEY" -out "$pki/relay.csr" >/dev/null 2>&1
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=$san" > "$pki/relay.ext"
  openssl x509 -req -days 1 -sha256 -in "$pki/relay.csr" \
    -CA "$CA_CERT" -CAkey "$pki/ca.key" -CAcreateserial \
    -extfile "$pki/relay.ext" -out "$RELAY_CERT" >/dev/null 2>&1
  chmod 600 "$pki/ca.key" "$RELAY_KEY"
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --remote) REMOTE="${2:-}"; shift 2 ;;
      --remote-binary) REMOTE_RIFT_BIN="${2:-}"; shift 2 ;;
      --relay-host) RELAY_HOST="${2:-}"; shift 2 ;;
      --relay-port) RELAY_PORT="${2:-}"; shift 2 ;;
      --relay) RELAY_URL="${2:-}"; shift 2 ;;
      --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
      --source) SOURCE="${2:-}"; shift 2 ;;
      --size-mib) SIZE_MIB="${2:-}"; shift 2 ;;
      --timeout) TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
      --artifact-dir) ARTIFACT_DIR="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
}

main() {
  parse_args "$@"
  for command in jq openssl sha256sum dd cp chmod; do need "$command"; done
  [[ -x "$RIFT_BIN" ]] || die "release binary not found: $RIFT_BIN"
  if [[ -n "$REMOTE_RIFT_BIN" ]]; then
    [[ -x "$REMOTE_RIFT_BIN" ]] || \
      die "remote release binary not found or executable: $REMOTE_RIFT_BIN"
  else
    REMOTE_RIFT_BIN="$RIFT_BIN"
  fi
  [[ -n "$REMOTE" ]] || die '--remote is required'
  if [[ "$REMOTE" != local ]]; then
    need ssh
    need scp
    [[ "$REMOTE" =~ ^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+$ ]] || \
      die 'remote must be a conservative USER@HOST SSH selector'
  fi
  if [[ ! "$RELAY_PORT" =~ ^[0-9]+$ ]] || (( RELAY_PORT > 65535 )); then
    die 'relay port must be 0..65535'
  fi
  if [[ ! "$SIZE_MIB" =~ ^[0-9]+$ ]] || (( SIZE_MIB == 0 || SIZE_MIB > 1024 )); then
    die 'size must be 1..1024 MiB'
  fi
  if [[ ! "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || \
    (( TIMEOUT_SECONDS < 10 || TIMEOUT_SECONDS > 3600 )); then
    die 'timeout must be 10..3600 seconds'
  fi

  if [[ -n "$RELAY_HOST" && -n "$RELAY_URL" ]]; then
    die 'choose either a managed --relay-host or an existing --relay'
  fi
  if [[ -z "$RELAY_HOST" && -z "$RELAY_URL" ]]; then
    die 'one of --relay-host or --relay is required'
  fi

  local local_arch remote_arch remote_os
  local_arch="$(uname -m)"
  remote_os="$(remote_run 'uname -s')"
  remote_arch="$(remote_run 'uname -m')"
  [[ "$remote_os" == Linux ]] || die "remote OS is $remote_os; this bundle is Linux-only"
  if [[ "$REMOTE_RIFT_BIN" == "$RIFT_BIN" && "$remote_arch" != "$local_arch" ]]; then
    die "remote architecture $remote_arch needs a matching --remote-binary; local artifact is $local_arch"
  fi

  if [[ -z "$ARTIFACT_DIR" ]]; then
    ARTIFACT_DIR="$ROOT_DIR/target/remote-acceptance"
  fi
  [[ ! -e "$ARTIFACT_DIR" ]] || die "artifact directory already exists: $ARTIFACT_DIR"
  mkdir -p "$ARTIFACT_DIR"

  if [[ -n "$RELAY_HOST" ]]; then
    make_ephemeral_pki
    local listen
    if [[ "$RELAY_HOST" == *:* ]]; then listen="[::]:$RELAY_PORT"; else listen="0.0.0.0:$RELAY_PORT"; fi
    "$RIFT_BIN" --json relay --listen "$listen" \
      --one-shot \
      --tls-cert "$RELAY_CERT" --tls-key "$RELAY_KEY" \
      > "$ARTIFACT_DIR/relay.jsonl" 2> "$ARTIFACT_DIR/relay.stderr" &
    RELAY_PID=$!
    wait_for_json_kind "$ARTIFACT_DIR/relay.jsonl" relay_ready "$RELAY_PID" || \
      die 'managed relay did not become ready'
    RELAY_PORT="$(jq -r 'select(.kind == "relay_ready") | .address | capture(":(?<port>[0-9]+)$").port' "$ARTIFACT_DIR/relay.jsonl" | tail -1)"
    if [[ ! "$RELAY_PORT" =~ ^[0-9]+$ ]] || (( RELAY_PORT == 0 || RELAY_PORT > 65535 )); then
      die 'managed relay reported a malformed bound port'
    fi
    if [[ "$RELAY_HOST" == *:* ]]; then
      RELAY_URL="wss://[$RELAY_HOST]:$RELAY_PORT/rift/v1"
    else
      RELAY_URL="wss://$RELAY_HOST:$RELAY_PORT/rift/v1"
    fi
  else
    [[ "$RELAY_URL" =~ ^wss://[A-Za-z0-9.-]+(:[0-9]+)?/rift/v1$ || \
      "$RELAY_URL" =~ ^wss://\[[0-9A-Fa-f:.]+\](:[0-9]+)?/rift/v1$ ]] || \
      die 'relay URL must be canonical wss://HOST[:PORT]/rift/v1'
    if [[ -n "$CA_CERT" ]]; then
      [[ -f "$CA_CERT" ]] || die "CA file not found: $CA_CERT"
    fi
  fi

  if [[ -z "$SOURCE" ]]; then
    SOURCE="$ARTIFACT_DIR/source.bin"
    dd if=/dev/urandom of="$SOURCE" bs=1M count="$SIZE_MIB" status=none
  fi
  [[ -f "$SOURCE" ]] || die "source is not a regular file: $SOURCE"

  REMOTE_DIR="$(remote_run 'mktemp -d -t rift-remote.XXXXXX')"
  [[ "$REMOTE_DIR" =~ ^/tmp/rift-remote\.[A-Za-z0-9]+$ ]] || \
    die 'remote returned a noncanonical temporary path'
  REMOTE_BINARY="$REMOTE_DIR/rift"
  copy_to_remote "$REMOTE_RIFT_BIN" "$REMOTE_BINARY"
  remote_run "chmod 700 '$REMOTE_BINARY'"
  local remote_ca=""
  local ca_arg=""
  if [[ -n "$CA_CERT" ]]; then
    remote_ca="$REMOTE_DIR/ca.crt"
    copy_to_remote "$CA_CERT" "$remote_ca"
    ca_arg="--ca-cert '$remote_ca'"
  fi
  remote_run "'$REMOTE_BINARY' --json doctor" > "$ARTIFACT_DIR/remote-doctor.json"
  jq -e '.ok == true and .kind == "doctor"' "$ARTIFACT_DIR/remote-doctor.json" >/dev/null || \
    die 'remote binary doctor failed'

  local -a sender_command=("$RIFT_BIN" --json send "$SOURCE" --relay "$RELAY_URL")
  if [[ -n "$CA_CERT" ]]; then
    sender_command+=(--ca-cert "$CA_CERT")
  fi
  "${sender_command[@]}" > "$ARTIFACT_DIR/sender.jsonl" \
    2> "$ARTIFACT_DIR/sender.stderr" &
  SENDER_PID=$!
  wait_for_json_kind "$ARTIFACT_DIR/sender.jsonl" offer "$SENDER_PID" || \
    die 'sender did not reserve a pairing code'
  local code
  code="$(jq -r 'select(.kind == "offer") | .code' "$ARTIFACT_DIR/sender.jsonl" | tail -1)"
  [[ "$code" =~ ^[0-9]{4}-[a-z]{6}$ ]] || die 'sender emitted a malformed pairing code'

  local receive_command
  receive_command="'$REMOTE_BINARY' --json receive '$code' '$REMOTE_DIR/destination.bin' --relay '$RELAY_URL' $ca_arg"
  if [[ "$REMOTE" == local ]]; then
    timeout "$TIMEOUT_SECONDS" bash -c "$receive_command" \
      > "$ARTIFACT_DIR/receiver.jsonl" 2> "$ARTIFACT_DIR/receiver.stderr" || \
      die 'receiver failed or exceeded its deadline'
  else
    timeout "$TIMEOUT_SECONDS" ssh -o BatchMode=yes -o ConnectTimeout=15 -- "$REMOTE" \
      "$receive_command" > "$ARTIFACT_DIR/receiver.jsonl" \
      2> "$ARTIFACT_DIR/receiver.stderr" || die 'receiver failed or exceeded its deadline'
  fi
  wait_bounded "$SENDER_PID" sender
  SENDER_PID=""
  if [[ -n "$RELAY_PID" ]]; then
    wait_bounded "$RELAY_PID" relay
    RELAY_PID=""
  fi

  local sender receiver local_sha remote_sha
  sender="$(jq -c 'select(.kind == "send_complete")' "$ARTIFACT_DIR/sender.jsonl")"
  receiver="$(jq -c 'select(.kind == "receive_complete")' "$ARTIFACT_DIR/receiver.jsonl")"
  [[ -n "$sender" && -n "$receiver" ]] || die 'terminal transfer evidence is missing'
  jq -e --argjson receiver "$receiver" \
    '.bytes == $receiver.bytes and .digest == $receiver.digest' <<< "$sender" >/dev/null || \
    die 'authenticated sender and receiver summaries disagree'
  local_sha="$(sha256sum "$SOURCE" | awk '{print $1}')"
  remote_sha="$(remote_run "sha256sum '$REMOTE_DIR/destination.bin'" | awk '{print $1}')"
  [[ "$local_sha" == "$remote_sha" ]] || die 'independent SHA-256 comparison failed'

  jq -n --argjson sender "$sender" --argjson receiver "$receiver" \
    --arg sha256 "$local_sha" --arg remote_mode "$([[ "$REMOTE" == local ]] && printf local || printf ssh)" \
    '{ok:true,kind:"remote_acceptance",remote_mode:$remote_mode,bytes:$sender.bytes,digest:$sender.digest,sha256:$sha256,migration:$sender.migration,receiver_commit:$receiver.ok}' \
    | tee "$ARTIFACT_DIR/result.json"
}

main "$@"
