#!/usr/bin/env bash
set -Eeuo pipefail

# Reproducible, destructive-only-to-self kernel assay for relay/direct path
# migration. Every resource is uniquely named and removed by the EXIT trap.

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly RIFT_BIN="${RIFT_BIN:-$ROOT_DIR/target/release/rift}"
readonly ARTIFACT_DIR="${1:-$ROOT_DIR/target/nat-matrix}"
readonly RUN_ID="${RIFT_MATRIX_RUN_ID:-$$}"
readonly PREFIX="riftlab-${RUN_ID}"
readonly NS_RELAY="${PREFIX}-relay"
readonly NS_NAT_A="${PREFIX}-nata"
readonly NS_NAT_B="${PREFIX}-natb"
readonly NS_PEER_A="${PREFIX}-peera"
readonly NS_PEER_B="${PREFIX}-peerb"
readonly PORT="${RIFT_MATRIX_PORT:-17337}"
readonly DIRECT_PORT_BASE="${RIFT_MATRIX_DIRECT_PORT:-20337}"
DIRECT_PORT="$DIRECT_PORT_BASE"
readonly SIZE_MIB="${RIFT_MATRIX_SIZE_MIB:-32}"
readonly DIRECT_RELAY_RATE="${RIFT_MATRIX_DIRECT_RELAY_RATE:-500kbit}"
readonly DIRECT_LOSS_EVERY="${RIFT_MATRIX_LOSS_EVERY:-100}"
readonly TRANSFER_TIMEOUT_SECONDS="${RIFT_MATRIX_TRANSFER_TIMEOUT_SECONDS:-600}"
readonly VETH_TAG="$((RUN_ID % 10000))"
readonly CA_CERT="$ARTIFACT_DIR/pki/ca.crt"
readonly SERVER_CERT="$ARTIFACT_DIR/pki/relay.crt"
readonly SERVER_KEY="$ARTIFACT_DIR/pki/relay.key"

RELAY_PID=""
SENDER_PID=""
RECEIVER_PID=""
TCPDUMP_PID=""
FAULT_PID=""
INJECT_DIRECT_FAILURE=0
INJECT_DIRECT_LOSS=0

die() {
  printf 'nat-matrix: %s\n' "$*" >&2
  exit 1
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

wait_for_transfer() {
  local pid="$1"
  local role="$2"
  local scenario="$3"
  local direction="$4"
  local deadline="$((SECONDS + TRANSFER_TIMEOUT_SECONDS))"
  while kill -0 "$pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      kill_if_live "$pid"
      die "${role} exceeded the bounded transfer deadline for ${scenario}/${direction}"
    fi
    sleep 0.1
  done
  wait "$pid" || die "${role} failed for ${scenario}/${direction}"
}

cleanup() {
  set +e
  kill_if_live "$RECEIVER_PID"
  kill_if_live "$SENDER_PID"
  kill_if_live "$RELAY_PID"
  kill_if_live "$TCPDUMP_PID"
  kill_if_live "$FAULT_PID"
  for namespace in "$NS_PEER_A" "$NS_PEER_B" "$NS_NAT_A" "$NS_NAT_B" "$NS_RELAY"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

wait_for_json_kind() {
  local file="$1"
  local kind="$2"
  local owner_pid="$3"
  local attempts="${4:-100}"
  for ((attempt = 0; attempt < attempts; attempt++)); do
    if [[ -s "$file" ]] \
      && grep -Fq "\"kind\":\"${kind}\"" "$file" \
      && jq -e --arg kind "$kind" 'select(.kind == $kind)' "$file" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$owner_pid" 2>/dev/null; then
      wait "$owner_pid" 2>/dev/null || true
      return 1
    fi
    sleep 0.1
  done
  return 1
}

ns() {
  local namespace="$1"
  shift
  ip netns exec "$namespace" "$@"
}

add_link() {
  local left_ns="$1"
  local left_name="$2"
  local left_addr="$3"
  local right_ns="$4"
  local right_name="$5"
  local right_addr="$6"
  local index="$7"
  local host_left="rl${VETH_TAG}${index}a"
  local host_right="rl${VETH_TAG}${index}b"

  ip link add "$host_left" type veth peer name "$host_right"
  ip link set "$host_left" netns "$left_ns"
  ip link set "$host_right" netns "$right_ns"
  ns "$left_ns" ip link set "$host_left" name "$left_name"
  ns "$right_ns" ip link set "$host_right" name "$right_name"
  ns "$left_ns" ip addr add "$left_addr" dev "$left_name"
  ns "$right_ns" ip addr add "$right_addr" dev "$right_name"
  ns "$left_ns" ip link set "$left_name" up
  ns "$right_ns" ip link set "$right_name" up
}

make_pki() {
  mkdir -p "$ARTIFACT_DIR/pki"
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=RIFT kernel matrix CA' \
    -keyout "$ARTIFACT_DIR/pki/ca.key" -out "$ARTIFACT_DIR/pki/ca.csr" >/dev/null 2>&1
  printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid:always' > "$ARTIFACT_DIR/pki/ca.ext"
  openssl x509 -req -days 2 -sha256 \
    -in "$ARTIFACT_DIR/pki/ca.csr" -signkey "$ARTIFACT_DIR/pki/ca.key" \
    -extfile "$ARTIFACT_DIR/pki/ca.ext" -out "$CA_CERT" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=rift-matrix-relay' \
    -keyout "$SERVER_KEY" -out "$ARTIFACT_DIR/pki/relay.csr" >/dev/null 2>&1
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=IP:10.240.1.1' \
    'authorityKeyIdentifier=keyid:always' > "$ARTIFACT_DIR/pki/relay.ext"
  openssl x509 -req -days 2 -sha256 \
    -in "$ARTIFACT_DIR/pki/relay.csr" \
    -CA "$CA_CERT" -CAkey "$ARTIFACT_DIR/pki/ca.key" -CAcreateserial \
    -extfile "$ARTIFACT_DIR/pki/relay.ext" -out "$SERVER_CERT" >/dev/null 2>&1
  chmod 600 "$ARTIFACT_DIR/pki/ca.key" "$SERVER_KEY"
}

make_topology() {
  for namespace in "$NS_RELAY" "$NS_NAT_A" "$NS_NAT_B" "$NS_PEER_A" "$NS_PEER_B"; do
    ip netns add "$namespace"
    ns "$namespace" ip link set lo up
  done

  add_link "$NS_RELAY" ra 10.240.1.1/30 "$NS_NAT_A" wan 10.240.1.2/30 1
  add_link "$NS_RELAY" rb 10.240.2.1/30 "$NS_NAT_B" wan 10.240.2.2/30 2
  add_link "$NS_NAT_A" lan 10.241.1.1/30 "$NS_PEER_A" eth0 10.241.1.2/30 3
  add_link "$NS_NAT_B" lan 10.241.2.1/30 "$NS_PEER_B" eth0 10.241.2.2/30 4

  # Traffic control must see real MTU-sized packets. Leaving veth GSO/TSO
  # enabled lets a >64 KiB aggregate reach a small token bucket; such a packet
  # can never fit and turns a rate intervention into an accidental black hole.
  for endpoint in \
    "$NS_RELAY:ra" "$NS_RELAY:rb" \
    "$NS_NAT_A:wan" "$NS_NAT_A:lan" \
    "$NS_NAT_B:wan" "$NS_NAT_B:lan" \
    "$NS_PEER_A:eth0" "$NS_PEER_B:eth0"; do
    local namespace="${endpoint%%:*}"
    local device="${endpoint##*:}"
    ns "$namespace" ethtool -K "$device" tso off gso off gro off
  done

  ns "$NS_RELAY" sysctl -qw net.ipv4.ip_forward=1
  for nat in "$NS_NAT_A" "$NS_NAT_B"; do
    ns "$nat" sysctl -qw net.ipv4.ip_forward=1
    ns "$nat" iptables -P FORWARD DROP
    ns "$nat" iptables -N RIFT_SCENARIO
    ns "$nat" iptables -A FORWARD -j RIFT_SCENARIO
    ns "$nat" iptables -A FORWARD -i lan -o wan -j ACCEPT
    ns "$nat" iptables -A FORWARD -i wan -o lan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done
  set_nat_mode endpoint-independent
  ns "$NS_NAT_A" ip route add default via 10.240.1.1
  ns "$NS_NAT_B" ip route add default via 10.240.2.1
  ns "$NS_PEER_A" ip route add default via 10.241.1.1
  ns "$NS_PEER_B" ip route add default via 10.241.2.1

  ns "$NS_PEER_A" ping -c 1 -W 1 10.240.1.1 >/dev/null
  ns "$NS_PEER_B" ping -c 1 -W 1 10.240.1.1 >/dev/null
}

set_nat_mode() {
  local mode="$1"
  ns "$NS_NAT_A" iptables -F RIFT_SCENARIO
  ns "$NS_NAT_B" iptables -F RIFT_SCENARIO
  ns "$NS_NAT_A" iptables -t nat -F PREROUTING
  ns "$NS_NAT_B" iptables -t nat -F PREROUTING
  ns "$NS_NAT_A" iptables -t nat -F POSTROUTING
  ns "$NS_NAT_B" iptables -t nat -F POSTROUTING
  case "$mode" in
    endpoint-independent)
      ns "$NS_NAT_A" iptables -t nat -A POSTROUTING -o wan -p udp \
        --sport "$DIRECT_PORT" -j SNAT --to-source "10.240.1.2:${DIRECT_PORT}"
      ns "$NS_NAT_B" iptables -t nat -A POSTROUTING -o wan -p udp \
        --sport "$DIRECT_PORT" -j SNAT --to-source "10.240.2.2:${DIRECT_PORT}"
      ns "$NS_NAT_A" iptables -t nat -A POSTROUTING -o wan -j SNAT --to-source 10.240.1.2
      ns "$NS_NAT_B" iptables -t nat -A POSTROUTING -o wan -j SNAT --to-source 10.240.2.2
      ns "$NS_NAT_A" iptables -t nat -A PREROUTING -i wan -p udp \
        --dport "$DIRECT_PORT" -j DNAT --to-destination "10.241.1.2:${DIRECT_PORT}"
      ns "$NS_NAT_B" iptables -t nat -A PREROUTING -i wan -p udp \
        --dport "$DIRECT_PORT" -j DNAT --to-destination "10.241.2.2:${DIRECT_PORT}"
      ns "$NS_NAT_A" iptables -A RIFT_SCENARIO -i wan -o lan -p udp \
        -d 10.241.1.2 --dport "$DIRECT_PORT" -j ACCEPT
      ns "$NS_NAT_B" iptables -A RIFT_SCENARIO -i wan -o lan -p udp \
        -d 10.241.2.2 --dport "$DIRECT_PORT" -j ACCEPT
      ;;
    endpoint-dependent)
      ns "$NS_NAT_A" iptables -t nat -A POSTROUTING -o wan -p udp \
        -d 10.240.1.1 --dport "$PORT" -j SNAT --to-source 10.240.1.2:21001
      ns "$NS_NAT_B" iptables -t nat -A POSTROUTING -o wan -p udp \
        -d 10.240.1.1 --dport "$PORT" -j SNAT --to-source 10.240.2.2:21002
      ns "$NS_NAT_A" iptables -t nat -A POSTROUTING -o wan -p udp \
        -j SNAT --to-source 10.240.1.2:22001
      ns "$NS_NAT_B" iptables -t nat -A POSTROUTING -o wan -p udp \
        -j SNAT --to-source 10.240.2.2:22002
      ns "$NS_NAT_A" iptables -t nat -A POSTROUTING -o wan -j SNAT --to-source 10.240.1.2
      ns "$NS_NAT_B" iptables -t nat -A POSTROUTING -o wan -j SNAT --to-source 10.240.2.2
      for nat in "$NS_NAT_A" "$NS_NAT_B"; do
        ns "$nat" iptables -A RIFT_SCENARIO -i wan -o lan -p udp \
          -s 10.240.1.1 --sport "$PORT" -j ACCEPT
        ns "$nat" iptables -A RIFT_SCENARIO -i wan -o lan -p udp -j DROP
      done
      ;;
    *) die "unknown NAT mode: $mode" ;;
  esac
}

clear_faults() {
  for nat in "$NS_NAT_A" "$NS_NAT_B"; do
    ns "$nat" tc qdisc del dev wan root 2>/dev/null || true
    ns "$nat" iptables -F RIFT_SCENARIO
  done
  ns "$NS_RELAY" tc qdisc del dev ra root 2>/dev/null || true
  ns "$NS_RELAY" tc qdisc del dev rb root 2>/dev/null || true
}

shape_protocol() {
  local protocol="$1"
  local delay_ms="$2"
  local rate="${3:-}"
  for nat in "$NS_NAT_A" "$NS_NAT_B"; do
    ns "$nat" tc qdisc add dev wan root handle 1: prio bands 3
    if [[ -n "$rate" ]]; then
      ns "$nat" tc qdisc add dev wan parent 1:3 handle 30: netem \
        limit 10000 delay "${delay_ms}ms" rate "$rate"
    else
      ns "$nat" tc qdisc add dev wan parent 1:3 handle 30: netem delay "${delay_ms}ms"
    fi
    ns "$nat" tc filter add dev wan protocol ip parent 1:0 prio 1 u32 \
      match ip protocol "$protocol" 0xff flowid 1:3
  done
}

shape_relay_preferred() {
  for nat in "$NS_NAT_A" "$NS_NAT_B"; do
    ns "$nat" tc qdisc add dev wan root handle 1: prio bands 3
    ns "$nat" tc qdisc add dev wan parent 1:2 handle 20: netem \
      limit 10000 delay 25ms rate 20mbit
    ns "$nat" tc qdisc add dev wan parent 1:3 handle 30: netem delay 150ms
    ns "$nat" tc filter add dev wan protocol ip parent 1:0 prio 1 u32 \
      match ip protocol 6 0xff flowid 1:2
    ns "$nat" tc filter add dev wan protocol ip parent 1:0 prio 2 u32 \
      match ip protocol 17 0xff flowid 1:3
  done
}

shape_relay_egress_rate() {
  local rate="$1"
  for device in ra rb; do
    ns "$NS_RELAY" tc qdisc add dev "$device" root handle 1: prio bands 3
    ns "$NS_RELAY" tc qdisc add dev "$device" parent 1:3 handle 30: \
      tbf rate "$rate" burst 4kb latency 5s
    ns "$NS_RELAY" tc filter add dev "$device" protocol ip parent 1:0 prio 1 u32 \
      match ip protocol 6 0xff flowid 1:3
  done
}

apply_scenario() {
  local scenario="$1"
  INJECT_DIRECT_FAILURE=0
  INJECT_DIRECT_LOSS=0
  clear_faults
  set_nat_mode endpoint-independent
  case "$scenario" in
    clean) ;;
    direct-preferred) shape_relay_egress_rate "$DIRECT_RELAY_RATE" ;;
    direct-fallback)
      shape_relay_egress_rate "$DIRECT_RELAY_RATE"
      INJECT_DIRECT_FAILURE=1
      ;;
    direct-lossy)
      shape_relay_egress_rate "$DIRECT_RELAY_RATE"
      INJECT_DIRECT_LOSS=1
      ;;
    relay-preferred) shape_relay_preferred ;;
    symmetric-nat) set_nat_mode endpoint-dependent ;;
    udp-blocked)
      ns "$NS_NAT_A" iptables -I RIFT_SCENARIO 1 -p udp -j DROP
      ns "$NS_NAT_B" iptables -I RIFT_SCENARIO 1 -p udp -j DROP
      ;;
    *) die "unknown scenario: $scenario" ;;
  esac
}

capture_potency() {
  local run_dir="$1"
  for side in a b; do
    local nat="$NS_NAT_A"
    [[ "$side" == b ]] && nat="$NS_NAT_B"
    ns "$nat" iptables -t nat -L POSTROUTING -n -v -x > "$run_dir/nat-${side}.txt"
    ns "$nat" iptables -t nat -L PREROUTING -n -v -x > "$run_dir/dnat-${side}.txt"
    ns "$nat" iptables -L FORWARD -n -v -x > "$run_dir/forward-${side}.txt"
    ns "$nat" iptables -L RIFT_SCENARIO -n -v -x > "$run_dir/scenario-${side}.txt"
    ns "$nat" tc -s qdisc show dev wan > "$run_dir/tc-${side}.txt"
    ns "$nat" ethtool -k wan > "$run_dir/offload-${side}.txt"
  done
  ns "$NS_RELAY" tc -s qdisc show dev ra > "$run_dir/tc-relay-a.txt"
  ns "$NS_RELAY" tc -s qdisc show dev rb > "$run_dir/tc-relay-b.txt"
}

exercise_symmetric_nat_potency() {
  local run_dir="$1"
  printf x | ns "$NS_PEER_A" socat - \
    "UDP-DATAGRAM:10.240.2.2:9,sourceport=${DIRECT_PORT}" \
    > "$run_dir/potency-a.stdout" 2> "$run_dir/potency-a.stderr"
  printf x | ns "$NS_PEER_B" socat - \
    "UDP-DATAGRAM:10.240.1.2:9,sourceport=${DIRECT_PORT}" \
    > "$run_dir/potency-b.stdout" 2> "$run_dir/potency-b.stderr"
}

run_transfer() {
  local scenario="$1"
  local direction="$2"
  local sender_ns="$NS_PEER_A"
  local receiver_ns="$NS_PEER_B"
  [[ "$direction" == b-to-a ]] && sender_ns="$NS_PEER_B" && receiver_ns="$NS_PEER_A"

  local run_dir="$ARTIFACT_DIR/runs/${scenario}-${direction}"
  local source="$run_dir/source.bin"
  local destination="$run_dir/destination.bin"
  local completion_started_ns completion_finished_ns completion_ns
  mkdir -p "$run_dir"
  dd if=/dev/urandom of="$source" bs=1M count="$SIZE_MIB" status=none
  rm -f "$destination"

  if [[ "${RIFT_MATRIX_PCAP:-0}" == 1 ]]; then
    if [[ "${RIFT_MATRIX_PCAP_FILTER:-udp}" == all ]]; then
      ip netns exec "$NS_RELAY" tcpdump -U -i any -n -w "$run_dir/traffic.pcap" \
        > "$run_dir/tcpdump.stdout" 2> "$run_dir/tcpdump.stderr" &
    else
      ip netns exec "$NS_RELAY" tcpdump -U -i any -n -w "$run_dir/traffic.pcap" \
        "${RIFT_MATRIX_PCAP_FILTER:-udp}" \
        > "$run_dir/tcpdump.stdout" 2> "$run_dir/tcpdump.stderr" &
    fi
    TCPDUMP_PID=$!
  fi

  ip netns exec "$NS_RELAY" "$RIFT_BIN" --json relay \
    --listen "10.240.1.1:${PORT}" \
    --tls-cert "$SERVER_CERT" --tls-key "$SERVER_KEY" \
    > "$run_dir/relay.jsonl" 2> "$run_dir/relay.stderr" &
  RELAY_PID=$!
  wait_for_json_kind "$run_dir/relay.jsonl" relay_ready "$RELAY_PID" 100 || \
    die "relay did not become ready for ${scenario}/${direction}"

  if [[ "${RIFT_MATRIX_PROFILE:-0}" == 1 ]]; then
    ip netns exec "$sender_ns" perf stat -x, -o "$run_dir/sender.perf.csv" \
      -e task-clock,cycles,instructions,cache-misses,context-switches,page-faults -- \
      /usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nvoluntary_switches=%w\ninvoluntary_switches=%c' \
      -o "$run_dir/sender.time" env RIFT_PATH_TRACE=1 \
      "$RIFT_BIN" --json send "$source" \
      --relay "wss://10.240.1.1:${PORT}/rift/v1" --ca-cert "$CA_CERT" \
      --direct-port "$DIRECT_PORT" \
      > "$run_dir/sender.jsonl" 2> "$run_dir/sender.stderr" &
  else
    ip netns exec "$sender_ns" env RIFT_PATH_TRACE=1 "$RIFT_BIN" --json send "$source" \
      --relay "wss://10.240.1.1:${PORT}/rift/v1" --ca-cert "$CA_CERT" \
      --direct-port "$DIRECT_PORT" \
      > "$run_dir/sender.jsonl" 2> "$run_dir/sender.stderr" &
  fi
  SENDER_PID=$!
  wait_for_json_kind "$run_dir/sender.jsonl" offer "$SENDER_PID" 100 || \
    die "sender did not reserve a code for ${scenario}/${direction}"
  local code
  code="$(jq -r 'select(.kind == "offer") | .code' "$run_dir/sender.jsonl" | tail -1)"
  [[ -n "$code" && "$code" != null ]] || die "sender emitted no pairing code"

  completion_started_ns="$(date +%s%N)"
  if [[ "${RIFT_MATRIX_PROFILE:-0}" == 1 ]]; then
    ip netns exec "$receiver_ns" perf stat -x, -o "$run_dir/receiver.perf.csv" \
      -e task-clock,cycles,instructions,cache-misses,context-switches,page-faults -- \
      /usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nvoluntary_switches=%w\ninvoluntary_switches=%c' \
      -o "$run_dir/receiver.time" "$RIFT_BIN" --json receive "$code" "$destination" \
      --relay "wss://10.240.1.1:${PORT}/rift/v1" --ca-cert "$CA_CERT" \
      --direct-port "$DIRECT_PORT" \
      > "$run_dir/receiver.jsonl" 2> "$run_dir/receiver.stderr" &
  else
    ip netns exec "$receiver_ns" "$RIFT_BIN" --json receive "$code" "$destination" \
      --relay "wss://10.240.1.1:${PORT}/rift/v1" --ca-cert "$CA_CERT" \
      --direct-port "$DIRECT_PORT" \
      > "$run_dir/receiver.jsonl" 2> "$run_dir/receiver.stderr" &
  fi
  RECEIVER_PID=$!

  if [[ "$INJECT_DIRECT_FAILURE" == 1 || "$INJECT_DIRECT_LOSS" == 1 ]]; then
    (
      while kill -0 "$SENDER_PID" 2>/dev/null; do
        if grep -Fq 'event=first_direct_record_acked' "$run_dir/sender.stderr"; then
          if [[ "$INJECT_DIRECT_FAILURE" == 1 ]]; then
            ns "$NS_NAT_A" iptables -w 2 -I RIFT_SCENARIO 1 -p udp -j DROP
            ns "$NS_NAT_B" iptables -w 2 -I RIFT_SCENARIO 1 -p udp -j DROP
            ns "$NS_RELAY" tc qdisc del dev ra root 2>/dev/null || true
            ns "$NS_RELAY" tc qdisc del dev rb root 2>/dev/null || true
          else
            # A deterministic packet loss process begins only after direct
            # delivery is proven live, so acquisition/trial potency is not
            # conflated with record recovery.
            ns "$NS_NAT_A" iptables -w 2 -I RIFT_SCENARIO 1 -p udp \
              -m statistic --mode nth --every "$DIRECT_LOSS_EVERY" --packet 0 -j DROP
            ns "$NS_NAT_B" iptables -w 2 -I RIFT_SCENARIO 1 -p udp \
              -m statistic --mode nth --every "$DIRECT_LOSS_EVERY" --packet 0 -j DROP
          fi
          : > "$run_dir/fault-injected"
          exit 0
        fi
        sleep 0.05
      done
      printf 'sender exited before the direct path became active\n' >&2
      exit 1
    ) > "$run_dir/fault.stdout" 2> "$run_dir/fault.stderr" &
    FAULT_PID=$!
  fi

  wait_for_transfer "$RECEIVER_PID" receiver "$scenario" "$direction"
  RECEIVER_PID=""
  completion_finished_ns="$(date +%s%N)"
  completion_ns="$((completion_finished_ns - completion_started_ns))"
  wait_for_transfer "$SENDER_PID" sender "$scenario" "$direction"
  SENDER_PID=""
  wait "$RELAY_PID" || die "relay failed for ${scenario}/${direction}"
  RELAY_PID=""
  kill_if_live "$FAULT_PID"
  FAULT_PID=""
  if [[ ("$INJECT_DIRECT_FAILURE" == 1 || "$INJECT_DIRECT_LOSS" == 1) \
    && ! -f "$run_dir/fault-injected" ]]; then
    die "direct fault was not injected for ${scenario}/${direction}"
  fi
  kill_if_live "$TCPDUMP_PID"
  TCPDUMP_PID=""

  cmp -s "$source" "$destination" || die "byte mismatch for ${scenario}/${direction}"
  local sender_digest receiver_digest
  sender_digest="$(jq -r 'select(.kind == "send_complete") | .digest' "$run_dir/sender.jsonl")"
  receiver_digest="$(jq -r 'select(.kind == "receive_complete") | .digest' "$run_dir/receiver.jsonl")"
  [[ -n "$sender_digest" && "$sender_digest" == "$receiver_digest" ]] || \
    die "authenticated digest mismatch for ${scenario}/${direction}"

  if [[ "$scenario" == symmetric-nat ]]; then
    exercise_symmetric_nat_potency "$run_dir"
  fi
  capture_potency "$run_dir"
  jq -n \
    --arg scenario "$scenario" --arg direction "$direction" \
    --argjson direct_port "$DIRECT_PORT" \
    --argjson completion_ns "$completion_ns" \
    --argjson sender "$(jq -c 'select(.kind == "send_complete")' "$run_dir/sender.jsonl")" \
    --argjson receiver "$(jq -c 'select(.kind == "receive_complete")' "$run_dir/receiver.jsonl")" \
    --argjson relay "$(jq -c 'select(.kind == "relay_complete")' "$run_dir/relay.jsonl")" \
    '{scenario:$scenario,direction:$direction,direct_port:$direct_port,completion_ns:$completion_ns,exact:true,sender:$sender,receiver:$receiver,relay:$relay}' \
    > "$run_dir/result.json"
}

assert_matrix() {
  local results="$ARTIFACT_DIR/results.json"
  jq -s '.' "$ARTIFACT_DIR"/runs/*/result.json > "$results"
  jq -e '
    length == 14 and
    ([.[].scenario] | unique) == ["clean", "direct-fallback", "direct-lossy", "direct-preferred", "relay-preferred", "symmetric-nat", "udp-blocked"] and
    all(group_by(.scenario)[]; ([.[].direction] | sort) == ["a-to-b", "b-to-a"])
  ' "$results" >/dev/null || die 'full matrix is missing a scenario or direction'
  jq -e 'all(.[]; .exact == true and .sender.bytes == .receiver.bytes and .sender.digest == .receiver.digest)' \
    "$results" >/dev/null || die 'exactness invariant failed'
  jq -e 'all(.[] | select(.scenario == "direct-preferred"); .sender.migration.direct_records > 0 and .sender.migration.first_direct_sequence >= 2 and .sender.migration.direct_max_datagram_bytes >= 1200 and .sender.migration.direct_max_datagram_bytes <= 1452 and .sender.migration.direct_smoothed_rtt_us > 0 and .sender.migration.direct_rto_us >= .sender.migration.direct_smoothed_rtt_us and .sender.migration.direct_send_batches > 0 and .sender.migration.direct_native_send_batches > 0 and .sender.migration.direct_gso_batches > 0 and .sender.migration.direct_gso_demotions == 0 and .relay.bytes < (.sender.bytes / 2))' \
    "$results" >/dev/null || die 'direct-preferred positive control did not migrate'
  jq -e 'all(.[] | select(.scenario == "direct-fallback"); .sender.migration.direct_records > 0 and .sender.migration.fallback_events > 0 and .sender.migration.relay_records > 0)' \
    "$results" >/dev/null || die 'direct-fallback control did not recover on relay'
  jq -e 'all(.[] | select(.scenario == "direct-lossy"); .sender.migration.direct_records > 0 and .sender.migration.fallback_events == 0 and .sender.migration.direct_max_datagram_bytes >= 1200 and .sender.migration.direct_max_datagram_bytes <= 1452 and .sender.migration.direct_smoothed_rtt_us > 0 and .sender.migration.direct_rto_us >= .sender.migration.direct_smoothed_rtt_us and .sender.migration.direct_send_batches > 0 and .sender.migration.direct_native_send_batches > 0 and .sender.migration.direct_gso_batches > 0 and .sender.migration.direct_gso_demotions == 1 and ((.sender.migration.direct_retransmitted_fragments + .sender.migration.direct_repair_symbols) > 0) and ((.sender.migration.direct_fast_retransmits + .sender.migration.direct_tail_probes + .sender.migration.direct_repair_symbols) > 0))' \
    "$results" >/dev/null || die 'direct-lossy control did not recover before relay fallback'
  jq -e 'all(.[] | select(.scenario == "relay-preferred"); .sender.migration.direct_records == 0 and .sender.migration.direct_goodput_floor_bps != null)' \
    "$results" >/dev/null || die 'relay-preferred control did not validate and reject direct'
  jq -e 'all(.[] | select(.scenario == "symmetric-nat"); .sender.migration.direct_records == 0 and .sender.migration.direct_goodput_floor_bps == null)' \
    "$results" >/dev/null || die 'symmetric NAT negative control unexpectedly acquired direct'
  jq -e 'all(.[] | select(.scenario == "udp-blocked"); .sender.migration.direct_records == 0 and .sender.migration.direct_goodput_floor_bps == null)' \
    "$results" >/dev/null || die 'UDP-blocked negative control unexpectedly acquired direct'

  for run_dir in "$ARTIFACT_DIR"/runs/symmetric-nat-*; do
    if ! {
      grep -Eq '^[[:space:]]*[1-9][0-9]*[[:space:]]+[0-9]+[[:space:]]+SNAT.*:21001' "$run_dir/nat-a.txt" &&
      grep -Eq '^[[:space:]]*[1-9][0-9]*[[:space:]]+[0-9]+[[:space:]]+SNAT.*:22001' "$run_dir/nat-a.txt" &&
      grep -Eq '^[[:space:]]*[1-9][0-9]*[[:space:]]+[0-9]+[[:space:]]+SNAT.*:21002' "$run_dir/nat-b.txt" &&
        grep -Eq '^[[:space:]]*[1-9][0-9]*[[:space:]]+[0-9]+[[:space:]]+SNAT.*:22002' "$run_dir/nat-b.txt"
    }; then
      die "symmetric NAT potency failed in $run_dir"
    fi
  done
  for run_dir in "$ARTIFACT_DIR"/runs/udp-blocked-*; do
    if ! {
      awk '$3 == "DROP" && $1 + 0 > 0 { hit = 1 } END { exit !hit }' "$run_dir/scenario-a.txt" &&
        awk '$3 == "DROP" && $1 + 0 > 0 { hit = 1 } END { exit !hit }' "$run_dir/scenario-b.txt"
    }; then
      die "UDP-blocked potency failed in $run_dir"
    fi
  done
  for run_dir in "$ARTIFACT_DIR"/runs/direct-lossy-*; do
    if ! {
      awk '$3 == "DROP" && $1 + 0 > 0 { hit = 1 } END { exit !hit }' "$run_dir/scenario-a.txt" &&
        awk '$3 == "DROP" && $1 + 0 > 0 { hit = 1 } END { exit !hit }' "$run_dir/scenario-b.txt"
    }; then
      die "direct-lossy potency failed in $run_dir"
    fi
  done
}

main() {
  [[ "$(id -u)" == 0 ]] || die 'must run as root for disposable network namespaces'
  for command in ip iptables tc ethtool jq openssl dd cmp ping socat sysctl date; do need "$command"; done
  if [[ "${RIFT_MATRIX_PROFILE:-0}" == 1 ]]; then
    need perf
    [[ -x /usr/bin/time ]] || die 'GNU time is required for profiling'
  fi
  [[ -x "$RIFT_BIN" ]] || die "release binary not found: $RIFT_BIN"
  (( DIRECT_LOSS_EVERY >= 2 && DIRECT_LOSS_EVERY <= 10000 )) || \
    die 'direct loss interval must be between 2 and 10000 packets'
  (( TRANSFER_TIMEOUT_SECONDS >= 10 && TRANSFER_TIMEOUT_SECONDS <= 3600 )) || \
    die 'transfer deadline must be between 10 and 3600 seconds'
  (( DIRECT_PORT_BASE > 0 && DIRECT_PORT_BASE <= 65521 )) || \
    die 'base direct port must leave room for the 14 isolated matrix transfers'
  [[ ! -e "$ARTIFACT_DIR" ]] || die "artifact directory already exists: $ARTIFACT_DIR"
  mkdir -p "$ARTIFACT_DIR/runs"
  make_pki
  make_topology

  local transfer_index=0
  for scenario in ${RIFT_MATRIX_SCENARIOS:-clean direct-preferred direct-lossy direct-fallback relay-preferred symmetric-nat udp-blocked}; do
    for direction in ${RIFT_MATRIX_DIRECTIONS:-a-to-b b-to-a}; do
      DIRECT_PORT="$((DIRECT_PORT_BASE + transfer_index))"
      transfer_index="$((transfer_index + 1))"
      apply_scenario "$scenario"
      run_transfer "$scenario" "$direction"
    done
  done
  clear_faults
  if [[ "${RIFT_MATRIX_ASSERT_FULL:-1}" == 1 ]]; then
    assert_matrix
  else
    jq -s '.' "$ARTIFACT_DIR"/runs/*/result.json > "$ARTIFACT_DIR/results.json"
  fi
  printf '%s\n' "$ARTIFACT_DIR/results.json"
}

main "$@"
