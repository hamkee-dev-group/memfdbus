#!/usr/bin/env sh
set -eu

bin=${1:-./build/memfdbus}
cc=${CC:-cc}
cflags=${CFLAGS:--std=c11 -Wall -Wextra -Wpedantic -O2}
ldflags=${LDFLAGS:-}
tmp=$(mktemp -d)
sock="$tmp/memfdbus.sock"
broker_log="$tmp/broker.log"

cleanup() {
    stop_broker
    rm -rf "$tmp"
}

stop_broker() {
    if [ "${broker_pid:-}" ]; then
        kill "$broker_pid" 2>/dev/null || true
        wait "$broker_pid" 2>/dev/null || true
        broker_pid=
    fi
}

wait_for_socket() {
    wait_sock=$1
    wait_log=$2
    i=0
    while [ ! -S "$wait_sock" ]; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then
            cat "$wait_log" >&2 || true
            echo "broker did not create socket" >&2
            exit 1
        fi
        sleep 0.05
    done
}

start_broker() {
    start_sock=$1
    start_log=$2
    shift 2
    "$bin" broker --socket "$start_sock" "$@" >"$start_log" 2>&1 &
    broker_pid=$!
    wait_for_socket "$start_sock" "$start_log"
}

trap cleanup EXIT INT TERM

start_broker "$sock" "$broker_log"

payload="$tmp/payload.bin"
payload_v2="$tmp/payload-v2.bin"
copy="$tmp/copy.bin"
inspect_fd="$tmp/inspect_fd"
held_fd="$tmp/held_fd"
api_smoke="$tmp/api_smoke"
digest_mismatch="$tmp/digest_mismatch"
"$cc" $cflags -o "$inspect_fd" tests/inspect_fd.c $ldflags
"$cc" $cflags -o "$held_fd" tests/held_fd.c $ldflags
"$cc" $cflags -Iinclude -o "$api_smoke" tests/api_smoke.c build/libmemfdbus.a $ldflags
"$cc" $cflags -Isrc -o "$digest_mismatch" tests/digest_mismatch.c src/sha256.c $ldflags
python3 - "$payload" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
chunk = bytes(range(256)) * 4096
path.write_bytes(chunk + b"memfdbus\n")
PY
python3 - "$payload_v2" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_bytes((b"replacement-payload\n" * 8192) + b"memfdbus-v2\n")
PY

id=$("$bin" put "$payload" --name smoke-object --socket "$sock")
case "$id" in
    ''|*[!0-9]*) echo "put returned non-numeric id: $id" >&2; exit 1 ;;
esac

"$bin" get "$id" "$copy" --socket "$sock"
cmp "$payload" "$copy"

stdin_id=$("$bin" put - --name stdin-object --socket "$sock" < "$payload")
case "$stdin_id" in
    ''|*[!0-9]*) echo "put from stdin returned non-numeric id: $stdin_id" >&2; exit 1 ;;
esac
stdin_copy="$tmp/stdin-copy.bin"
"$bin" get --name stdin-object - --socket "$sock" > "$stdin_copy"
cmp "$payload" "$stdin_copy"

long_name=$(python3 - <<'PY'
print("x" * 65537)
PY
)
if "$bin" get --name "$long_name" "$tmp/too-long.bin" --socket "$sock" 2>"$tmp/too-long.err"; then
    echo "get --name unexpectedly accepted an oversized name" >&2
    exit 1
fi
grep -F "object name too long" "$tmp/too-long.err" >/dev/null

exec_copy="$tmp/exec-copy.bin"
"$bin" exec "$id" --socket "$sock" -- sh -c '
    test "$MEMFDBUS_NAME" = smoke-object
    test "$MEMFDBUS_OBJECT_ID" = "$2"
    test "$MEMFDBUS_SIZE" = "$(wc -c < "$3")"
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_copy" "$id" "$payload"
cmp "$payload" "$exec_copy"

exec_copy_again="$tmp/exec-copy-again.bin"
"$bin" exec "$id" --socket "$sock" -- sh -c '
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_copy_again"
cmp "$payload" "$exec_copy_again"

"$bin" exec "$id" --socket "$sock" -- "$inspect_fd" "$payload"

"$api_smoke" "$sock" "$payload"

id_v2=$("$bin" put "$payload_v2" --name smoke-object --socket "$sock")
case "$id_v2" in
    ''|*[!0-9]*) echo "put returned non-numeric replacement id: $id_v2" >&2; exit 1 ;;
esac
test "$id_v2" != "$id"

latest_copy="$tmp/latest-copy.bin"
"$bin" get --name smoke-object "$latest_copy" --socket "$sock"
cmp "$payload_v2" "$latest_copy"

old_copy="$tmp/old-copy.bin"
"$bin" get "$id" "$old_copy" --socket "$sock"
cmp "$payload" "$old_copy"

exec_latest="$tmp/exec-latest.bin"
"$bin" exec --name smoke-object --socket "$sock" -- sh -c '
    test "$MEMFDBUS_NAME" = smoke-object
    test "$MEMFDBUS_OBJECT_ID" = "$2"
    test "$MEMFDBUS_SIZE" = "$(wc -c < "$3")"
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_latest" "$id_v2" "$payload_v2"
cmp "$payload_v2" "$exec_latest"

"$bin" list --socket "$sock" >"$tmp/list.txt"
grep -F "$id" "$tmp/list.txt" >/dev/null
grep -F "$stdin_id" "$tmp/list.txt" >/dev/null
grep -F "$id_v2" "$tmp/list.txt" >/dev/null
grep -F "smoke-object" "$tmp/list.txt" >/dev/null
grep -F "stdin-object" "$tmp/list.txt" >/dev/null
python3 - "$tmp/list.txt" "$id" "$stdin_id" "$id_v2" >"$tmp/list-digests.sh" <<'PY'
import pathlib
import re
import sys

digest_re = re.compile(r"^sha256:[0-9a-f]{64}$")
rows = {}
for lineno, line in enumerate(pathlib.Path(sys.argv[1]).read_text().splitlines(), 1):
    parts = line.split("\t")
    if len(parts) != 6:
        raise SystemExit(f"list line {lineno} did not have 6 tab-separated columns: {line!r}")
    object_id, owner, allowed, size_text, digest, name = parts
    if not object_id.isdigit() or not size_text.isdigit():
        raise SystemExit(f"list line {lineno} had a non-numeric id or size: {line!r}")
    if not owner.startswith("owner=") or not allowed.startswith("allowed="):
        raise SystemExit(f"list line {lineno} was missing owner/allowed tokens: {line!r}")
    if not digest_re.match(digest):
        raise SystemExit(f"list line {lineno} had an invalid digest: {line!r}")
    rows[int(object_id)] = (owner, allowed, int(size_text), digest, name)

id_v1 = int(sys.argv[2])
stdin_id = int(sys.argv[3])
id_v2 = int(sys.argv[4])

if rows[id_v1][0] != "owner=-" or rows[id_v1][1] != "allowed=-":
    raise SystemExit("unexpected owner/allowed tokens for public object")
if rows[id_v1][3] != rows[stdin_id][3]:
    raise SystemExit("same-content objects did not share the same digest")
if rows[id_v1][3] == rows[id_v2][3]:
    raise SystemExit("different-content object unexpectedly reused the same digest")

print(f"digest_v1={rows[id_v1][3]}")
print(f"digest_stdin={rows[stdin_id][3]}")
print(f"digest_v2={rows[id_v2][3]}")
PY
. "$tmp/list-digests.sh"

exec_digest_v1="$tmp/exec-digest-v1.bin"
"$bin" exec "$id" --socket "$sock" -- sh -c '
    test "$MEMFDBUS_DIGEST" = "$2"
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_digest_v1" "$digest_v1"
cmp "$payload" "$exec_digest_v1"

exec_digest_stdin="$tmp/exec-digest-stdin.bin"
"$bin" exec "$stdin_id" --socket "$sock" -- sh -c '
    test "$MEMFDBUS_DIGEST" = "$2"
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_digest_stdin" "$digest_stdin"
cmp "$payload" "$exec_digest_stdin"

exec_digest_v2="$tmp/exec-digest-v2.bin"
"$bin" exec "$id_v2" --socket "$sock" -- sh -c '
    test "$MEMFDBUS_DIGEST" = "$2"
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$exec_digest_v2" "$digest_v2"
cmp "$payload_v2" "$exec_digest_v2"

dropped_latest=$("$bin" drop --name smoke-object --socket "$sock")
test "$dropped_latest" = "$id_v2"

after_drop_latest="$tmp/after-drop-latest.bin"
"$bin" get --name smoke-object "$after_drop_latest" --socket "$sock"
cmp "$payload" "$after_drop_latest"

dropped_old=$("$bin" drop "$id" --socket "$sock")
test "$dropped_old" = "$id"
if "$bin" get "$id" "$tmp/missing.bin" --socket "$sock" 2>"$tmp/missing.err"; then
    echo "get unexpectedly succeeded after drop" >&2
    exit 1
fi
grep -F "object not found" "$tmp/missing.err" >/dev/null

if "$bin" get --name smoke-object "$tmp/missing-name.bin" --socket "$sock" 2>"$tmp/missing-name.err"; then
    echo "get --name unexpectedly succeeded after dropping all versions" >&2
    exit 1
fi
grep -F "object not found" "$tmp/missing-name.err" >/dev/null

stop_broker

payload_size=$(wc -c < "$payload")
payload_v2_size=$(wc -c < "$payload_v2")
python3 - "$broker_log" "$id" "$stdin_id" "$id_v2" "$dropped_latest" "$dropped_old" \
    "$payload_size" "$payload_v2_size" "$digest_v1" "$digest_stdin" "$digest_v2" <<'PY'
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
object_id = int(sys.argv[2])
stdin_id = int(sys.argv[3])
replacement_id = int(sys.argv[4])
dropped_latest = int(sys.argv[5])
dropped_old = int(sys.argv[6])
payload_size = int(sys.argv[7])
payload_v2_size = int(sys.argv[8])
digest_v1 = sys.argv[9]
digest_stdin = sys.argv[10]
digest_v2 = sys.argv[11]

records = []
for lineno, raw_line in enumerate(log_path.read_text().splitlines(), 1):
    line = raw_line.strip()
    if not line:
        continue
    if not line.startswith("{"):
        if line.startswith("memfdbus broker listening on "):
            continue
        raise SystemExit(f"unexpected non-JSON broker log line {lineno}: {line}")
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"malformed JSON audit line {lineno}: {exc}") from exc
    records.append(record)

if not records:
    raise SystemExit("broker log did not contain any JSON audit records")

def expect_type(record, key, expected_type, allow_none=False):
    value = record.get(key)
    if value is None:
        if allow_none:
            return
        raise SystemExit(f"record missing required field {key}: {record}")
    if isinstance(value, bool) or not isinstance(value, expected_type):
        raise SystemExit(f"record field {key} has wrong type: {record}")

for record in records:
    expect_type(record, "ts_ns", int)
    expect_type(record, "op", str)
    expect_type(record, "operation", str)
    expect_type(record, "result", str)
    if record["op"] != record["operation"]:
        raise SystemExit(f"op/operation mismatch: {record}")
    expect_type(record, "object_id", int, allow_none=True)
    expect_type(record, "name", str, allow_none=True)
    expect_type(record, "size", int, allow_none=True)
    expect_type(record, "count", int, allow_none=True)
    expect_type(record, "digest", str, allow_none=True)
    expect_type(record, "job_id", str, allow_none=True)
    expect_type(record, "selector", str, allow_none=True)
    expect_type(record, "error", str, allow_none=True)

def find_record(description, predicate):
    for record in records:
        if predicate(record):
            return record
    raise SystemExit(f"missing audit record: {description}")

find_record(
    "put ok for smoke-object v1",
    lambda r: r["op"] == "put" and r["result"] == "ok" and r["object_id"] == object_id
    and r["name"] == "smoke-object" and r["size"] == payload_size and r["digest"] == digest_v1
    and r["job_id"] is None,
)
find_record(
    "put ok for stdin-object",
    lambda r: r["op"] == "put" and r["result"] == "ok" and r["object_id"] == stdin_id
    and r["name"] == "stdin-object" and r["size"] == payload_size and r["digest"] == digest_stdin
    and r["job_id"] is None,
)
find_record(
    "put ok for smoke-object v2",
    lambda r: r["op"] == "put" and r["result"] == "ok" and r["object_id"] == replacement_id
    and r["name"] == "smoke-object" and r["size"] == payload_v2_size and r["digest"] == digest_v2
    and r["job_id"] is None,
)
find_record(
    "get ok by id",
    lambda r: r["op"] == "get" and r["result"] == "ok" and r["selector"] == "id"
    and r["object_id"] == object_id and r["name"] == "smoke-object"
    and r["size"] == payload_size and r["digest"] == digest_v1 and r["job_id"] is None,
)
find_record(
    "get ok by name",
    lambda r: r["op"] == "get" and r["result"] == "ok" and r["selector"] == "name"
    and r["object_id"] == stdin_id and r["name"] == "stdin-object"
    and r["size"] == payload_size and r["digest"] == digest_stdin and r["job_id"] is None,
)
find_record(
    "list ok",
    lambda r: r["op"] == "list" and r["result"] == "ok" and isinstance(r["count"], int)
    and r["count"] >= 3 and r["size"] == r["count"] and r["digest"] is None
    and r["job_id"] is None,
)
find_record(
    "drop ok by name",
    lambda r: r["op"] == "drop" and r["result"] == "ok" and r["selector"] == "name"
    and r["object_id"] == dropped_latest and r["name"] == "smoke-object"
    and r["size"] == payload_v2_size and r["digest"] == digest_v2 and r["job_id"] is None,
)
find_record(
    "drop ok by id",
    lambda r: r["op"] == "drop" and r["result"] == "ok" and r["selector"] == "id"
    and r["object_id"] == dropped_old and r["name"] == "smoke-object"
    and r["size"] == payload_size and r["digest"] == digest_v1 and r["job_id"] is None,
)
find_record(
    "get not_found by id",
    lambda r: r["op"] == "get" and r["result"] == "not_found" and r["selector"] == "id"
    and r["object_id"] == dropped_old and r["name"] is None and r["error"] == "object not found"
    and r["digest"] is None and r["job_id"] is None,
)
find_record(
    "get not_found by name",
    lambda r: r["op"] == "get" and r["result"] == "not_found" and r["selector"] == "name"
    and r["object_id"] is None and r["name"] == "smoke-object"
    and r["error"] == "object not found" and r["digest"] is None and r["job_id"] is None,
)

id_get_ok = [
    r for r in records
    if r["op"] == "get" and r["result"] == "ok" and r["selector"] == "id"
]
name_get_ok = [
    r for r in records
    if r["op"] == "get" and r["result"] == "ok" and r["selector"] == "name"
]
if len(id_get_ok) < 5:
    raise SystemExit(f"expected at least 5 successful id-based get records, saw {len(id_get_ok)}")
if len(name_get_ok) < 5:
    raise SystemExit(f"expected at least 5 successful name-based get records, saw {len(name_get_ok)}")
PY

quota_a="$tmp/quota-a.bin"
quota_b="$tmp/quota-b.bin"
printf '12345' >"$quota_a"
printf 'abcdef' >"$quota_b"

name_limit_sock="$tmp/name-limit.sock"
name_limit_log="$tmp/name-limit.log"
start_broker "$name_limit_sock" "$name_limit_log" --max-name-bytes 8 --listen-backlog 1
name_limit_id=$("$bin" put "$quota_a" --name 12345678 --socket "$name_limit_sock")
"$bin" get --name 12345678 "$tmp/name-limit-copy.bin" --socket "$name_limit_sock"
cmp "$quota_a" "$tmp/name-limit-copy.bin"
"$bin" list --socket "$name_limit_sock" >"$tmp/name-limit-list.txt"
grep -F "12345678" "$tmp/name-limit-list.txt" >/dev/null
if "$bin" put "$quota_a" --name 123456789 --socket "$name_limit_sock" 2>"$tmp/name-limit-put.err"; then
    echo "put unexpectedly accepted a broker-over-limit name" >&2
    exit 1
fi
grep -F "object name exceeds broker name limit" "$tmp/name-limit-put.err" >/dev/null
if "$bin" get --name 123456789 "$tmp/name-limit-too-long.bin" --socket "$name_limit_sock" \
    2>"$tmp/name-limit-get.err"; then
    echo "get unexpectedly accepted a broker-over-limit name" >&2
    exit 1
fi
grep -F "object name exceeds broker name limit" "$tmp/name-limit-get.err" >/dev/null
if "$bin" drop --name 123456789 --socket "$name_limit_sock" 2>"$tmp/name-limit-drop.err"; then
    echo "drop unexpectedly accepted a broker-over-limit name" >&2
    exit 1
fi
grep -F "object name exceeds broker name limit" "$tmp/name-limit-drop.err" >/dev/null
test "$("$bin" drop --name 12345678 --socket "$name_limit_sock")" = "$name_limit_id"
stop_broker

request_sock="$tmp/request-limit.sock"
request_log="$tmp/request-limit.log"
start_broker "$request_sock" "$request_log" --max-request-bytes 80
request_over_name=$(python3 - <<'PY'
print("x" * 81)
PY
)
request_id=$("$bin" put "$quota_a" --name short --socket "$request_sock")
"$bin" get --name short "$tmp/request-limit-copy.bin" --socket "$request_sock"
cmp "$quota_a" "$tmp/request-limit-copy.bin"
if "$bin" put "$quota_a" --name "$request_over_name" --socket "$request_sock" \
    2>"$tmp/request-put.err"; then
    echo "put unexpectedly accepted an over-budget request payload" >&2
    exit 1
fi
grep -F "request payload exceeds broker limit" "$tmp/request-put.err" >/dev/null
if "$bin" get --name "$request_over_name" "$tmp/request-too-long.bin" --socket "$request_sock" \
    2>"$tmp/request-get.err"; then
    echo "get unexpectedly accepted an over-budget request payload" >&2
    exit 1
fi
grep -F "request payload exceeds broker limit" "$tmp/request-get.err" >/dev/null
if "$bin" drop --name "$request_over_name" --socket "$request_sock" \
    2>"$tmp/request-drop.err"; then
    echo "drop unexpectedly accepted an over-budget request payload" >&2
    exit 1
fi
grep -F "request payload exceeds broker limit" "$tmp/request-drop.err" >/dev/null
python3 - "$request_sock" >"$tmp/request-overflow.out" <<'PY'
import socket
import struct
import sys

MAGIC = 0x4d464442
VERSION = 1
CMD_LIST = 3
BAD_REQUEST = 3
HEADER_FMT = "<IHHIIQQIIII"

header = struct.pack(
    HEADER_FMT,
    MAGIC, VERSION, CMD_LIST,
    0,
    0,
    0,
    0,
    0xFFFFFFFF,
    1,
    0,
    0,
)
assert len(header) == 48

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
sock.sendall(header)

resp = b""
while len(resp) < 48:
    chunk = sock.recv(48 - len(resp))
    if not chunk:
        raise SystemExit("broker closed before sending response header")
    resp += chunk
(_, _, _, status, _, _, _, _, text_len, _, _) = struct.unpack(HEADER_FMT, resp)
text = b""
while len(text) < text_len:
    chunk = sock.recv(text_len - len(text))
    if not chunk:
        raise SystemExit("broker closed before sending response text")
    text += chunk
sock.close()

if status != BAD_REQUEST:
    raise SystemExit(f"expected BAD_REQUEST status, got {status} ({text!r})")
expected = b"request payload exceeds broker limit"
if text != expected:
    raise SystemExit(f"unexpected error text: {text!r}")
PY
"$bin" list --socket "$request_sock" >"$tmp/request-overflow-list.txt"
grep -F "short" "$tmp/request-overflow-list.txt" >/dev/null
test "$("$bin" drop --name short --socket "$request_sock")" = "$request_id"
stop_broker
python3 - "$request_log" <<'PY'
import json
import pathlib
import sys

records = []
for raw in pathlib.Path(sys.argv[1]).read_text().splitlines():
    line = raw.strip()
    if not line or not line.startswith("{"):
        continue
    records.append(json.loads(line))

for record in records:
    if (record.get("op") == "list" and record.get("result") == "bad_request"
            and record.get("error") == "request payload exceeds broker limit"):
        break
else:
    raise SystemExit("missing list bad_request audit record for request overflow")

for record in records:
    if record.get("op") == "list" and record.get("result") == "ok":
        break
else:
    raise SystemExit("missing follow-up list ok audit record")
PY

default_request_sock="$tmp/request-default.sock"
default_request_log="$tmp/request-default.log"
start_broker "$default_request_sock" "$default_request_log"
python3 - "$default_request_sock" >"$tmp/request-default-overflow.out" <<'PY'
import socket
import struct
import sys

MAGIC = 0x4d464442
VERSION = 1
CMD_LIST = 3
BAD_REQUEST = 3
HEADER_FMT = "<IHHIIQQIIII"

header = struct.pack(
    HEADER_FMT,
    MAGIC, VERSION, CMD_LIST,
    0,
    0,
    0,
    0,
    0xFFFFFFFF,
    1,
    0,
    0,
)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
sock.sendall(header)

resp = b""
while len(resp) < 48:
    chunk = sock.recv(48 - len(resp))
    if not chunk:
        raise SystemExit("broker closed before sending response header")
    resp += chunk
(_, _, _, status, _, _, _, _, text_len, _, _) = struct.unpack(HEADER_FMT, resp)
text = b""
while len(text) < text_len:
    chunk = sock.recv(text_len - len(text))
    if not chunk:
        raise SystemExit("broker closed before sending response text")
    text += chunk
sock.close()

if status != BAD_REQUEST:
    raise SystemExit(f"expected BAD_REQUEST status, got {status} ({text!r})")
expected = b"request payload exceeds broker limit"
if text != expected:
    raise SystemExit(f"unexpected error text: {text!r}")
PY
"$bin" list --socket "$default_request_sock" >"$tmp/request-default-list.txt"
stop_broker

list_sock="$tmp/list-limit.sock"
list_log="$tmp/list-limit.log"
start_broker "$list_sock" "$list_log" --max-list-bytes 288
list_id_a=$("$bin" put "$quota_a" --name a --socket "$list_sock")
list_id_b=$("$bin" put "$quota_a" --name b --socket "$list_sock")
list_id_c=$("$bin" put "$quota_a" --name c --socket "$list_sock")
list_id_d=$("$bin" put "$quota_a" --name d --socket "$list_sock")
if "$bin" list --socket "$list_sock" >"$tmp/list-too-large.out" 2>"$tmp/list-too-large.err"; then
    echo "list unexpectedly succeeded past the broker list budget" >&2
    exit 1
fi
grep -F "list response too large" "$tmp/list-too-large.err" >/dev/null
test "$("$bin" drop "$list_id_d" --socket "$list_sock")" = "$list_id_d"
"$bin" list --socket "$list_sock" >"$tmp/list-limit-ok.txt"
grep -F "$list_id_a" "$tmp/list-limit-ok.txt" >/dev/null
grep -F "$list_id_b" "$tmp/list-limit-ok.txt" >/dev/null
grep -F "$list_id_c" "$tmp/list-limit-ok.txt" >/dev/null
stop_broker

policy_sock="$tmp/policy.sock"
policy_log="$tmp/policy.log"
start_broker "$policy_sock" "$policy_log"
pub_id=$("$bin" put "$quota_a" --name pub --socket "$policy_sock")
mine_id=$("$bin" put "$quota_a" --name mine --job-id alpha --socket "$policy_sock")
theirs_id=$("$bin" put "$quota_a" --name theirs --job-id gamma --socket "$policy_sock")
policy_id=$("$bin" put "$payload" --name policy-object --job-id alpha --allow-job beta --socket "$policy_sock")
env_owned_id=$(MEMFDBUS_JOB_ID=env7 "$bin" put "$quota_a" --name env-owned --socket "$policy_sock")
for value in "$pub_id" "$mine_id" "$theirs_id" "$policy_id" "$env_owned_id"; do
    case "$value" in
        ''|*[!0-9]*) echo "policy put returned non-numeric id: $value" >&2; exit 1 ;;
    esac
done
"$bin" list --socket "$policy_sock" >"$tmp/policy-host-list.txt"
grep -F "pub" "$tmp/policy-host-list.txt" >/dev/null
grep -F "mine" "$tmp/policy-host-list.txt" >/dev/null
grep -F "theirs" "$tmp/policy-host-list.txt" >/dev/null
grep -F "policy-object" "$tmp/policy-host-list.txt" >/dev/null
awk -F '\t' '$NF=="env-owned"{print $0}' "$tmp/policy-host-list.txt" | grep -F "owner=env7" >/dev/null
awk -F '\t' '$NF=="mine"{print $0}' "$tmp/policy-host-list.txt" | grep -F "owner=alpha" >/dev/null
awk -F '\t' '$NF=="policy-object"{print $0}' "$tmp/policy-host-list.txt" | grep -F "allowed=beta" >/dev/null

"$bin" list --job-id alpha --socket "$policy_sock" >"$tmp/policy-alpha-list.txt"
grep -F "pub" "$tmp/policy-alpha-list.txt" >/dev/null
grep -F "mine" "$tmp/policy-alpha-list.txt" >/dev/null
grep -F "policy-object" "$tmp/policy-alpha-list.txt" >/dev/null
if grep -F "theirs" "$tmp/policy-alpha-list.txt" >/dev/null; then
    echo "alpha unexpectedly saw gamma-owned object in list" >&2
    exit 1
fi

"$bin" list --job-id beta --socket "$policy_sock" >"$tmp/policy-beta-list.txt"
grep -F "pub" "$tmp/policy-beta-list.txt" >/dev/null
grep -F "policy-object" "$tmp/policy-beta-list.txt" >/dev/null
if grep -F "mine" "$tmp/policy-beta-list.txt" >/dev/null; then
    echo "beta unexpectedly saw alpha-only object in list" >&2
    exit 1
fi

"$bin" list --job-id gamma --socket "$policy_sock" >"$tmp/policy-gamma-list.txt"
grep -F "theirs" "$tmp/policy-gamma-list.txt" >/dev/null
if grep -F "policy-object" "$tmp/policy-gamma-list.txt" >/dev/null; then
    echo "gamma unexpectedly saw policy-object in list" >&2
    exit 1
fi

"$bin" get --job-id alpha "$policy_id" "$tmp/policy-alpha.bin" --socket "$policy_sock"
cmp "$payload" "$tmp/policy-alpha.bin"
"$bin" get --job-id beta "$policy_id" "$tmp/policy-beta.bin" --socket "$policy_sock"
cmp "$payload" "$tmp/policy-beta.bin"
if "$bin" get --job-id gamma "$policy_id" "$tmp/policy-gamma.bin" --socket "$policy_sock" \
    2>"$tmp/policy-gamma.err"; then
    echo "gamma unexpectedly fetched policy-object by id" >&2
    exit 1
fi
grep -Fx "broker error: access denied" "$tmp/policy-gamma.err" >/dev/null
if [ -e "$tmp/policy-gamma.bin" ] && cmp -s "$payload" "$tmp/policy-gamma.bin"; then
    echo "gamma unexpectedly received the policy payload" >&2
    exit 1
fi
"$bin" get --job-id alpha --name policy-object "$tmp/policy-alpha-name.bin" --socket "$policy_sock"
cmp "$payload" "$tmp/policy-alpha-name.bin"
"$bin" get --job-id beta --name policy-object "$tmp/policy-beta-name.bin" --socket "$policy_sock"
cmp "$payload" "$tmp/policy-beta-name.bin"
if "$bin" get --job-id gamma --name policy-object "$tmp/policy-gamma-name.bin" --socket "$policy_sock" \
    2>"$tmp/policy-gamma-name.err"; then
    echo "gamma unexpectedly fetched policy-object by name" >&2
    exit 1
fi
grep -Fx "broker error: access denied" "$tmp/policy-gamma-name.err" >/dev/null
"$bin" get --job-id beta --name pub "$tmp/policy-public.bin" --socket "$policy_sock"
cmp "$quota_a" "$tmp/policy-public.bin"

"$bin" exec --job-id beta "$policy_id" --socket "$policy_sock" -- sh -c '
    cat "/proc/self/fd/$MEMFDBUS_FD" > "$1"
' sh "$tmp/policy-exec-beta.bin"
cmp "$payload" "$tmp/policy-exec-beta.bin"
if "$bin" exec --job-id gamma "$policy_id" --socket "$policy_sock" -- true \
    2>"$tmp/policy-exec-gamma.err"; then
    echo "gamma unexpectedly exec-fetched policy-object" >&2
    exit 1
fi
grep -Fx "broker error: access denied" "$tmp/policy-exec-gamma.err" >/dev/null

if "$bin" drop --job-id beta "$policy_id" --socket "$policy_sock" 2>"$tmp/policy-drop-beta.err"; then
    echo "beta unexpectedly dropped alpha-owned policy-object" >&2
    exit 1
fi
grep -Fx "broker error: access denied" "$tmp/policy-drop-beta.err" >/dev/null
if "$bin" drop --job-id gamma --name policy-object --socket "$policy_sock" \
    2>"$tmp/policy-drop-gamma.err"; then
    echo "gamma unexpectedly dropped policy-object by name" >&2
    exit 1
fi
grep -Fx "broker error: access denied" "$tmp/policy-drop-gamma.err" >/dev/null
"$bin" get --job-id alpha "$policy_id" "$tmp/policy-still-there.bin" --socket "$policy_sock"
cmp "$payload" "$tmp/policy-still-there.bin"
test "$("$bin" drop --job-id alpha "$policy_id" --socket "$policy_sock")" = "$policy_id"
if "$bin" get --job-id alpha "$policy_id" "$tmp/policy-missing.bin" --socket "$policy_sock" \
    2>"$tmp/policy-missing.err"; then
    echo "alpha unexpectedly fetched a dropped policy-object" >&2
    exit 1
fi
grep -Fx "broker error: object not found" "$tmp/policy-missing.err" >/dev/null
stop_broker

python3 - "$policy_log" "$policy_id" "$digest_v1" <<'PY'
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
policy_id = int(sys.argv[2])
policy_digest = sys.argv[3]
records = []

for raw_line in log_path.read_text().splitlines():
    line = raw_line.strip()
    if not line or not line.startswith("{"):
        continue
    records.append(json.loads(line))

def require(description, predicate):
    for record in records:
        if predicate(record):
            return
    raise SystemExit(f"missing policy audit record: {description}")

require(
    "put with alpha job id",
    lambda r: r["op"] == "put" and r["result"] == "ok" and r["object_id"] == policy_id
    and r["name"] == "policy-object" and r["job_id"] == "alpha" and r["digest"] == policy_digest,
)
require(
    "beta get ok with digest",
    lambda r: r["op"] == "get" and r["result"] == "ok" and r["object_id"] == policy_id
    and r["job_id"] == "beta" and r["digest"] == policy_digest,
)
require(
    "gamma get forbidden",
    lambda r: r["op"] == "get" and r["result"] == "forbidden" and r["object_id"] == policy_id
    and r["job_id"] == "gamma" and r["digest"] == policy_digest,
)
require(
    "alpha list ok",
    lambda r: r["op"] == "list" and r["result"] == "ok" and r["job_id"] == "alpha",
)
require(
    "beta drop forbidden",
    lambda r: r["op"] == "drop" and r["result"] == "forbidden" and r["object_id"] == policy_id
    and r["job_id"] == "beta" and r["digest"] == policy_digest,
)
require(
    "alpha drop ok",
    lambda r: r["op"] == "drop" and r["result"] == "ok" and r["object_id"] == policy_id
    and r["job_id"] == "alpha" and r["digest"] == policy_digest,
)
PY

held_sock="$tmp/held.sock"
held_log="$tmp/held.log"
held_ready="$tmp/held.ready"
held_release="$tmp/held.release"
start_broker "$held_sock" "$held_log"
held_id=$("$bin" put "$payload" --name held-exec --socket "$held_sock")
"$bin" exec "$held_id" --socket "$held_sock" -- "$held_fd" "$payload" "$held_ready" "$held_release" &
held_pid=$!
i=0
while [ ! -f "$held_ready" ]; do
    i=$((i + 1))
    if [ "$i" -gt 100 ]; then
        echo "held-fd helper did not report readiness" >&2
        wait "$held_pid" || true
        exit 1
    fi
    sleep 0.05
done
test "$("$bin" drop "$held_id" --socket "$held_sock")" = "$held_id"
if "$bin" get "$held_id" "$tmp/held-missing.bin" --socket "$held_sock" 2>"$tmp/held-missing.err"; then
    echo "get unexpectedly succeeded after dropping held-exec" >&2
    wait "$held_pid" || true
    exit 1
fi
grep -F "object not found" "$tmp/held-missing.err" >/dev/null
: >"$held_release"
wait "$held_pid"
stop_broker

ca_sock="$tmp/content-addressed.sock"
ca_log="$tmp/content-addressed.log"
start_broker "$ca_sock" "$ca_log"
ca_id_a=$("$bin" put "$payload" --content-addressed --socket "$ca_sock")
ca_id_b=$("$bin" put "$payload" --content-addressed --socket "$ca_sock")
ca_id_c=$("$bin" put "$payload_v2" --content-addressed --socket "$ca_sock")
for value in "$ca_id_a" "$ca_id_b" "$ca_id_c"; do
    case "$value" in
        ''|*[!0-9]*) echo "content-addressed put returned non-numeric id: $value" >&2; exit 1 ;;
    esac
done
"$bin" list --socket "$ca_sock" >"$tmp/content-addressed-list.txt"
python3 - "$tmp/content-addressed-list.txt" "$ca_id_a" "$ca_id_b" "$ca_id_c" >"$tmp/content-addressed.sh" <<'PY'
import pathlib
import sys

rows = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    object_id, owner, allowed, size_text, digest, name = line.split("\t")
    rows[int(object_id)] = {
        "owner": owner,
        "allowed": allowed,
        "size": int(size_text),
        "digest": digest,
        "name": name,
    }

id_a = int(sys.argv[2])
id_b = int(sys.argv[3])
id_c = int(sys.argv[4])

for object_id in (id_a, id_b, id_c):
    row = rows[object_id]
    if row["digest"] != row["name"]:
        raise SystemExit(f"content-addressed row did not use digest as the logical name: {row}")

if rows[id_a]["digest"] != rows[id_b]["digest"]:
    raise SystemExit("same-content content-addressed puts did not reuse the same digest name")
if rows[id_a]["digest"] == rows[id_c]["digest"]:
    raise SystemExit("different-content content-addressed put reused the same digest name")

print(f"ca_name_a={rows[id_a]['name']}")
print(f"ca_name_c={rows[id_c]['name']}")
PY
. "$tmp/content-addressed.sh"
"$bin" get --name "$ca_name_a" "$tmp/content-addressed-a.bin" --socket "$ca_sock"
cmp "$payload" "$tmp/content-addressed-a.bin"
"$bin" get --name "$ca_name_c" "$tmp/content-addressed-c.bin" --socket "$ca_sock"
cmp "$payload_v2" "$tmp/content-addressed-c.bin"
stop_broker

client_quota_sock="$tmp/client-quota.sock"
client_quota_log="$tmp/client-quota.log"
start_broker "$client_quota_sock" "$client_quota_log" --max-clients 1
python3 - "$client_quota_sock" <<'PY' &
import socket
import sys
import time

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
time.sleep(2)
sock.close()
PY
client_holder_pid=$!
sleep 0.1
if "$bin" list --socket "$client_quota_sock" >"$tmp/client-quota.out" 2>"$tmp/client-quota.err"; then
    echo "broker unexpectedly accepted a client past --max-clients" >&2
    wait "$client_holder_pid" || true
    exit 1
fi
grep -F "broker client quota exceeded" "$tmp/client-quota.err" >/dev/null
wait "$client_holder_pid"
"$bin" list --socket "$client_quota_sock" >"$tmp/client-quota-after.txt"
stop_broker

quota_sock="$tmp/quota-objects.sock"
quota_log="$tmp/quota-objects.log"
start_broker "$quota_sock" "$quota_log" --max-objects 1
quota_id=$("$bin" put "$quota_a" --name quota-a --socket "$quota_sock")
if "$bin" put "$quota_b" --name quota-b --socket "$quota_sock" 2>"$tmp/quota-objects.err"; then
    echo "put unexpectedly exceeded max object count" >&2
    exit 1
fi
grep -F "broker object quota exceeded" "$tmp/quota-objects.err" >/dev/null
"$bin" get "$quota_id" "$tmp/quota-object-copy.bin" --socket "$quota_sock"
cmp "$quota_a" "$tmp/quota-object-copy.bin"
stop_broker

quota_sock="$tmp/quota-bytes.sock"
quota_log="$tmp/quota-bytes.log"
start_broker "$quota_sock" "$quota_log" --max-total-bytes 10
quota_id=$("$bin" put "$quota_a" --name quota-a --socket "$quota_sock")
if "$bin" put "$quota_b" --name quota-b --socket "$quota_sock" 2>"$tmp/quota-bytes.err"; then
    echo "put unexpectedly exceeded max total bytes" >&2
    exit 1
fi
grep -F "broker object quota exceeded" "$tmp/quota-bytes.err" >/dev/null
test "$("$bin" drop "$quota_id" --socket "$quota_sock")" = "$quota_id"
quota_id=$("$bin" put "$quota_b" --name quota-b --socket "$quota_sock")
"$bin" get "$quota_id" "$tmp/quota-bytes-copy.bin" --socket "$quota_sock"
cmp "$quota_b" "$tmp/quota-bytes-copy.bin"
stop_broker

if "$bin" broker --socket "$tmp/zero-objects.sock" --max-objects 0 >"$tmp/zero-objects.out" 2>"$tmp/zero-objects.err"; then
    echo "broker unexpectedly accepted --max-objects 0" >&2
    exit 1
fi
grep -F -- "--max-objects" "$tmp/zero-objects.err" >/dev/null
test ! -S "$tmp/zero-objects.sock"

if "$bin" broker --socket "$tmp/zero-bytes.sock" --max-total-bytes 0 >"$tmp/zero-bytes.out" 2>"$tmp/zero-bytes.err"; then
    echo "broker unexpectedly accepted --max-total-bytes 0" >&2
    exit 1
fi
grep -F -- "--max-total-bytes" "$tmp/zero-bytes.err" >/dev/null
test ! -S "$tmp/zero-bytes.sock"

if "$bin" broker --socket "$tmp/zero-clients.sock" --max-clients 0 >"$tmp/zero-clients.out" \
    2>"$tmp/zero-clients.err"; then
    echo "broker unexpectedly accepted --max-clients 0" >&2
    exit 1
fi
grep -F -- "--max-clients" "$tmp/zero-clients.err" >/dev/null
test ! -S "$tmp/zero-clients.sock"

if "$bin" broker --socket "$tmp/zero-backlog.sock" --listen-backlog 0 >"$tmp/zero-backlog.out" \
    2>"$tmp/zero-backlog.err"; then
    echo "broker unexpectedly accepted --listen-backlog 0" >&2
    exit 1
fi
grep -F -- "--listen-backlog" "$tmp/zero-backlog.err" >/dev/null
test ! -S "$tmp/zero-backlog.sock"

if "$bin" broker --socket "$tmp/negative-backlog.sock" --listen-backlog -1 \
    >"$tmp/negative-backlog.out" 2>"$tmp/negative-backlog.err"; then
    echo "broker unexpectedly accepted --listen-backlog -1" >&2
    exit 1
fi
grep -F -- "--listen-backlog" "$tmp/negative-backlog.err" >/dev/null
test ! -S "$tmp/negative-backlog.sock"

if "$bin" broker --socket "$tmp/text-backlog.sock" --listen-backlog nope >"$tmp/text-backlog.out" \
    2>"$tmp/text-backlog.err"; then
    echo "broker unexpectedly accepted a non-numeric backlog" >&2
    exit 1
fi
grep -F -- "--listen-backlog" "$tmp/text-backlog.err" >/dev/null
test ! -S "$tmp/text-backlog.sock"

digest_sock="$tmp/digest.sock"
digest_log="$tmp/digest.log"
start_broker "$digest_sock" "$digest_log"
"$digest_mismatch" "$digest_sock"
"$bin" list --socket "$digest_sock" >"$tmp/digest-list.txt"
if grep -F "mismatch-object" "$tmp/digest-list.txt" >/dev/null; then
    echo "broker retained an object after digest mismatch" >&2
    exit 1
fi
grep -F "match-object" "$tmp/digest-list.txt" >/dev/null
if "$bin" get --name mismatch-object "$tmp/digest-mismatch-get.bin" --socket "$digest_sock" \
    2>"$tmp/digest-mismatch-get.err"; then
    echo "get unexpectedly succeeded for mismatch-object" >&2
    exit 1
fi
grep -F "object not found" "$tmp/digest-mismatch-get.err" >/dev/null
"$bin" get --name match-object "$tmp/digest-match-get.bin" --socket "$digest_sock"
stop_broker

printf 'smoke ok: objects %s, %s, and %s\n' "$id" "$stdin_id" "$id_v2"
