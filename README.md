# memfdbus

`memfdbus` is a local object bus for passing large immutable blobs between
processes without copying blob bytes through the broker. Publishers create a
Linux `memfd`, write the payload once, seal it immutable, and pass the file
descriptor over a Unix domain socket. Consumers receive a duplicate descriptor
and can read or `mmap` the same pages.

This repository contains a small C implementation with the platform-facing
pieces from [plan.md](./plan.md):

- sealed `memfd` helpers
- `SCM_RIGHTS` descriptor passing
- a small Unix-socket broker
- a C library and public header for embedding publishers/consumers
- a CLI for publishing, fetching, and listing objects
- name-based lookup for "latest blob wins" workflows
- optional content-addressed naming via SHA-256 digests
- per-job owner/allow policy on put/get/list/drop/exec
- broker limits for objects, bytes, request size, list size, name bytes, and
  concurrent clients
- JSONL audit records with object id, name, size, digest, job id, operation,
  selector, and result
- `exec` handoff for running consumers with an inherited sealed object fd
- integration tests that exercise the real kernel path

## Requirements

- Linux with `memfd_create(2)` and file sealing support
- a C11 compiler
- Python 3 for the smoke test payload generator

## Quick Start

Build:

```sh
make
```

This builds both the CLI broker/client and a static C library:

```text
build/memfdbus
build/libmemfdbus.a
include/memfdbus.h
```

Run a broker:

```sh
./build/memfdbus broker --socket /tmp/memfdbus.sock >/tmp/memfdbus.log
```

Publish a file:

```sh
object_id=$(./build/memfdbus put ./large.bin --socket /tmp/memfdbus.sock)
```

Publish a replacement version under a stable logical name:

```sh
./build/memfdbus put ./model-v2.bin --name model.bin --socket /tmp/memfdbus.sock
```

Publish under the content digest instead of an explicit logical name:

```sh
./build/memfdbus put ./model-v2.bin --content-addressed --socket /tmp/memfdbus.sock
```

Fetch it back:

```sh
./build/memfdbus get "$object_id" ./copy.bin --socket /tmp/memfdbus.sock
```

Fetch the latest object for a logical name:

```sh
./build/memfdbus get --name model.bin ./copy.bin --socket /tmp/memfdbus.sock
```

Run a consumer with the sealed memfd inherited:

```sh
./build/memfdbus exec "$object_id" --socket /tmp/memfdbus.sock -- \
  sh -c 'wc -c "/proc/self/fd/$MEMFDBUS_FD"'
```

List broker objects:

```sh
./build/memfdbus list --socket /tmp/memfdbus.sock
```

Release an object when consumers no longer need to discover it:

```sh
./build/memfdbus drop "$object_id" --socket /tmp/memfdbus.sock
```

## Shape Of The MVP

The broker stores only object metadata and descriptors. Blob content is not
serialized through the broker. Objects are accepted only when the fd is sealed
with `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, and `F_SEAL_SEAL`.

If multiple objects are published with the same name, `get --name` and
`exec --name` resolve to the newest matching object while older immutable
versions remain addressable by numeric ID. `drop --name` releases the newest
matching object, so a previous version becomes latest again if one exists.

If `put` is given `--content-addressed`, the object's logical name becomes its
`sha256:...` digest string. Re-publishing identical content then produces a new
numeric object id with the same digest/name, which makes digest-based lookup
and dedup-aware workflows straightforward without forcing that mode on ordinary
named publishes.

The broker is intentionally in-memory. Discoverable references can be dropped
without invalidating descriptors that were already handed out, so consumers can
retain an fd or mapping after broker-side removal.

Run the integration smoke test:

```sh
make test
```

## CLI

```sh
memfdbus broker [--socket PATH] [--max-name-bytes N] [--max-objects N]
                [--max-request-bytes N] [--max-list-bytes N]
                [--max-total-bytes N] [--listen-backlog N] [--max-clients N]
memfdbus put FILE [--name NAME | --content-addressed]
             [--job-id JOB] [--allow-job JOB] [--socket PATH]
memfdbus get OBJECT_ID OUT [--job-id JOB] [--socket PATH]
memfdbus get --name NAME OUT [--job-id JOB] [--socket PATH]
memfdbus exec OBJECT_ID [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]
memfdbus exec --name NAME [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]
memfdbus drop OBJECT_ID [--job-id JOB] [--socket PATH]
memfdbus drop --name NAME [--job-id JOB] [--socket PATH]
memfdbus list [--job-id JOB] [--socket PATH]
```

`put` creates a memfd, copies the input into it once, seals it immutable, and
sends only the descriptor plus metadata to the broker. When source and
destination are regular files, `put` and `get` try to use `copy_file_range(2)`
before falling back to buffered copies. `get` and `exec` can target either a
numeric object ID or the latest object for a logical name. `exec` receives a
fresh sealed descriptor, clears close-on-exec on that one fd, and runs the
requested command with `MEMFDBUS_FD`, `MEMFDBUS_OBJECT_ID`, `MEMFDBUS_SIZE`,
`MEMFDBUS_DIGEST`, and `MEMFDBUS_NAME` in the environment so consumers can
`mmap` or read the object directly. `drop` removes the broker's discoverable
reference and closes its stored descriptor; descriptors already handed to
consumers continue to refer to the sealed object through normal Linux fd
lifetime rules.

Use `-` as the input path for `put` to read from stdin, or as the output path
for `get` to write to stdout.

Broker limits are fail-closed. A publish is rejected when it would exceed
`--max-objects`, `--max-total-bytes`, `--max-name-bytes`, or
`--max-request-bytes`. `list` is rejected when the visible listing would exceed
`--max-list-bytes`. New client connections are rejected once `--max-clients` is
reached.

## Job Policy

The broker can operate without job ids, but it also supports simple per-job
ownership and a single explicitly allowed peer job per object.

Examples:

```sh
export MEMFDBUS_JOB_ID=alpha
./build/memfdbus put ./weights.bin --name model.bin --allow-job beta --socket /tmp/memfdbus.sock
./build/memfdbus list --socket /tmp/memfdbus.sock
./build/memfdbus get --job-id beta --name model.bin ./copy.bin --socket /tmp/memfdbus.sock
./build/memfdbus drop --job-id alpha --name model.bin --socket /tmp/memfdbus.sock
```

Policy rules:

- No `job_id` means the request is treated as unscoped.
- An object with no owner is visible to everyone.
- The owner job can fetch, list, exec, and drop its object.
- The single `--allow-job` peer can fetch, list, and exec the object, but
  cannot drop it.
- Other jobs receive `forbidden`.

`list` output is tab-separated and currently prints:

```text
OBJECT_ID<TAB>owner=JOB<TAB>allowed=JOB<TAB>SIZE<TAB>DIGEST<TAB>NAME
```

Use `--content-addressed` when you want `NAME` to equal `DIGEST`.

## Audit Log

The broker writes one JSON object per line to stdout. Redirect broker stdout to
capture the audit stream and keep stderr for fatal startup/runtime errors.

Example record:

```json
{"ts_ns":1710000000000000000,"op":"get","operation":"get","result":"ok","selector":"name","object_id":7,"name":"model.bin","size":1048576,"count":null,"digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","job_id":"beta","error":null}
```

Fields include the operation, result, selector (`id` or `name` when relevant),
object id, logical name, visible object count for `list`, digest, and caller
job id when known. This is the blob-level audit source for consumers such as
`fanotifyd`, which cannot observe anonymous memfd contents directly.

## C API

Programs can link against `libmemfdbus.a` and include `memfdbus.h`:

```sh
cc -std=c11 -Iinclude consumer.c build/libmemfdbus.a -o consumer
```

Minimal consumer:

```c
#include "memfdbus.h"

#include <sys/mman.h>
#include <stdio.h>

int main(void) {
    struct memfdbus_error err = {0};
    struct memfdbus_object obj;

    if (memfdbus_get_fd(MEMFDBUS_DEFAULT_SOCKET, 0, "model.bin", &obj, &err) != 0) {
        fprintf(stderr, "%s\n", memfdbus_error_message(&err));
        return 1;
    }

    void *p = mmap(NULL, (size_t)obj.size, PROT_READ, MAP_SHARED, obj.fd, 0);
    if (p == MAP_FAILED) {
        memfdbus_object_close(&obj);
        return 1;
    }

    /* Use p without copying object bytes through the broker. */
    munmap(p, (size_t)obj.size);
    memfdbus_object_close(&obj);
    return 0;
}
```

The public API currently covers:

- `memfdbus_put_file` and `memfdbus_put_fd`
- `memfdbus_get_fd` and `memfdbus_get_file`
- `memfdbus_drop`
- `memfdbus_list`
- `memfdbus_put_file_for_job` and `memfdbus_put_fd_for_job`
- `memfdbus_get_fd_for_job` and `memfdbus_get_file_for_job`
- `memfdbus_drop_for_job`
- `memfdbus_list_for_job`
- `memfdbus_validate_fd`

All API functions return `0` on success or a negative `enum memfdbus_result`
value on failure. `struct memfdbus_error` carries a stable result code, optional
`errno`, and a human-readable message.
