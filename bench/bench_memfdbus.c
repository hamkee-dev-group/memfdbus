#define _GNU_SOURCE

#include "memfdbus.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define BENCH_OBJECT_NAME "memfdbus-bench"
#define BENCH_SENTINEL "MFDBBNCH"
#define BENCH_SENTINEL_LEN 8u

static void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void die_errno(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static int memfd_create_compat(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        die_errno("clock_gettime");
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_payload(unsigned char *buf, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        buf[i] = (unsigned char)((i * 2654435761u) >> 24);
    }
    if (size >= BENCH_SENTINEL_LEN) {
        memcpy(buf, BENCH_SENTINEL, BENCH_SENTINEL_LEN);
    }
}

static void write_full_or_die(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die_errno("write payload");
        }
        p += n;
        len -= (size_t)n;
    }
}

static int prepare_input_fd(const unsigned char *payload, size_t size)
{
    int fd = memfd_create_compat("bench-input", MFD_CLOEXEC);

    if (fd < 0) {
        die_errno("memfd_create");
    }
    if (size > 0) {
        write_full_or_die(fd, payload, size);
    }
    return fd;
}

static void verify_object(const struct memfdbus_object *obj, uint64_t expected_size,
                          const unsigned char *expected_payload)
{
    if (obj->size != expected_size) {
        die("size mismatch: expected=%" PRIu64 " got=%" PRIu64, expected_size, obj->size);
    }
    if (expected_size == 0) {
        return;
    }
    void *m = mmap(NULL, (size_t)expected_size, PROT_READ, MAP_SHARED, obj->fd, 0);
    if (m == MAP_FAILED) {
        die_errno("mmap object fd");
    }
    size_t check = BENCH_SENTINEL_LEN;
    if ((uint64_t)check > expected_size) {
        check = (size_t)expected_size;
    }
    if (memcmp(m, expected_payload, check) != 0) {
        munmap(m, (size_t)expected_size);
        die("payload sentinel mismatch");
    }
    if (munmap(m, (size_t)expected_size) < 0) {
        die_errno("munmap");
    }
}

static void emit_json(const char *operation, uint64_t payload_size, uint64_t iterations,
                      uint64_t elapsed_ns)
{
    double seconds = (double)elapsed_ns / 1e9;
    double throughput = 0.0;

    if (seconds > 0.0) {
        throughput = (double)payload_size * (double)iterations / seconds;
    }
    printf("{\"backend\":\"memfdbus\",\"operation\":\"%s\","
           "\"payload_size\":%" PRIu64 ",\"iterations\":%" PRIu64 ","
           "\"elapsed_ns\":%" PRIu64 ",\"throughput_bytes_per_sec\":%.3f}\n",
           operation, payload_size, iterations, elapsed_ns, throughput);
    fflush(stdout);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--socket PATH] [--size BYTES] [--iterations N]\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *socket_path = MEMFDBUS_DEFAULT_SOCKET;
    uint64_t size = 4096;
    uint64_t iterations = 64;
    static struct option long_opts[] = {
        {"socket", required_argument, NULL, 's'},
        {"size", required_argument, NULL, 'z'},
        {"iterations", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int opt;

    while ((opt = getopt_long(argc, argv, "s:z:n:h", long_opts, NULL)) != -1) {
        char *end = NULL;

        switch (opt) {
        case 's':
            socket_path = optarg;
            break;
        case 'z':
            errno = 0;
            size = strtoull(optarg, &end, 10);
            if (errno || !end || *end != '\0') {
                die("invalid --size: %s", optarg);
            }
            break;
        case 'n':
            errno = 0;
            iterations = strtoull(optarg, &end, 10);
            if (errno || !end || *end != '\0') {
                die("invalid --iterations: %s", optarg);
            }
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    if (iterations == 0) {
        die("--iterations must be > 0");
    }

    unsigned char *payload = NULL;
    if (size > 0) {
        payload = malloc((size_t)size);
        if (!payload) {
            die("payload allocation failed (size=%" PRIu64 ")", size);
        }
        fill_payload(payload, (size_t)size);
    }

    int input_fd = prepare_input_fd(payload, (size_t)size);

    uint64_t put_elapsed = 0;
    uint64_t get_elapsed = 0;

    for (uint64_t i = 0; i < iterations; i++) {
        struct memfdbus_error err;
        struct memfdbus_object obj;
        uint64_t obj_id = 0;
        uint64_t t0;
        int rc;

        memset(&err, 0, sizeof(err));
        if (lseek(input_fd, 0, SEEK_SET) < 0) {
            die_errno("lseek input");
        }
        t0 = now_ns();
        rc = memfdbus_put_fd(socket_path, input_fd, BENCH_OBJECT_NAME, &obj_id, &err);
        put_elapsed += now_ns() - t0;
        if (rc != MEMFDBUS_RESULT_OK) {
            die("put_fd: %s", memfdbus_error_message(&err));
        }

        memset(&err, 0, sizeof(err));
        memset(&obj, 0, sizeof(obj));
        t0 = now_ns();
        rc = memfdbus_get_fd(socket_path, obj_id, NULL, &obj, &err);
        get_elapsed += now_ns() - t0;
        if (rc != MEMFDBUS_RESULT_OK) {
            die("get_fd: %s", memfdbus_error_message(&err));
        }

        verify_object(&obj, size, payload);
        memfdbus_object_close(&obj);

        memset(&err, 0, sizeof(err));
        uint64_t dropped = 0;
        rc = memfdbus_drop(socket_path, obj_id, NULL, &dropped, &err);
        if (rc != MEMFDBUS_RESULT_OK) {
            die("drop: %s", memfdbus_error_message(&err));
        }
    }

    emit_json("put_fd", size, iterations, put_elapsed);
    emit_json("get_fd", size, iterations, get_elapsed);

    close(input_fd);
    free(payload);
    return 0;
}
