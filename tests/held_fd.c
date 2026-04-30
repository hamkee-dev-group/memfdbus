#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif

#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif

#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif

#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif

#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

#define COPY_BUFSZ (64u * 1024u)

static void die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void die_errno(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

static uint64_t parse_u64_env(const char *name)
{
    const char *value = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (!value || !*value) {
        die("missing numeric environment value");
    }
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || !end || *end != '\0') {
        die("invalid numeric environment value");
    }
    return (uint64_t)parsed;
}

static int parse_fd_env(void)
{
    uint64_t fd = parse_u64_env("MEMFDBUS_FD");

    if (fd > INT32_MAX) {
        die("MEMFDBUS_FD is out of range");
    }
    return (int)fd;
}

static void read_full_or_die(int fd, void *buf, size_t len)
{
    char *p = buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die_errno("read");
        }
        if (n == 0) {
            die("unexpected EOF");
        }
        p += n;
        len -= (size_t)n;
    }
}

static void compare_expected_file(int fd, uint64_t size, const char *path)
{
    unsigned char got[COPY_BUFSZ];
    unsigned char want[COPY_BUFSZ];
    uint64_t off = 0;
    int expected_fd = open(path, O_RDONLY | O_CLOEXEC);

    if (expected_fd < 0) {
        die_errno("open expected payload");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        die_errno("lseek held fd");
    }
    while (off < size) {
        size_t want_len = COPY_BUFSZ;
        ssize_t got_n;
        ssize_t want_n;

        if (size - off < want_len) {
            want_len = (size_t)(size - off);
        }
        got_n = read(fd, got, want_len);
        want_n = read(expected_fd, want, want_len);
        if (got_n != (ssize_t)want_len || want_n != (ssize_t)want_len) {
            die("held fd read length mismatch");
        }
        if (memcmp(got, want, want_len) != 0) {
            die("held fd content mismatch");
        }
        off += want_len;
    }
    close(expected_fd);
}

static void compare_mapping(const void *mapped, uint64_t size, const char *path)
{
    const unsigned char *mem = mapped;
    unsigned char buf[COPY_BUFSZ];
    uint64_t off = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        die_errno("open expected payload");
    }
    while (off < size) {
        size_t want = COPY_BUFSZ;

        if (size - off < want) {
            want = (size_t)(size - off);
        }
        read_full_or_die(fd, buf, want);
        if (memcmp(mem + off, buf, want) != 0) {
            die("mapped memfd content did not match expected payload");
        }
        off += want;
    }
    close(fd);
}

static void wait_for_path(const char *path)
{
    for (int i = 0; i < 400; i++) {
        if (access(path, F_OK) == 0) {
            return;
        }
        usleep(10000);
    }
    die("timed out waiting for release signal");
}

int main(int argc, char **argv)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int fd;
    uint64_t size;
    struct stat st;
    int seals;
    int ready_fd;
    void *mapped = NULL;
    ssize_t wrote;

    if (argc != 4) {
        die("usage: held_fd EXPECTED_PAYLOAD READY_PATH RELEASE_PATH");
    }
    fd = parse_fd_env();
    size = parse_u64_env("MEMFDBUS_SIZE");

    if (fstat(fd, &st) < 0) {
        die_errno("fstat memfd");
    }
    if (!S_ISREG(st.st_mode) || (uint64_t)st.st_size != size) {
        die("inherited fd metadata mismatch");
    }

    ready_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (ready_fd < 0) {
        die_errno("create ready signal");
    }
    close(ready_fd);
    wait_for_path(argv[3]);

    compare_expected_file(fd, size, argv[1]);
    if (size > 0) {
        mapped = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
        if (mapped == MAP_FAILED) {
            die_errno("mmap memfd");
        }
        compare_mapping(mapped, size, argv[1]);
        munmap(mapped, (size_t)size);
    }

    seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        die_errno("F_GET_SEALS");
    }
    if ((seals & required) != required) {
        die("held fd is missing required immutable seals");
    }
    errno = 0;
    wrote = pwrite(fd, "x", 1, 0);
    if (wrote >= 0 || errno != EPERM) {
        die("write to sealed held fd unexpectedly succeeded");
    }

    return 0;
}
