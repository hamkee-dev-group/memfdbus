#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SIZE_BYTES (64ULL * 1024ULL * 1024ULL)
#define DEFAULT_ITERS 5ULL

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
            die_errno("write");
        }
        p += n;
        len -= (size_t)n;
    }
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
            die("short read: peer closed early");
        }
        p += n;
        len -= (size_t)n;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [--size BYTES] [--iters N]\n", prog);
}

int main(int argc, char **argv)
{
    uint64_t size = DEFAULT_SIZE_BYTES;
    uint64_t iters = DEFAULT_ITERS;
    static struct option long_opts[] = {
        {"size", required_argument, NULL, 'z'},
        {"iters", required_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int opt;

    while ((opt = getopt_long(argc, argv, "z:n:h", long_opts, NULL)) != -1) {
        char *end = NULL;

        switch (opt) {
        case 'z':
            errno = 0;
            size = strtoull(optarg, &end, 10);
            if (errno || !end || *end != '\0') {
                die("invalid --size: %s", optarg);
            }
            break;
        case 'n':
            errno = 0;
            iters = strtoull(optarg, &end, 10);
            if (errno || !end || *end != '\0') {
                die("invalid --iters: %s", optarg);
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
    if (iters == 0) {
        die("--iters must be > 0");
    }

    signal(SIGPIPE, SIG_IGN);

    unsigned char *payload = NULL;
    if (size > 0) {
        payload = malloc((size_t)size);
        if (!payload) {
            die("payload allocation failed (size=%" PRIu64 ")", size);
        }
        fill_payload(payload, (size_t)size);
    }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        die_errno("socketpair");
    }

    pid_t pid = fork();
    if (pid < 0) {
        die_errno("fork");
    }
    if (pid == 0) {
        unsigned char *rbuf = NULL;

        close(fds[0]);
        if (size > 0) {
            rbuf = malloc((size_t)size);
            if (!rbuf) {
                die("recv buffer allocation failed");
            }
        }
        for (uint64_t i = 0; i < iters; i++) {
            if (size > 0) {
                read_full_or_die(fds[1], rbuf, (size_t)size);
            }
        }
        free(rbuf);
        close(fds[1]);
        free(payload);
        _exit(0);
    }

    close(fds[1]);
    for (uint64_t i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();

        if (size > 0) {
            write_full_or_die(fds[0], payload, (size_t)size);
        }
        uint64_t elapsed = now_ns() - t0;
        double seconds = (double)elapsed / 1e9;
        double mb_s = 0.0;
        if (seconds > 0.0) {
            mb_s = (double)size / seconds / 1e6;
        }
        printf("uds_stream,put_get,%" PRIu64 ",%" PRIu64 ",%.3f\n", size, elapsed, mb_s);
        fflush(stdout);
    }
    close(fds[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        die_errno("waitpid");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        die("child exited abnormally (status=0x%x)", status);
    }

    free(payload);
    return 0;
}
