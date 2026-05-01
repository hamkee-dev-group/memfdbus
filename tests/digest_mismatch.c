#define _GNU_SOURCE

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
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

#define MFDB_MAGIC 0x4d464442u
#define MFDB_VERSION 1u
#define MFDB_CMD_PUT 1
#define MFDB_OK 0
#define MFDB_BAD_REQUEST 3

struct mfdb_msg {
    uint32_t magic;
    uint16_t version;
    uint16_t cmd;
    uint32_t status;
    uint32_t job_len;
    uint64_t object_id;
    uint64_t size;
    uint32_t name_len;
    uint32_t text_len;
    uint32_t allow_len;
    uint32_t reserved;
};

static void die_errno(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static void die_msg(const char *what)
{
    fprintf(stderr, "%s\n", what);
    exit(1);
}

static int memfd_create_compat(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

static int connect_socket(const char *path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        die_errno("socket");
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        die_msg("socket path too long");
    }
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        die_errno("connect");
    }
    return fd;
}

static int make_sealed_memfd(const unsigned char *data, size_t len)
{
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int fd = memfd_create_compat("digest-mismatch", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    size_t written = 0;

    if (fd < 0) {
        die_errno("memfd_create");
    }
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die_errno("write memfd");
        }
        written += (size_t)n;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        die_errno("lseek memfd");
    }
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        die_errno("F_ADD_SEALS");
    }
    return fd;
}

static void send_full(int sock, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = send(sock, p, len, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die_errno("send");
        }
        p += n;
        len -= (size_t)n;
    }
}

static void read_full(int sock, void *buf, size_t len)
{
    char *p = buf;

    while (len > 0) {
        ssize_t n = read(sock, p, len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            die_errno("read");
        }
        if (n == 0) {
            die_msg("unexpected EOF");
        }
        p += n;
        len -= (size_t)n;
    }
}

static void send_msg_with_fd(int sock, const struct mfdb_msg *msg, int fd)
{
    struct iovec iov = {
        .iov_base = (void *)msg,
        .iov_len = sizeof(*msg),
    };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr mh;
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(control, 0, sizeof(control));
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control;
    mh.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    mh.msg_controllen = CMSG_SPACE(sizeof(int));

    do {
        n = sendmsg(sock, &mh, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(*msg)) {
        die_errno("sendmsg");
    }
}

static void compute_digest(const unsigned char *data, size_t len,
                           char digest[MEMFDBUS_DIGEST_BUFSZ])
{
    struct memfdbus_sha256_ctx ctx;
    unsigned char raw[MEMFDBUS_SHA256_RAW_LEN];

    memfdbus_sha256_init(&ctx);
    memfdbus_sha256_update(&ctx, data, len);
    memfdbus_sha256_final(&ctx, raw);
    memfdbus_sha256_format(digest, raw);
}

static void send_put(int sock, int memfd, uint64_t size, const char *name,
                     const char *digest)
{
    struct mfdb_msg req;

    memset(&req, 0, sizeof(req));
    req.magic = MFDB_MAGIC;
    req.version = MFDB_VERSION;
    req.cmd = MFDB_CMD_PUT;
    req.size = size;
    req.name_len = (uint32_t)strlen(name);
    req.text_len = MEMFDBUS_DIGEST_STRLEN;
    send_msg_with_fd(sock, &req, memfd);
    send_full(sock, name, req.name_len);
    send_full(sock, digest, req.text_len);
}

static void recv_response(int sock, struct mfdb_msg *resp, char *text, size_t text_cap)
{
    read_full(sock, resp, sizeof(*resp));
    if (resp->magic != MFDB_MAGIC || resp->version != MFDB_VERSION) {
        die_msg("invalid response magic/version");
    }
    if (resp->text_len) {
        if (resp->text_len >= text_cap) {
            die_msg("response text too large");
        }
        read_full(sock, text, resp->text_len);
        text[resp->text_len] = '\0';
    } else {
        text[0] = '\0';
    }
}

int main(int argc, char **argv)
{
    unsigned char payload_a[1024];
    unsigned char payload_b[1024];
    char digest_a[MEMFDBUS_DIGEST_BUFSZ];
    char digest_b[MEMFDBUS_DIGEST_BUFSZ];
    struct mfdb_msg resp;
    char text[512];
    int sock;
    int memfd;

    if (argc != 2) {
        die_msg("usage: digest_mismatch SOCKET");
    }

    for (size_t i = 0; i < sizeof(payload_a); i++) {
        payload_a[i] = (unsigned char)(i & 0xff);
        payload_b[i] = (unsigned char)((i & 0xff) ^ 0xff);
    }
    compute_digest(payload_a, sizeof(payload_a), digest_a);
    compute_digest(payload_b, sizeof(payload_b), digest_b);
    if (strcmp(digest_a, digest_b) == 0) {
        die_msg("test setup error: payload A and B produced the same digest");
    }

    sock = connect_socket(argv[1]);
    memfd = make_sealed_memfd(payload_a, sizeof(payload_a));
    send_put(sock, memfd, sizeof(payload_a), "mismatch-object", digest_b);
    close(memfd);
    recv_response(sock, &resp, text, sizeof(text));
    close(sock);
    if (resp.status != MFDB_BAD_REQUEST) {
        fprintf(stderr,
                "expected bad_request for digest mismatch, got status=%u text=\"%s\"\n",
                resp.status, text);
        return 1;
    }
    if (!strstr(text, "digest mismatch")) {
        fprintf(stderr, "expected digest mismatch error text, got \"%s\"\n", text);
        return 1;
    }

    sock = connect_socket(argv[1]);
    memfd = make_sealed_memfd(payload_a, sizeof(payload_a));
    send_put(sock, memfd, sizeof(payload_a), "match-object", digest_a);
    close(memfd);
    recv_response(sock, &resp, text, sizeof(text));
    close(sock);
    if (resp.status != MFDB_OK) {
        fprintf(stderr,
                "expected ok for matching digest, got status=%u text=\"%s\"\n",
                resp.status, text);
        return 1;
    }

    return 0;
}
