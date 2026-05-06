#define _GNU_SOURCE

#include "memfdbus.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
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

#define MFDB_MAGIC 0x4d464442u
#define MFDB_VERSION 1u
#define MFDB_MAX_JOB_ID 256u
#define MFDB_COPY_BUFSZ (1024u * 1024u)

enum mfdb_cmd {
    MFDB_CMD_PUT = 1,
    MFDB_CMD_GET = 2,
    MFDB_CMD_LIST = 3,
    MFDB_CMD_DROP = 4,
};

enum mfdb_status {
    MFDB_OK = 0,
    MFDB_ERR = 1,
    MFDB_NOT_FOUND = 2,
    MFDB_BAD_REQUEST = 3,
    MFDB_FORBIDDEN = 4,
};

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

static void close_nointr(int fd)
{
    if (fd >= 0) {
        while (close(fd) < 0 && errno == EINTR) {
        }
    }
}

static int set_error(struct memfdbus_error *err, int code, int sys_errno, const char *fmt, ...)
{
    va_list ap;

    if (err) {
        err->code = code;
        err->sys_errno = sys_errno;
        va_start(ap, fmt);
        vsnprintf(err->message, sizeof(err->message), fmt, ap);
        va_end(ap);
    }
    if (sys_errno) {
        errno = sys_errno;
    }
    return code;
}

static int set_errno_error(struct memfdbus_error *err, const char *what)
{
    int saved = errno;

    return set_error(err, MEMFDBUS_RESULT_ERROR, saved, "%s: %s", what, strerror(saved));
}

const char *memfdbus_error_message(const struct memfdbus_error *err)
{
    if (!err || !err->message[0]) {
        return "memfdbus error";
    }
    return err->message;
}

static ssize_t retry_read(int fd, void *buf, size_t count)
{
    ssize_t n;

    do {
        n = read(fd, buf, count);
    } while (n < 0 && errno == EINTR);
    return n;
}

static ssize_t retry_write(int fd, const void *buf, size_t count)
{
    ssize_t n;

    do {
        n = write(fd, buf, count);
    } while (n < 0 && errno == EINTR);
    return n;
}

static ssize_t retry_send_nosignal(int fd, const void *buf, size_t count)
{
    ssize_t n;

    do {
        n = send(fd, buf, count, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    return n;
}

static int read_full(int fd, void *buf, size_t len)
{
    char *p = buf;

    while (len > 0) {
        ssize_t n = retry_read(fd, p, len);

        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (n < 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = retry_write(fd, p, len);

        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_full(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0) {
        ssize_t n = retry_send_nosignal(fd, p, len);

        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static void init_msg(struct mfdb_msg *msg, uint16_t cmd)
{
    memset(msg, 0, sizeof(*msg));
    msg->magic = MFDB_MAGIC;
    msg->version = MFDB_VERSION;
    msg->cmd = cmd;
}

static bool valid_msg(const struct mfdb_msg *msg)
{
    return msg->magic == MFDB_MAGIC && msg->version == MFDB_VERSION;
}

static int memfd_create_compat(const char *name, unsigned int flags)
{
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static uint32_t name_len_or_error(const char *name, struct memfdbus_error *err)
{
    size_t len;

    if (!name || !*name) {
        set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "object name must not be empty");
        return UINT32_MAX;
    }
    len = strlen(name);
    if (len > MEMFDBUS_MAX_NAME) {
        set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "object name too long");
        return UINT32_MAX;
    }
    return (uint32_t)len;
}

static const char *resolve_job_id(const char *job_id)
{
    const char *env_job_id;

    if (job_id && job_id[0]) {
        return job_id;
    }
    env_job_id = getenv("MEMFDBUS_JOB_ID");
    return env_job_id && env_job_id[0] ? env_job_id : NULL;
}

static uint32_t job_len_or_error(const char *job_id, const char *label,
                                 struct memfdbus_error *err)
{
    size_t len;

    if (!job_id || !job_id[0]) {
        set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "%s must not be empty", label);
        return UINT32_MAX;
    }
    len = strlen(job_id);
    if (len > MFDB_MAX_JOB_ID) {
        set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "%s too long", label);
        return UINT32_MAX;
    }
    return (uint32_t)len;
}

static int connect_socket_api(const char *socket_path, struct memfdbus_error *err)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr;

    if (!socket_path) {
        socket_path = MEMFDBUS_DEFAULT_SOCKET;
    }
    if (fd < 0) {
        set_errno_error(err, "socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close_nointr(fd);
        set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, ENAMETOOLONG,
                  "socket path too long: %s", socket_path);
        return -1;
    }
    strcpy(addr.sun_path, socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        set_errno_error(err, "connect");
        close_nointr(fd);
        return -1;
    }
    return fd;
}

static int send_msg_maybe_fd(int sock, const struct mfdb_msg *msg, int fd)
{
    const char *p = (const char *)msg;
    struct iovec iov = {
        .iov_base = (void *)msg,
        .iov_len = sizeof(*msg),
    };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr mh;
    ssize_t n;

    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;

    if (fd >= 0) {
        struct cmsghdr *cmsg;

        memset(control, 0, sizeof(control));
        mh.msg_control = control;
        mh.msg_controllen = sizeof(control);
        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
        mh.msg_controllen = CMSG_SPACE(sizeof(int));
    }

    do {
        n = sendmsg(sock, &mh, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);

    if (n <= 0) {
        if (n == 0) {
            errno = EPIPE;
        }
        return -1;
    }
    if ((size_t)n < sizeof(*msg) &&
        send_full(sock, p + n, sizeof(*msg) - (size_t)n) < 0) {
        return -1;
    }
    return 0;
}

static int recv_msg_maybe_fd(int sock, struct mfdb_msg *msg, int *out_fd)
{
    struct iovec iov = {
        .iov_base = msg,
        .iov_len = sizeof(*msg),
    };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr mh;
    ssize_t n;

    *out_fd = -1;
    memset(msg, 0, sizeof(*msg));
    memset(control, 0, sizeof(control));
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control;
    mh.msg_controllen = sizeof(control);

    do {
        n = recvmsg(sock, &mh, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        errno = ECONNRESET;
        return -1;
    }
    if (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        errno = EMSGSIZE;
        return -1;
    }

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }

    if ((size_t)n < sizeof(*msg) &&
        read_full(sock, (char *)msg + n, sizeof(*msg) - (size_t)n) < 0) {
        close_nointr(*out_fd);
        *out_fd = -1;
        return -1;
    }
    return 0;
}

static int broker_status_to_result(uint32_t status)
{
    if (status == MFDB_NOT_FOUND) {
        return MEMFDBUS_RESULT_NOT_FOUND;
    }
    if (status == MFDB_FORBIDDEN) {
        return MEMFDBUS_RESULT_FORBIDDEN;
    }
    if (status == MFDB_BAD_REQUEST) {
        return MEMFDBUS_RESULT_BAD_REQUEST;
    }
    return MEMFDBUS_RESULT_ERROR;
}

static int recv_response(int sock, struct mfdb_msg *resp, int *fd, struct memfdbus_error *err)
{
    char *text = NULL;
    int result;

    if (recv_msg_maybe_fd(sock, resp, fd) < 0) {
        return set_errno_error(err, "receive response");
    }
    if (!valid_msg(resp)) {
        close_nointr(*fd);
        *fd = -1;
        return set_error(err, MEMFDBUS_RESULT_ERROR, EPROTO, "invalid response from broker");
    }
    if (resp->status == MFDB_OK) {
        return MEMFDBUS_RESULT_OK;
    }

    if (resp->text_len) {
        text = malloc((size_t)resp->text_len + 1);
        if (!text) {
            close_nointr(*fd);
            *fd = -1;
            return set_errno_error(err, "malloc");
        }
        if (read_full(sock, text, resp->text_len) < 0) {
            int ret;

            close_nointr(*fd);
            *fd = -1;
            ret = set_errno_error(err, "receive response text");
            free(text);
            return ret;
        }
        text[resp->text_len] = '\0';
    }

    result = broker_status_to_result(resp->status);
    set_error(err, result, 0, "broker error: %s", text ? text : "request failed");
    close_nointr(*fd);
    *fd = -1;
    free(text);
    return result;
}

int memfdbus_validate_fd(int fd, uint64_t expected_size, struct memfdbus_error *err)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat st;
    int seals;

    if (fd < 0) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EBADF, "invalid object fd");
    }
    if (fstat(fd, &st) < 0) {
        if (errno == EBADF) {
            return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EBADF, "invalid object fd");
        }
        return set_errno_error(err, "fstat");
    }
    if (!S_ISREG(st.st_mode)) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                         "descriptor is not a regular memfd-like file");
    }
    if ((uint64_t)st.st_size != expected_size) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                         "size mismatch: expected=%" PRIu64 " fd=%" PRIu64,
                         expected_size, (uint64_t)st.st_size);
    }
    seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        if (errno == EINVAL) {
            return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                             "descriptor is not a sealed memfd");
        }
        return set_errno_error(err, "F_GET_SEALS");
    }
    if ((seals & required) != required) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                         "fd is not fully immutable-sealed");
    }
    return MEMFDBUS_RESULT_OK;
}

static int copy_input_to_memfd(int input_fd, int memfd, uint64_t *out_size,
                               char digest[MEMFDBUS_DIGEST_BUFSZ],
                               struct memfdbus_error *err)
{
    struct memfdbus_sha256_ctx sha;
    unsigned char raw_digest[MEMFDBUS_SHA256_RAW_LEN];
    char *buf = malloc(MFDB_COPY_BUFSZ);
    uint64_t total = 0;

    if (!buf) {
        return set_errno_error(err, "malloc");
    }
    memfdbus_sha256_init(&sha);
    for (;;) {
        ssize_t n = retry_read(input_fd, buf, MFDB_COPY_BUFSZ);

        if (n < 0) {
            int ret = set_errno_error(err, "read input");

            free(buf);
            return ret;
        }
        if (n == 0) {
            break;
        }
        memfdbus_sha256_update(&sha, buf, (size_t)n);
        if (write_full(memfd, buf, (size_t)n) < 0) {
            int ret = set_errno_error(err, "write memfd");

            free(buf);
            return ret;
        }
        total += (uint64_t)n;
    }
    free(buf);
    memfdbus_sha256_final(&sha, raw_digest);
    memfdbus_sha256_format(digest, raw_digest);
    *out_size = total;
    return MEMFDBUS_RESULT_OK;
}

static int make_sealed_memfd_from_fd(int input_fd, const char *name, uint64_t *out_size,
                                     char digest[MEMFDBUS_DIGEST_BUFSZ],
                                     struct memfdbus_error *err)
{
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int fd = memfd_create_compat(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd < 0) {
        set_errno_error(err, "memfd_create");
        return -1;
    }
    if (copy_input_to_memfd(input_fd, fd, out_size, digest, err) != MEMFDBUS_RESULT_OK) {
        close_nointr(fd);
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        set_errno_error(err, "lseek memfd");
        close_nointr(fd);
        return -1;
    }
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        set_errno_error(err, "F_ADD_SEALS");
        close_nointr(fd);
        return -1;
    }
    return fd;
}

int memfdbus_put_fd_for_job(const char *socket_path, int input_fd, const char *name,
                            const char *job_id, const char *allow_job, uint64_t *out_id,
                            struct memfdbus_error *err)
{
    struct mfdb_msg req;
    struct mfdb_msg resp;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    uint32_t allow_len = 0;
    uint32_t job_len = 0;
    uint64_t size;
    uint32_t name_len = name_len_or_error(name, err);
    int memfd;
    int sock;
    int resp_fd = -1;
    int ret;

    if (input_fd < 0) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EBADF, "invalid input fd");
    }
    job_id = resolve_job_id(job_id);
    if (name_len == UINT32_MAX) {
        return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
    }
    if (allow_job && !job_id) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                         "allow_job requires a non-empty job_id");
    }
    if (job_id) {
        job_len = job_len_or_error(job_id, "job_id", err);
        if (job_len == UINT32_MAX) {
            return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
        }
    }
    if (allow_job) {
        allow_len = job_len_or_error(allow_job, "allow_job", err);
        if (allow_len == UINT32_MAX) {
            return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
        }
    }
    memfd = make_sealed_memfd_from_fd(input_fd, name, &size, digest, err);
    if (memfd < 0) {
        return MEMFDBUS_RESULT_ERROR;
    }
    sock = connect_socket_api(socket_path, err);
    if (sock < 0) {
        close_nointr(memfd);
        return MEMFDBUS_RESULT_ERROR;
    }

    init_msg(&req, MFDB_CMD_PUT);
    req.allow_len = allow_len;
    req.job_len = job_len;
    req.size = size;
    req.name_len = name_len;
    req.text_len = MEMFDBUS_DIGEST_STRLEN;
    if (send_msg_maybe_fd(sock, &req, memfd) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        return set_errno_error(err, "send put request");
    }
    if (send_full(sock, name, name_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        return set_errno_error(err, "send object name");
    }
    if (send_full(sock, digest, req.text_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        return set_errno_error(err, "send object digest");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        return set_errno_error(err, "send job id");
    }
    if (req.allow_len && send_full(sock, allow_job, req.allow_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        return set_errno_error(err, "send allowed job id");
    }

    ret = recv_response(sock, &resp, &resp_fd, err);
    close_nointr(resp_fd);
    close_nointr(sock);
    close_nointr(memfd);
    if (ret != MEMFDBUS_RESULT_OK) {
        return ret;
    }
    if (out_id) {
        *out_id = resp.object_id;
    }
    return MEMFDBUS_RESULT_OK;
}

int memfdbus_put_file_for_job(const char *socket_path, const char *path, const char *name,
                              const char *job_id, const char *allow_job, uint64_t *out_id,
                              struct memfdbus_error *err)
{
    int fd;
    int ret;

    if (!path) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "missing input path");
    }
    if (strcmp(path, "-") == 0) {
        return memfdbus_put_fd_for_job(socket_path, STDIN_FILENO, name ? name : "stdin",
                                       job_id, allow_job, out_id, err);
    }
    if (!name) {
        const char *slash = strrchr(path, '/');

        name = slash ? slash + 1 : path;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return set_errno_error(err, "open input");
    }
    ret = memfdbus_put_fd_for_job(socket_path, fd, name, job_id, allow_job, out_id, err);
    close_nointr(fd);
    return ret;
}

static int send_selector_request(const char *socket_path, uint16_t cmd, uint64_t id,
                                 const char *name, const char *job_id, struct mfdb_msg *resp,
                                 int *fd, struct memfdbus_error *err)
{
    struct mfdb_msg req;
    uint32_t job_len = 0;
    uint32_t name_len = 0;
    int sock;
    int ret;

    job_id = resolve_job_id(job_id);
    if ((id != 0) == (name != NULL)) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL,
                         "specify object id or name, but not both");
    }
    if (name) {
        name_len = name_len_or_error(name, err);
        if (name_len == UINT32_MAX) {
            return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
        }
    }
    if (job_id) {
        job_len = job_len_or_error(job_id, "job_id", err);
        if (job_len == UINT32_MAX) {
            return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
        }
    }

    sock = connect_socket_api(socket_path, err);
    if (sock < 0) {
        return MEMFDBUS_RESULT_ERROR;
    }
    init_msg(&req, cmd);
    req.job_len = job_len;
    req.object_id = id;
    req.name_len = name_len;
    if (send_msg_maybe_fd(sock, &req, -1) < 0) {
        close_nointr(sock);
        return set_errno_error(err, "send request");
    }
    if (name_len && send_full(sock, name, name_len) < 0) {
        close_nointr(sock);
        return set_errno_error(err, "send object name");
    }
    if (job_len && send_full(sock, job_id, job_len) < 0) {
        close_nointr(sock);
        return set_errno_error(err, "send job id");
    }

    ret = recv_response(sock, resp, fd, err);
    if (ret != MEMFDBUS_RESULT_OK) {
        close_nointr(sock);
        return ret;
    }
    return sock;
}

int memfdbus_get_fd_for_job(const char *socket_path, uint64_t id, const char *name,
                            const char *job_id, struct memfdbus_object *out,
                            struct memfdbus_error *err)
{
    struct mfdb_msg resp;
    int fd = -1;
    int sock;
    char object_digest[MEMFDBUS_DIGEST_BUFSZ];
    char *object_name;
    int ret;

    if (!out) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "missing output object");
    }
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    sock = send_selector_request(socket_path, MFDB_CMD_GET, id, name, job_id, &resp, &fd, err);
    if (sock < 0) {
        return sock;
    }
    if (fd < 0) {
        close_nointr(sock);
        return set_error(err, MEMFDBUS_RESULT_ERROR, EPROTO, "broker did not send an object fd");
    }
    if (resp.name_len > MEMFDBUS_MAX_NAME) {
        close_nointr(sock);
        close_nointr(fd);
        return set_error(err, MEMFDBUS_RESULT_ERROR, EPROTO,
                         "broker sent an oversized object name");
    }
    if (resp.text_len != MEMFDBUS_DIGEST_STRLEN) {
        close_nointr(sock);
        close_nointr(fd);
        return set_error(err, MEMFDBUS_RESULT_ERROR, EPROTO,
                         "broker sent an invalid object digest");
    }
    object_name = malloc((size_t)resp.name_len + 1);
    if (!object_name) {
        close_nointr(sock);
        close_nointr(fd);
        return set_errno_error(err, "malloc");
    }
    if (read_full(sock, object_name, resp.name_len) < 0) {
        ret = set_errno_error(err, "receive object name");
        close_nointr(sock);
        close_nointr(fd);
        free(object_name);
        return ret;
    }
    object_name[resp.name_len] = '\0';
    if (read_full(sock, object_digest, resp.text_len) < 0) {
        ret = set_errno_error(err, "receive object digest");
        close_nointr(sock);
        close_nointr(fd);
        free(object_name);
        return ret;
    }
    object_digest[resp.text_len] = '\0';
    if (!memfdbus_digest_is_valid(object_digest)) {
        close_nointr(sock);
        close_nointr(fd);
        free(object_name);
        return set_error(err, MEMFDBUS_RESULT_ERROR, EPROTO,
                         "broker sent an invalid object digest");
    }
    close_nointr(sock);

    ret = memfdbus_validate_fd(fd, resp.size, err);
    if (ret != MEMFDBUS_RESULT_OK) {
        close_nointr(fd);
        free(object_name);
        return ret;
    }

    out->id = resp.object_id;
    out->size = resp.size;
    out->fd = fd;
    memcpy(out->digest, object_digest, sizeof(out->digest));
    out->name = object_name;
    return MEMFDBUS_RESULT_OK;
}

int memfdbus_get_file_for_job(const char *socket_path, uint64_t id, const char *name,
                              const char *job_id, const char *out_path,
                              struct memfdbus_error *err)
{
    struct memfdbus_object object;
    char *buf;
    uint64_t copied = 0;
    int out_fd;
    int ret;

    if (!out_path) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "missing output path");
    }
    ret = memfdbus_get_fd_for_job(socket_path, id, name, job_id, &object, err);
    if (ret != MEMFDBUS_RESULT_OK) {
        return ret;
    }
    out_fd = strcmp(out_path, "-") == 0 ? STDOUT_FILENO :
        open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (out_fd < 0) {
        memfdbus_object_close(&object);
        return set_errno_error(err, "open output");
    }
    if (lseek(object.fd, 0, SEEK_SET) < 0) {
        if (out_fd != STDOUT_FILENO) {
            close_nointr(out_fd);
        }
        memfdbus_object_close(&object);
        return set_errno_error(err, "lseek object fd");
    }

    buf = malloc(MFDB_COPY_BUFSZ);
    if (!buf) {
        if (out_fd != STDOUT_FILENO) {
            close_nointr(out_fd);
        }
        memfdbus_object_close(&object);
        return set_errno_error(err, "malloc");
    }
    while (copied < object.size) {
        size_t want = MFDB_COPY_BUFSZ;
        ssize_t n;

        if (object.size - copied < want) {
            want = (size_t)(object.size - copied);
        }
        n = retry_read(object.fd, buf, want);
        if (n <= 0) {
            ret = n < 0 ? set_errno_error(err, "read object fd") :
                set_error(err, MEMFDBUS_RESULT_ERROR, EIO, "unexpected EOF from object fd");
            free(buf);
            if (out_fd != STDOUT_FILENO) {
                close_nointr(out_fd);
            }
            memfdbus_object_close(&object);
            return ret;
        }
        if (write_full(out_fd, buf, (size_t)n) < 0) {
            ret = set_errno_error(err, "write output");
            free(buf);
            if (out_fd != STDOUT_FILENO) {
                close_nointr(out_fd);
            }
            memfdbus_object_close(&object);
            return ret;
        }
        copied += (uint64_t)n;
    }

    free(buf);
    if (out_fd != STDOUT_FILENO) {
        close_nointr(out_fd);
    }
    memfdbus_object_close(&object);
    return MEMFDBUS_RESULT_OK;
}

int memfdbus_drop_for_job(const char *socket_path, uint64_t id, const char *name,
                          const char *job_id, uint64_t *out_id,
                          struct memfdbus_error *err)
{
    struct mfdb_msg resp;
    int fd = -1;
    int sock = send_selector_request(socket_path, MFDB_CMD_DROP, id, name, job_id, &resp, &fd, err);

    close_nointr(fd);
    if (sock < 0) {
        return sock;
    }
    close_nointr(sock);
    if (out_id) {
        *out_id = resp.object_id;
    }
    return MEMFDBUS_RESULT_OK;
}

int memfdbus_list_for_job(const char *socket_path, const char *job_id,
                          struct memfdbus_list *out, struct memfdbus_error *err)
{
    struct mfdb_msg req;
    struct mfdb_msg resp;
    uint32_t job_len = 0;
    int sock;
    int fd = -1;
    int ret;
    char *text;

    if (!out) {
        return set_error(err, MEMFDBUS_RESULT_BAD_REQUEST, EINVAL, "missing output list");
    }
    job_id = resolve_job_id(job_id);
    if (job_id) {
        job_len = job_len_or_error(job_id, "job_id", err);
        if (job_len == UINT32_MAX) {
            return err ? err->code : MEMFDBUS_RESULT_BAD_REQUEST;
        }
    }
    memset(out, 0, sizeof(*out));
    sock = connect_socket_api(socket_path, err);
    if (sock < 0) {
        return MEMFDBUS_RESULT_ERROR;
    }
    init_msg(&req, MFDB_CMD_LIST);
    req.job_len = job_len;
    if (send_msg_maybe_fd(sock, &req, -1) < 0) {
        close_nointr(sock);
        return set_errno_error(err, "send list request");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        return set_errno_error(err, "send job id");
    }
    ret = recv_response(sock, &resp, &fd, err);
    close_nointr(fd);
    if (ret != MEMFDBUS_RESULT_OK) {
        close_nointr(sock);
        return ret;
    }

    text = malloc((size_t)resp.text_len + 1);
    if (!text) {
        close_nointr(sock);
        return set_errno_error(err, "malloc");
    }
    if (resp.text_len && read_full(sock, text, resp.text_len) < 0) {
        ret = set_errno_error(err, "receive list");
        close_nointr(sock);
        free(text);
        return ret;
    }
    text[resp.text_len] = '\0';
    close_nointr(sock);

    out->text = text;
    out->len = resp.text_len;
    return MEMFDBUS_RESULT_OK;
}

int memfdbus_put_file(const char *socket_path, const char *path, const char *name,
                      uint64_t *out_id, struct memfdbus_error *err)
{
    return memfdbus_put_file_for_job(socket_path, path, name, NULL, NULL, out_id, err);
}

int memfdbus_put_fd(const char *socket_path, int input_fd, const char *name,
                    uint64_t *out_id, struct memfdbus_error *err)
{
    return memfdbus_put_fd_for_job(socket_path, input_fd, name, NULL, NULL, out_id, err);
}

int memfdbus_get_fd(const char *socket_path, uint64_t id, const char *name,
                    struct memfdbus_object *out, struct memfdbus_error *err)
{
    return memfdbus_get_fd_for_job(socket_path, id, name, NULL, out, err);
}

int memfdbus_get_file(const char *socket_path, uint64_t id, const char *name,
                      const char *out_path, struct memfdbus_error *err)
{
    return memfdbus_get_file_for_job(socket_path, id, name, NULL, out_path, err);
}

int memfdbus_drop(const char *socket_path, uint64_t id, const char *name,
                  uint64_t *out_id, struct memfdbus_error *err)
{
    return memfdbus_drop_for_job(socket_path, id, name, NULL, out_id, err);
}

int memfdbus_list(const char *socket_path, struct memfdbus_list *out,
                  struct memfdbus_error *err)
{
    return memfdbus_list_for_job(socket_path, NULL, out, err);
}

void memfdbus_object_close(struct memfdbus_object *object)
{
    if (!object) {
        return;
    }
    if (object->fd > 0) {
        close_nointr(object->fd);
    }
    free(object->name);
    object->id = 0;
    object->size = 0;
    object->fd = -1;
    memset(object->digest, 0, sizeof(object->digest));
    object->name = NULL;
}

void memfdbus_list_free(struct memfdbus_list *list)
{
    if (!list) {
        return;
    }
    free(list->text);
    list->text = NULL;
    list->len = 0;
}
