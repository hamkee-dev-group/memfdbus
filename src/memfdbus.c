#define _GNU_SOURCE

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
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
#define MFDB_DEFAULT_SOCKET "/tmp/memfdbus.sock"
#define MFDB_MAX_JOB_ID 256u
#define MFDB_MAX_NAME (64u * 1024u)
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

struct object {
    uint64_t id;
    uint64_t size;
    int fd;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    char *allowed_job;
    char *name;
    char *owner_job;
};

struct object_store {
    struct object *items;
    size_t len;
    size_t cap;
    uint64_t next_id;
    size_t max_name_bytes;
    size_t max_objects;
    size_t max_request_bytes;
    size_t max_list_bytes;
    uint64_t total_bytes;
    uint64_t max_total_bytes;
};

static volatile sig_atomic_t stop_broker;

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

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);

    if (!p) {
        die_errno("malloc");
    }
    return p;
}

static char *xstrdup(const char *s)
{
    char *p = strdup(s);

    if (!p) {
        die_errno("strdup");
    }
    return p;
}

static char *xstrdup_nullable(const char *s)
{
    return s ? xstrdup(s) : NULL;
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

static void close_nointr(int fd)
{
    if (fd >= 0) {
        while (close(fd) < 0 && errno == EINTR) {
        }
    }
}

static void remove_client_slot(int *clients, size_t *len, size_t idx)
{
    close_nointr(clients[idx]);
    if (idx + 1 < *len) {
        memmove(&clients[idx], &clients[idx + 1], (*len - idx - 1) * sizeof(clients[0]));
    }
    (*len)--;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash ? slash + 1 : path;
}

static uint64_t parse_id(const char *s)
{
    char *end = NULL;
    unsigned long long v;

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || !end || *end != '\0' || v == 0) {
        die("invalid object id: %s", s);
    }
    return (uint64_t)v;
}

static uint64_t parse_positive_u64_option(const char *flag, const char *s)
{
    char *end = NULL;
    unsigned long long v;

    if (!s[0]) {
        die("invalid %s: %s", flag, s);
    }
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') {
            die("invalid %s: %s", flag, s);
        }
    }

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || !end || *end != '\0' || v == 0) {
        die("invalid %s: %s", flag, s);
    }
    return (uint64_t)v;
}

static size_t parse_positive_size_option(const char *flag, const char *s)
{
    uint64_t v = parse_positive_u64_option(flag, s);

    if (v > SIZE_MAX) {
        die("invalid %s: %s", flag, s);
    }
    return (size_t)v;
}

static size_t parse_bounded_size_option(const char *flag, const char *s, size_t max_value)
{
    size_t v = parse_positive_size_option(flag, s);

    if (v > max_value) {
        die("invalid %s: %s", flag, s);
    }
    return v;
}

static int parse_positive_int_option(const char *flag, const char *s)
{
    uint64_t v = parse_positive_u64_option(flag, s);

    if (v > INT_MAX) {
        die("invalid %s: %s", flag, s);
    }
    return (int)v;
}

static bool fd_is_regular_file(int fd)
{
    struct stat st;

    if (fstat(fd, &st) < 0) {
        return false;
    }
    return S_ISREG(st.st_mode);
}

static bool copy_file_range_fallback_errno(int err)
{
    return err == ENOSYS || err == EXDEV || err == EINVAL || err == EOPNOTSUPP;
}

static ssize_t retry_copy_file_range(int in_fd, int out_fd, size_t len)
{
    ssize_t n;

    do {
        n = copy_file_range(in_fd, NULL, out_fd, NULL, len, 0);
    } while (n < 0 && errno == EINTR);
    return n;
}

static void buffered_copy_exact(int in_fd, int out_fd, uint64_t size)
{
    char *buf = xmalloc(MFDB_COPY_BUFSZ);
    uint64_t copied = 0;

    while (copied < size) {
        size_t want = MFDB_COPY_BUFSZ;
        ssize_t n;

        if (size - copied < want) {
            want = (size_t)(size - copied);
        }
        n = retry_read(in_fd, buf, want);
        if (n < 0) {
            free(buf);
            die_errno("read memfd");
        }
        if (n == 0) {
            free(buf);
            die("unexpected EOF from memfd");
        }
        if (write_full(out_fd, buf, (size_t)n) < 0) {
            free(buf);
            die_errno("write output");
        }
        copied += (uint64_t)n;
    }

    free(buf);
}

static bool try_copy_file_range_exact(int in_fd, int out_fd, uint64_t size, uint64_t *copied)
{
    *copied = 0;
    if (!fd_is_regular_file(in_fd) || !fd_is_regular_file(out_fd)) {
        return false;
    }
    while (*copied < size) {
        size_t want = MFDB_COPY_BUFSZ;
        ssize_t n;

        if (size - *copied < want) {
            want = (size_t)(size - *copied);
        }
        n = retry_copy_file_range(in_fd, out_fd, want);
        if (n > 0) {
            *copied += (uint64_t)n;
            continue;
        }
        if (n == 0) {
            die("unexpected EOF from memfd");
        }
        if (copy_file_range_fallback_errno(errno)) {
            return false;
        }
        die_errno("copy_file_range");
    }
    return true;
}

static const char *next_arg(int *i, int argc, char **argv, const char *flag)
{
    if (*i + 1 >= argc) {
        die("missing value for %s", flag);
    }
    return argv[++(*i)];
}

static uint32_t object_name_len_or_die(const char *name)
{
    size_t len = strlen(name);

    if (name[0] == '\0') {
        die("object name must not be empty");
    }
    if (len > MFDB_MAX_NAME) {
        die("object name too long");
    }
    return (uint32_t)len;
}

static uint32_t job_id_len_or_die(const char *flag, const char *job_id)
{
    size_t len;

    if (!job_id || job_id[0] == '\0') {
        die("%s requires a non-empty job id", flag);
    }
    len = strlen(job_id);
    if (len > MFDB_MAX_JOB_ID) {
        die("job id too long");
    }
    return (uint32_t)len;
}

static const char *job_id_from_env(void)
{
    const char *job_id = getenv("MEMFDBUS_JOB_ID");

    return job_id && job_id[0] ? job_id : NULL;
}

static bool job_id_matches(const char *lhs, const char *rhs)
{
    return lhs && rhs && strcmp(lhs, rhs) == 0;
}

static bool object_is_visible_to_job(const struct object *obj, const char *job_id)
{
    if (!job_id || job_id[0] == '\0') {
        return true;
    }
    if (!obj->owner_job) {
        return true;
    }
    if (job_id_matches(obj->owner_job, job_id)) {
        return true;
    }
    return job_id_matches(obj->allowed_job, job_id);
}

static bool object_can_drop_for_job(const struct object *obj, const char *job_id)
{
    if (!obj->owner_job) {
        return true;
    }
    if (!job_id || job_id[0] == '\0') {
        return true;
    }
    return job_id_matches(obj->owner_job, job_id);
}

static bool request_payload_exceeds(const struct mfdb_msg *req, size_t limit)
{
    const uint32_t parts[] = {req->name_len, req->text_len, req->job_len, req->allow_len};
    size_t sum = 0;

    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        if (parts[i] > limit - sum) {
            return true;
        }
        sum += parts[i];
    }
    return false;
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

static int connect_socket(const char *socket_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr;

    if (fd < 0) {
        die_errno("socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close_nointr(fd);
        die("socket path too long: %s", socket_path);
    }
    strcpy(addr.sun_path, socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close_nointr(fd);
        die_errno("connect");
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

    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        errno = EPIPE;
        return -1;
    }
    if ((size_t)n < sizeof(*msg)) {
        if (send_full(sock, p + n, sizeof(*msg) - (size_t)n) < 0) {
            return -1;
        }
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

static int send_error(int sock, uint16_t cmd, uint32_t status, const char *text)
{
    struct mfdb_msg resp;
    uint32_t len = text ? (uint32_t)strlen(text) : 0;

    init_msg(&resp, cmd);
    resp.status = status;
    resp.text_len = len;
    if (send_msg_maybe_fd(sock, &resp, -1) < 0) {
        return -1;
    }
    if (len && send_full(sock, text, len) < 0) {
        return -1;
    }
    return 0;
}

static void json_write_string(FILE *out, const char *s)
{
    if (!s) {
        fputs("null", out);
        return;
    }

    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", (unsigned int)*p);
            } else {
                fputc((int)*p, out);
            }
            break;
        }
    }
    fputc('"', out);
}

static void json_write_u64_or_null(FILE *out, uint64_t value, bool present)
{
    if (!present) {
        fputs("null", out);
        return;
    }
    fprintf(out, "%" PRIu64, value);
}

static void broker_log_event_detail(const char *op, const char *result, uint64_t object_id,
                                    const char *name, const uint64_t *size,
                                    const char *digest, const char *job_id,
                                    const char *selector, const char *error,
                                    const uint64_t *count)
{
    struct timespec ts = {0};
    uint64_t ts_ns = 0;

    if (clock_gettime(CLOCK_REALTIME, &ts) == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0) {
        ts_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    }

    fputc('{', stdout);
    fprintf(stdout, "\"ts_ns\":%" PRIu64, ts_ns);
    fputs(",\"op\":", stdout);
    json_write_string(stdout, op);
    fputs(",\"operation\":", stdout);
    json_write_string(stdout, op);
    fputs(",\"result\":", stdout);
    json_write_string(stdout, result);
    fputs(",\"selector\":", stdout);
    json_write_string(stdout, selector);
    fputs(",\"object_id\":", stdout);
    json_write_u64_or_null(stdout, object_id, object_id != 0);
    fputs(",\"name\":", stdout);
    json_write_string(stdout, name);
    fputs(",\"size\":", stdout);
    json_write_u64_or_null(stdout, size ? *size : 0, size != NULL);
    fputs(",\"count\":", stdout);
    json_write_u64_or_null(stdout, count ? *count : 0, count != NULL);
    fputs(",\"digest\":", stdout);
    json_write_string(stdout, digest);
    fputs(",\"job_id\":", stdout);
    json_write_string(stdout, job_id);
    fputs(",\"error\":", stdout);
    json_write_string(stdout, error);
    fputs("}\n", stdout);
    fflush(stdout);
}

static void broker_log_event(const char *op, const char *result, uint64_t object_id,
                             const char *name, const uint64_t *size,
                             const char *digest, const char *job_id)
{
    broker_log_event_detail(op, result, object_id, name, size, digest, job_id,
                            NULL, NULL, NULL);
}

static void recv_response_or_die(int sock, struct mfdb_msg *resp, int *fd)
{
    char *text = NULL;

    if (recv_msg_maybe_fd(sock, resp, fd) < 0) {
        die_errno("receive response");
    }
    if (!valid_msg(resp)) {
        die("invalid response from broker");
    }
    if (resp->status != MFDB_OK && resp->text_len) {
        text = xmalloc((size_t)resp->text_len + 1);
        if (read_full(sock, text, resp->text_len) < 0) {
            free(text);
            die_errno("receive response text");
        }
        text[resp->text_len] = '\0';
    }
    if (resp->status != MFDB_OK) {
        if (*fd >= 0) {
            close_nointr(*fd);
            *fd = -1;
        }
        die("broker error: %s", text ? text : "request failed");
    }
    free(text);
}

static int add_object(struct object_store *store, uint64_t size, int fd, const char *name,
                      const char *digest, const char *owner_job, const char *allowed_job,
                      uint64_t *id)
{
    struct object *items;

    if (store->len >= store->max_objects ||
        size > store->max_total_bytes - store->total_bytes) {
        return -2;
    }

    if (store->len == store->cap) {
        size_t new_cap = store->cap ? store->cap * 2 : 32;

        items = realloc(store->items, new_cap * sizeof(*items));
        if (!items) {
            return -1;
        }
        store->items = items;
        store->cap = new_cap;
    }

    *id = store->next_id++;
    store->items[store->len++] = (struct object){
        .id = *id,
        .size = size,
        .fd = fd,
        .allowed_job = xstrdup_nullable(allowed_job),
        .name = xstrdup(name),
        .owner_job = xstrdup_nullable(owner_job),
    };
    strcpy(store->items[store->len - 1].digest, digest);
    store->total_bytes += size;
    return 0;
}

static struct object *find_object(struct object_store *store, uint64_t id)
{
    for (size_t i = 0; i < store->len; i++) {
        if (store->items[i].id == id) {
            return &store->items[i];
        }
    }
    return NULL;
}

static struct object *find_latest_object_by_name(struct object_store *store, const char *name)
{
    for (size_t i = store->len; i > 0; i--) {
        struct object *obj = &store->items[i - 1];

        if (strcmp(obj->name, name) == 0) {
            return obj;
        }
    }
    return NULL;
}

static void remove_object_at(struct object_store *store, size_t idx)
{
    store->total_bytes -= store->items[idx].size;
    close_nointr(store->items[idx].fd);
    free(store->items[idx].allowed_job);
    free(store->items[idx].name);
    free(store->items[idx].owner_job);
    if (idx + 1 < store->len) {
        memmove(&store->items[idx], &store->items[idx + 1],
                (store->len - idx - 1) * sizeof(store->items[0]));
    }
    store->len--;
}

static struct object *find_object_with_index(struct object_store *store, uint64_t id, size_t *idx)
{
    for (size_t i = 0; i < store->len; i++) {
        if (store->items[i].id == id) {
            *idx = i;
            return &store->items[i];
        }
    }
    return NULL;
}

static struct object *find_latest_object_by_name_with_index(struct object_store *store,
                                                            const char *name, size_t *idx)
{
    for (size_t i = store->len; i > 0; i--) {
        struct object *obj = &store->items[i - 1];

        if (strcmp(obj->name, name) == 0) {
            *idx = i - 1;
            return obj;
        }
    }
    return NULL;
}

static void free_store(struct object_store *store)
{
    for (size_t i = 0; i < store->len; i++) {
        close_nointr(store->items[i].fd);
        free(store->items[i].allowed_job);
        free(store->items[i].name);
        free(store->items[i].owner_job);
    }
    free(store->items);
}

static int validate_sealed_memfd(int fd, uint64_t claimed_size, char *err, size_t err_len)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat st;
    int seals;

    if (fd < 0) {
        snprintf(err, err_len, "missing memfd descriptor");
        return -1;
    }
    if (fstat(fd, &st) < 0) {
        snprintf(err, err_len, "fstat failed: %s", strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(err, err_len, "descriptor is not a regular memfd-like file");
        return -1;
    }
    if ((uint64_t)st.st_size != claimed_size) {
        snprintf(err, err_len, "size mismatch: header=%" PRIu64 " fd=%" PRIu64,
                 claimed_size, (uint64_t)st.st_size);
        return -1;
    }
    seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        snprintf(err, err_len, "F_GET_SEALS failed: %s", strerror(errno));
        return -1;
    }
    if ((seals & required) != required) {
        snprintf(err, err_len, "fd is not fully immutable-sealed");
        return -1;
    }
    return 0;
}

static int verify_fd_digest(int fd, uint64_t size, const char *expected,
                            char *err, size_t err_len)
{
    struct memfdbus_sha256_ctx ctx;
    unsigned char raw[MEMFDBUS_SHA256_RAW_LEN];
    char actual[MEMFDBUS_DIGEST_BUFSZ];
    char *buf = malloc(MFDB_COPY_BUFSZ);
    uint64_t off = 0;

    if (!buf) {
        snprintf(err, err_len, "digest verification allocation failed");
        return -1;
    }
    memfdbus_sha256_init(&ctx);
    while (off < size) {
        size_t want = MFDB_COPY_BUFSZ;
        ssize_t n;

        if (size - off < want) {
            want = (size_t)(size - off);
        }
        do {
            n = pread(fd, buf, want, (off_t)off);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            snprintf(err, err_len, "digest verification read failed: %s", strerror(errno));
            free(buf);
            return -1;
        }
        if (n == 0) {
            snprintf(err, err_len, "digest verification short read");
            free(buf);
            return -1;
        }
        memfdbus_sha256_update(&ctx, buf, (size_t)n);
        off += (uint64_t)n;
    }
    free(buf);
    memfdbus_sha256_final(&ctx, raw);
    memfdbus_sha256_format(actual, raw);
    if (strcmp(actual, expected) != 0) {
        snprintf(err, err_len, "digest mismatch");
        return -1;
    }
    return 0;
}

static int reopen_object_fd(int fd)
{
    char path[64];

    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", fd) >= (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return open(path, O_RDWR | O_CLOEXEC);
}

static void handle_put(int client, struct object_store *store, const struct mfdb_msg *req, int fd)
{
    char *allowed_job = NULL;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    char *name = NULL;
    char *owner_job = NULL;
    char err[256];
    const char *error_text = NULL;
    uint64_t id;
    struct mfdb_msg resp;
    int add_ret;

    if (req->name_len > MFDB_MAX_NAME) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "name too long", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "name too long");
        return;
    }
    if (req->job_len > MFDB_MAX_JOB_ID) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "job id too long", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "job id too long");
        return;
    }
    if (req->allow_len > MFDB_MAX_JOB_ID) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "allowed job id too long", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "allowed job id too long");
        return;
    }
    if (request_payload_exceeds(req, store->max_request_bytes)) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "request payload exceeds broker limit", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST,
                   "request payload exceeds broker limit");
        return;
    }
    if (req->name_len > store->max_name_bytes) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "object name exceeds broker name limit", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST,
                   "object name exceeds broker name limit");
        return;
    }

    name = xmalloc((size_t)req->name_len + 1);
    if (read_full(client, name, req->name_len) < 0) {
        close_nointr(fd);
        free(name);
        broker_log_event_detail("put", "bad_request", 0, NULL, &req->size, NULL, NULL,
                                "name", "failed to read object name", NULL);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "failed to read object name");
        return;
    }
    name[req->name_len] = '\0';
    if (name[0] == '\0') {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, NULL, NULL,
                                "name", "name must not be empty", NULL);
        free(name);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "name must not be empty");
        return;
    }
    if (req->text_len != MEMFDBUS_DIGEST_STRLEN) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, NULL, NULL,
                                "name", "invalid object digest", NULL);
        free(name);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "invalid object digest");
        return;
    }
    if (read_full(client, digest, req->text_len) < 0) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, NULL, NULL,
                                "name", "failed to read object digest", NULL);
        free(name);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "failed to read object digest");
        return;
    }
    digest[req->text_len] = '\0';
    if (!memfdbus_digest_is_valid(digest)) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, NULL,
                                "name", "invalid object digest", NULL);
        free(name);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "invalid object digest");
        return;
    }
    if (req->allow_len && !req->job_len) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, NULL,
                                "name", "allowed job requires owner job", NULL);
        free(name);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "allowed job requires owner job");
        return;
    }
    if (req->job_len) {
        owner_job = xmalloc((size_t)req->job_len + 1);
        if (read_full(client, owner_job, req->job_len) < 0) {
            close_nointr(fd);
            broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, NULL,
                                    "name", "failed to read job id", NULL);
            free(name);
            free(owner_job);
            send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "failed to read job id");
            return;
        }
        owner_job[req->job_len] = '\0';
        if (owner_job[0] == '\0') {
            close_nointr(fd);
            broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, NULL,
                                    "name", "job id must not be empty", NULL);
            free(name);
            free(owner_job);
            send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "job id must not be empty");
            return;
        }
    }
    if (req->allow_len) {
        allowed_job = xmalloc((size_t)req->allow_len + 1);
        if (read_full(client, allowed_job, req->allow_len) < 0) {
            close_nointr(fd);
            broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, owner_job,
                                    "name", "failed to read allowed job id", NULL);
            free(allowed_job);
            free(name);
            free(owner_job);
            send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, "failed to read allowed job id");
            return;
        }
        allowed_job[req->allow_len] = '\0';
        if (allowed_job[0] == '\0') {
            close_nointr(fd);
            broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, owner_job,
                                    "name", "allowed job id must not be empty", NULL);
            free(allowed_job);
            free(name);
            free(owner_job);
            send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST,
                       "allowed job id must not be empty");
            return;
        }
    }

    if (validate_sealed_memfd(fd, req->size, err, sizeof(err)) < 0) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, owner_job,
                                "name", err, NULL);
        free(allowed_job);
        free(name);
        free(owner_job);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, err);
        return;
    }

    if (verify_fd_digest(fd, req->size, digest, err, sizeof(err)) < 0) {
        close_nointr(fd);
        broker_log_event_detail("put", "bad_request", 0, name, &req->size, digest, owner_job,
                                "name", err, NULL);
        free(allowed_job);
        free(name);
        free(owner_job);
        send_error(client, MFDB_CMD_PUT, MFDB_BAD_REQUEST, err);
        return;
    }

    add_ret = add_object(store, req->size, fd, name, digest, owner_job, allowed_job, &id);
    if (add_ret < 0) {
        close_nointr(fd);
        error_text = add_ret == -2 ? "broker object quota exceeded" :
                     "broker object store allocation failed";
        broker_log_event_detail("put", "error", 0, name, &req->size, digest, owner_job,
                                "name", error_text, NULL);
        free(allowed_job);
        free(name);
        free(owner_job);
        send_error(client, MFDB_CMD_PUT, MFDB_ERR, error_text);
        return;
    }

    init_msg(&resp, MFDB_CMD_PUT);
    resp.status = MFDB_OK;
    resp.object_id = id;
    resp.size = req->size;
    if (send_msg_maybe_fd(client, &resp, -1) < 0) {
         
    }
    broker_log_event("put", "ok", id, name, &req->size, digest, owner_job);
    free(allowed_job);
    free(name);
    free(owner_job);
}

static void handle_get(int client, struct object_store *store, const struct mfdb_msg *req)
{
    char *caller_job = NULL;
    struct object *obj = NULL;
    struct mfdb_msg resp;
    char *lookup_name = NULL;
    const char *selector = NULL;
    int send_fd = -1;

    if (req->name_len) {
        selector = "name";
    } else if (req->object_id) {
        selector = "id";
    }

    if (req->object_id && req->name_len) {
        broker_log_event_detail("get", "bad_request", req->object_id, NULL, NULL, NULL, NULL,
                                NULL, "specify object id or name, not both", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "specify object id or name, not both");
        return;
    }
    if (!req->object_id && !req->name_len) {
        broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                NULL, "missing object selector", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "missing object selector");
        return;
    }
    if (req->name_len > MFDB_MAX_NAME) {
        broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "name too long", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "name too long");
        return;
    }
    if (req->job_len > MFDB_MAX_JOB_ID) {
        broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                selector, "job id too long", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "job id too long");
        return;
    }
    if (request_payload_exceeds(req, store->max_request_bytes)) {
        broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "request payload exceeds broker limit", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST,
                   "request payload exceeds broker limit");
        return;
    }
    if (req->name_len > store->max_name_bytes) {
        broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "object name exceeds broker name limit", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST,
                   "object name exceeds broker name limit");
        return;
    }

    if (req->name_len) {
        lookup_name = xmalloc((size_t)req->name_len + 1);
        if (read_full(client, lookup_name, req->name_len) < 0) {
            broker_log_event_detail("get", "bad_request", 0, NULL, NULL, NULL, NULL,
                                    "name", "failed to read object name", NULL);
            send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "failed to read object name");
            free(lookup_name);
            return;
        }
        lookup_name[req->name_len] = '\0';
        obj = find_latest_object_by_name(store, lookup_name);
    } else {
        obj = find_object(store, req->object_id);
    }
    if (req->job_len) {
        caller_job = xmalloc((size_t)req->job_len + 1);
        if (read_full(client, caller_job, req->job_len) < 0) {
            broker_log_event_detail("get", "bad_request", req->object_id, lookup_name, NULL, NULL,
                                    NULL, selector, "failed to read job id", NULL);
            send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "failed to read job id");
            free(caller_job);
            free(lookup_name);
            return;
        }
        caller_job[req->job_len] = '\0';
        if (caller_job[0] == '\0') {
            broker_log_event_detail("get", "bad_request", req->object_id, lookup_name, NULL, NULL,
                                    NULL, selector, "job id must not be empty", NULL);
            send_error(client, MFDB_CMD_GET, MFDB_BAD_REQUEST, "job id must not be empty");
            free(caller_job);
            free(lookup_name);
            return;
        }
    }

    if (!obj) {
        broker_log_event_detail("get", "not_found", req->object_id, lookup_name, NULL, NULL, caller_job,
                                selector, "object not found", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_NOT_FOUND, "object not found");
        free(caller_job);
        free(lookup_name);
        return;
    }
    if (!object_is_visible_to_job(obj, caller_job)) {
        broker_log_event_detail("get", "forbidden", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "access denied", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_FORBIDDEN, "access denied");
        free(caller_job);
        free(lookup_name);
        return;
    }
    send_fd = reopen_object_fd(obj->fd);
    if (send_fd < 0) {
        broker_log_event_detail("get", "error", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "failed to reopen object fd", NULL);
        send_error(client, MFDB_CMD_GET, MFDB_ERR, "failed to reopen object fd");
        free(caller_job);
        free(lookup_name);
        return;
    }

    init_msg(&resp, MFDB_CMD_GET);
    resp.status = MFDB_OK;
    resp.object_id = obj->id;
    resp.size = obj->size;
    resp.name_len = (uint32_t)strlen(obj->name);
    resp.text_len = MEMFDBUS_DIGEST_STRLEN;
    if (send_msg_maybe_fd(client, &resp, send_fd) < 0) {
        broker_log_event_detail("get", "error", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "failed to send object response", NULL);
        close_nointr(send_fd);
        free(caller_job);
        free(lookup_name);
        return;
    }
    if (resp.name_len && send_full(client, obj->name, resp.name_len) < 0) {
        broker_log_event_detail("get", "error", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "failed to send object name", NULL);
        close_nointr(send_fd);
        free(caller_job);
        free(lookup_name);
        return;
    }
    if (send_full(client, obj->digest, resp.text_len) < 0) {
        broker_log_event_detail("get", "error", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "failed to send object digest", NULL);
        close_nointr(send_fd);
        free(caller_job);
        free(lookup_name);
        return;
    }
    broker_log_event_detail("get", "ok", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                            selector, NULL, NULL);
    close_nointr(send_fd);
    free(caller_job);
    free(lookup_name);
}

static char *build_list_text(struct object_store *store, const char *caller_job, uint32_t *out_len,
                             uint64_t *out_count)
{
    size_t max_text_len = store->max_list_bytes;
    size_t max_cap = max_text_len;
    size_t cap = max_cap < 1024 ? max_cap : 1024;
    uint64_t count = 0;
    size_t len = 0;
    char *buf = xmalloc(cap);

    if (max_cap < SIZE_MAX) {
        max_cap++;
    }

    buf[0] = '\0';
    for (size_t i = 0; i < store->len; i++) {
        struct object *obj = &store->items[i];
        const char *allowed_job = obj->allowed_job ? obj->allowed_job : "-";
        const char *owner_job = obj->owner_job ? obj->owner_job : "-";
        int needed;

        if (!object_is_visible_to_job(obj, caller_job)) {
            continue;
        }

        needed = snprintf(NULL, 0, "%" PRIu64 "\towner=%s\tallowed=%s\t%" PRIu64 "\t%s\t%s\n",
                          obj->id, owner_job, allowed_job, obj->size, obj->digest, obj->name);

        if (needed < 0) {
            free(buf);
            return NULL;
        }
        if (len + (size_t)needed > max_text_len) {
            free(buf);
            errno = E2BIG;
            return NULL;
        }
        if (len + (size_t)needed + 1 > cap) {
            while (len + (size_t)needed + 1 > cap) {
                size_t next = cap * 2;

                if (next <= cap || next > max_cap) {
                    next = max_cap;
                }
                if (next == cap) {
                    break;
                }
                cap = next;
            }
            if (len + (size_t)needed + 1 > cap) {
                free(buf);
                errno = E2BIG;
                return NULL;
            }
            char *new_buf = realloc(buf, cap);
            if (!new_buf) {
                free(buf);
                return NULL;
            }
            buf = new_buf;
        }
        snprintf(buf + len, cap - len, "%" PRIu64 "\towner=%s\tallowed=%s\t%" PRIu64 "\t%s\t%s\n",
                 obj->id, owner_job, allowed_job, obj->size, obj->digest, obj->name);
        len += (size_t)needed;
        count++;
    }
    if (len > UINT32_MAX) {
        free(buf);
        errno = EOVERFLOW;
        return NULL;
    }
    *out_count = count;
    *out_len = (uint32_t)len;
    return buf;
}

static void handle_list(int client, struct object_store *store, const struct mfdb_msg *req)
{
    char *caller_job = NULL;
    struct mfdb_msg resp;
    uint64_t count = 0;
    char *text;

    if (req->job_len > MFDB_MAX_JOB_ID) {
        broker_log_event_detail("list", "bad_request", 0, NULL, NULL, NULL, NULL,
                                NULL, "job id too long", NULL);
        send_error(client, MFDB_CMD_LIST, MFDB_BAD_REQUEST, "job id too long");
        return;
    }
    if (request_payload_exceeds(req, store->max_request_bytes)) {
        broker_log_event_detail("list", "bad_request", 0, NULL, NULL, NULL, NULL,
                                NULL, "request payload exceeds broker limit", NULL);
        send_error(client, MFDB_CMD_LIST, MFDB_BAD_REQUEST,
                   "request payload exceeds broker limit");
        return;
    }
    if (req->job_len) {
        caller_job = xmalloc((size_t)req->job_len + 1);
        if (read_full(client, caller_job, req->job_len) < 0) {
            broker_log_event_detail("list", "bad_request", 0, NULL, NULL, NULL, NULL,
                                    NULL, "failed to read job id", NULL);
            free(caller_job);
            send_error(client, MFDB_CMD_LIST, MFDB_BAD_REQUEST, "failed to read job id");
            return;
        }
        caller_job[req->job_len] = '\0';
        if (caller_job[0] == '\0') {
            broker_log_event_detail("list", "bad_request", 0, NULL, NULL, NULL, NULL,
                                    NULL, "job id must not be empty", NULL);
            free(caller_job);
            send_error(client, MFDB_CMD_LIST, MFDB_BAD_REQUEST, "job id must not be empty");
            return;
        }
    }

    init_msg(&resp, MFDB_CMD_LIST);
    resp.status = MFDB_OK;
    text = build_list_text(store, caller_job, &resp.text_len, &count);
    if (!text) {
        const char *error_text = errno == E2BIG ? "list response too large" :
                                 "failed to build object list";

        broker_log_event_detail("list", "error", 0, NULL, &count, NULL, caller_job,
                                NULL, error_text, &count);
        send_error(client, MFDB_CMD_LIST, MFDB_ERR, error_text);
        free(caller_job);
        return;
    }

    if (send_msg_maybe_fd(client, &resp, -1) < 0) {
        broker_log_event_detail("list", "error", 0, NULL, &count, NULL, caller_job,
                                NULL, "failed to send object list response", &count);
        free(text);
        free(caller_job);
        return;
    }
    if (resp.text_len && send_full(client, text, resp.text_len) < 0) {
        broker_log_event_detail("list", "error", 0, NULL, &count, NULL, caller_job,
                                NULL, "failed to send object list payload", &count);
        free(text);
        free(caller_job);
        return;
    }
    broker_log_event_detail("list", "ok", 0, NULL, &count, NULL, caller_job, NULL, NULL, &count);
    free(text);
    free(caller_job);
}

static void handle_drop(int client, struct object_store *store, const struct mfdb_msg *req)
{
    char *caller_job = NULL;
    struct object *obj = NULL;
    char dropped_digest[MEMFDBUS_DIGEST_BUFSZ];
    char *dropped_name = NULL;
    struct mfdb_msg resp;
    char *lookup_name = NULL;
    const char *selector = NULL;
    uint64_t id;
    uint64_t size;
    size_t idx = 0;

    if (req->name_len) {
        selector = "name";
    } else if (req->object_id) {
        selector = "id";
    }

    if (req->object_id && req->name_len) {
        broker_log_event_detail("drop", "bad_request", req->object_id, NULL, NULL, NULL, NULL,
                                NULL, "specify object id or name, not both", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "specify object id or name, not both");
        return;
    }
    if (!req->object_id && !req->name_len) {
        broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                NULL, "missing object selector", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "missing object selector");
        return;
    }
    if (req->name_len > MFDB_MAX_NAME) {
        broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "name too long", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "name too long");
        return;
    }
    if (req->job_len > MFDB_MAX_JOB_ID) {
        broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                selector, "job id too long", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "job id too long");
        return;
    }
    if (request_payload_exceeds(req, store->max_request_bytes)) {
        broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "request payload exceeds broker limit", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST,
                   "request payload exceeds broker limit");
        return;
    }
    if (req->name_len > store->max_name_bytes) {
        broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                "name", "object name exceeds broker name limit", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST,
                   "object name exceeds broker name limit");
        return;
    }

    if (req->name_len) {
        lookup_name = xmalloc((size_t)req->name_len + 1);
        if (read_full(client, lookup_name, req->name_len) < 0) {
            broker_log_event_detail("drop", "bad_request", 0, NULL, NULL, NULL, NULL,
                                    "name", "failed to read object name", NULL);
            send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "failed to read object name");
            free(lookup_name);
            return;
        }
        lookup_name[req->name_len] = '\0';
        obj = find_latest_object_by_name_with_index(store, lookup_name, &idx);
    } else {
        obj = find_object_with_index(store, req->object_id, &idx);
    }
    if (req->job_len) {
        caller_job = xmalloc((size_t)req->job_len + 1);
        if (read_full(client, caller_job, req->job_len) < 0) {
            broker_log_event_detail("drop", "bad_request", req->object_id, lookup_name, NULL, NULL,
                                    NULL, selector, "failed to read job id", NULL);
            send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "failed to read job id");
            free(caller_job);
            free(lookup_name);
            return;
        }
        caller_job[req->job_len] = '\0';
        if (caller_job[0] == '\0') {
            broker_log_event_detail("drop", "bad_request", req->object_id, lookup_name, NULL, NULL,
                                    NULL, selector, "job id must not be empty", NULL);
            send_error(client, MFDB_CMD_DROP, MFDB_BAD_REQUEST, "job id must not be empty");
            free(caller_job);
            free(lookup_name);
            return;
        }
    }

    if (!obj) {
        broker_log_event_detail("drop", "not_found", req->object_id, lookup_name, NULL, NULL, caller_job,
                                selector, "object not found", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_NOT_FOUND, "object not found");
        free(caller_job);
        free(lookup_name);
        return;
    }
    if (!object_can_drop_for_job(obj, caller_job)) {
        broker_log_event_detail("drop", "forbidden", obj->id, obj->name, &obj->size, obj->digest, caller_job,
                                selector, "access denied", NULL);
        send_error(client, MFDB_CMD_DROP, MFDB_FORBIDDEN, "access denied");
        free(caller_job);
        free(lookup_name);
        return;
    }

    id = obj->id;
    size = obj->size;
    dropped_name = xstrdup(obj->name);
    strcpy(dropped_digest, obj->digest);
    remove_object_at(store, idx);

    init_msg(&resp, MFDB_CMD_DROP);
    resp.status = MFDB_OK;
    resp.object_id = id;
    resp.size = size;
    send_msg_maybe_fd(client, &resp, -1);
    broker_log_event_detail("drop", "ok", id, dropped_name, &size, dropped_digest, caller_job,
                            selector, NULL, NULL);
    free(caller_job);
    free(dropped_name);
    free(lookup_name);
}

static void handle_client(int client, struct object_store *store)
{
    struct mfdb_msg req;
    int fd = -1;

    if (recv_msg_maybe_fd(client, &req, &fd) < 0) {
        close_nointr(fd);
        return;
    }
    if (!valid_msg(&req)) {
        close_nointr(fd);
        broker_log_event_detail("unknown", "bad_request", 0, NULL, NULL, NULL, NULL,
                                NULL, "invalid protocol header", NULL);
        send_error(client, 0, MFDB_BAD_REQUEST, "invalid protocol header");
        return;
    }

    switch (req.cmd) {
    case MFDB_CMD_PUT:
        handle_put(client, store, &req, fd);
        break;
    case MFDB_CMD_GET:
        close_nointr(fd);
        handle_get(client, store, &req);
        break;
    case MFDB_CMD_LIST:
        close_nointr(fd);
        handle_list(client, store, &req);
        break;
    case MFDB_CMD_DROP:
        close_nointr(fd);
        handle_drop(client, store, &req);
        break;
    default:
        close_nointr(fd);
        broker_log_event_detail("unknown", "bad_request", req.cmd, NULL, NULL, NULL, NULL,
                                NULL, "unknown command", NULL);
        send_error(client, req.cmd, MFDB_BAD_REQUEST, "unknown command");
        break;
    }
}

static void on_signal(int signo)
{
    (void)signo;
    stop_broker = 1;
}

static int run_broker(const char *socket_path, size_t max_name_bytes, size_t max_objects,
                      size_t max_request_bytes, size_t max_list_bytes,
                      uint64_t max_total_bytes, int listen_backlog, size_t max_clients)
{
    int *clients = NULL;
    size_t client_cap = 0;
    size_t client_len = 0;
    int srv;
    struct sockaddr_un addr;
    struct object_store store = {
        .next_id = 1,
        .max_name_bytes = max_name_bytes,
        .max_objects = max_objects,
        .max_request_bytes = max_request_bytes,
        .max_list_bytes = max_list_bytes,
        .max_total_bytes = max_total_bytes,
    };
    struct sigaction sa;
    struct stat existing;

    srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv < 0) {
        die_errno("socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close_nointr(srv);
        die("socket path too long: %s", socket_path);
    }
    strcpy(addr.sun_path, socket_path);

    if (lstat(socket_path, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) {
            close_nointr(srv);
            die("refusing to unlink non-socket path: %s", socket_path);
        }
        if (unlink(socket_path) < 0) {
            close_nointr(srv);
            die_errno("unlink stale socket");
        }
    } else if (errno != ENOENT) {
        close_nointr(srv);
        die_errno("lstat socket path");
    }
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close_nointr(srv);
        die_errno("bind");
    }
    if (fcntl(srv, F_SETFL, O_NONBLOCK) < 0) {
        close_nointr(srv);
        unlink(socket_path);
        die_errno("fcntl O_NONBLOCK");
    }
    if (listen(srv, listen_backlog) < 0) {
        close_nointr(srv);
        unlink(socket_path);
        die_errno("listen");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("memfdbus broker listening on %s\n", socket_path);
    fflush(stdout);

    while (!stop_broker) {
        struct pollfd *pfds;
        int ready;
        size_t nfds = 1 + client_len;

        pfds = xmalloc(nfds * sizeof(*pfds));
        pfds[0].fd = srv;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        for (size_t i = 0; i < client_len; i++) {
            pfds[i + 1].fd = clients[i];
            pfds[i + 1].events = POLLIN;
            pfds[i + 1].revents = 0;
        }

        ready = poll(pfds, nfds, 250);
        if (ready < 0) {
            free(pfds);
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        if (ready == 0) {
            free(pfds);
            continue;
        }

        if (pfds[0].revents & POLLIN) {
            for (;;) {
                int client = accept4(srv, NULL, NULL, SOCK_CLOEXEC);

                if (client < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        break;
                    }
                    perror("accept");
                    stop_broker = 1;
                    break;
                }
                if (client_len >= max_clients) {
                    broker_log_event_detail("unknown", "error", 0, NULL, NULL, NULL, NULL,
                                            NULL, "broker client quota exceeded", NULL);
                    send_error(client, 0, MFDB_ERR, "broker client quota exceeded");
                    close_nointr(client);
                    continue;
                }
                if (client_len == client_cap) {
                    size_t new_cap = client_cap ? client_cap * 2 : 16;
                    int *new_clients = realloc(clients, new_cap * sizeof(*new_clients));

                    if (!new_clients) {
                        close_nointr(client);
                        free(pfds);
                        close_nointr(srv);
                        unlink(socket_path);
                        free_store(&store);
                        free(clients);
                        die_errno("realloc clients");
                    }
                    clients = new_clients;
                    client_cap = new_cap;
                }
                clients[client_len++] = client;
            }
        }

        for (size_t i = 0; i < client_len;) {
            short revents = pfds[i + 1].revents;

            if (revents & POLLIN) {
                handle_client(clients[i], &store);
                remove_client_slot(clients, &client_len, i);
                continue;
            }
            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                remove_client_slot(clients, &client_len, i);
                continue;
            }
            i++;
        }
        free(pfds);
    }

    for (size_t i = 0; i < client_len; i++) {
        close_nointr(clients[i]);
    }
    free(clients);
    close_nointr(srv);
    unlink(socket_path);
    free_store(&store);
    return 0;
}

static uint64_t copy_to_memfd(const char *path, int memfd, char digest[MEMFDBUS_DIGEST_BUFSZ])
{
    struct memfdbus_sha256_ctx sha;
    unsigned char raw_digest[MEMFDBUS_SHA256_RAW_LEN];
    char *buf = xmalloc(MFDB_COPY_BUFSZ);
    int in = STDIN_FILENO;
    uint64_t total = 0;

    if (strcmp(path, "-") != 0) {
        in = open(path, O_RDONLY | O_CLOEXEC);
        if (in < 0) {
            free(buf);
            die_errno("open input");
        }
    }

    memfdbus_sha256_init(&sha);
    for (;;) {
        ssize_t n = retry_read(in, buf, MFDB_COPY_BUFSZ);

        if (n < 0) {
            free(buf);
            if (in != STDIN_FILENO) {
                close_nointr(in);
            }
            die_errno("read input");
        }
        if (n == 0) {
            break;
        }
        memfdbus_sha256_update(&sha, buf, (size_t)n);
        if (write_full(memfd, buf, (size_t)n) < 0) {
            free(buf);
            if (in != STDIN_FILENO) {
                close_nointr(in);
            }
            die_errno("write destination");
        }
        total += (uint64_t)n;
    }

    memfdbus_sha256_final(&sha, raw_digest);
    memfdbus_sha256_format(digest, raw_digest);
    free(buf);
    if (in != STDIN_FILENO) {
        close_nointr(in);
    }
    return total;
}

static int make_sealed_memfd_from_file(const char *path, const char *name, uint64_t *size,
                                       char digest[MEMFDBUS_DIGEST_BUFSZ])
{
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int fd = memfd_create_compat(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd < 0) {
        die_errno("memfd_create");
    }
    *size = copy_to_memfd(path, fd, digest);
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close_nointr(fd);
        die_errno("lseek memfd");
    }
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        close_nointr(fd);
        die_errno("F_ADD_SEALS");
    }
    return fd;
}

static int open_output(const char *path)
{
    int fd;

    if (strcmp(path, "-") == 0) {
        return STDOUT_FILENO;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        die_errno("open output");
    }
    return fd;
}

static void copy_from_fd_to_output(int fd, uint64_t size, const char *out_path)
{
    int out = open_output(out_path);
    uint64_t copied = 0;

    if (lseek(fd, 0, SEEK_SET) < 0) {
        if (out != STDOUT_FILENO) {
            close_nointr(out);
        }
        die_errno("lseek memfd");
    }
    if (!try_copy_file_range_exact(fd, out, size, &copied)) {
        buffered_copy_exact(fd, out, size - copied);
    }

    if (out != STDOUT_FILENO) {
        close_nointr(out);
    }
}

static void set_env_u64(const char *name, uint64_t value)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRIu64, value);
    if (setenv(name, buf, 1) < 0) {
        die_errno("setenv");
    }
}

static void set_env_int(const char *name, int value)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%d", value);
    if (setenv(name, buf, 1) < 0) {
        die_errno("setenv");
    }
}

static int fetch_object_fd(const char *socket_path, uint64_t id, const char *lookup_name,
                           const char *job_id, struct mfdb_msg *resp, char **out_name,
                           char out_digest[MEMFDBUS_DIGEST_BUFSZ])
{
    struct mfdb_msg req;
    uint32_t job_len = job_id ? job_id_len_or_die("--job-id", job_id) : 0;
    int sock;
    int fd = -1;
    char *name;
    char err[256];

    sock = connect_socket(socket_path);
    init_msg(&req, MFDB_CMD_GET);
    req.object_id = id;
    req.job_len = job_len;
    req.name_len = lookup_name ? object_name_len_or_die(lookup_name) : 0;
    if (send_msg_maybe_fd(sock, &req, -1) < 0) {
        close_nointr(sock);
        die_errno("send get request");
    }
    if (req.name_len && send_full(sock, lookup_name, req.name_len) < 0) {
        close_nointr(sock);
        die_errno("send object name");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        die_errno("send job id");
    }
    recv_response_or_die(sock, resp, &fd);
    if (fd < 0) {
        close_nointr(sock);
        die("broker did not send an object fd");
    }
    if (resp->name_len > MFDB_MAX_NAME) {
        close_nointr(sock);
        close_nointr(fd);
        die("broker sent an oversized object name");
    }
    if (resp->text_len != MEMFDBUS_DIGEST_STRLEN) {
        close_nointr(sock);
        close_nointr(fd);
        die("broker sent an invalid object digest");
    }
    name = xmalloc((size_t)resp->name_len + 1);
    if (read_full(sock, name, resp->name_len) < 0) {
        close_nointr(sock);
        close_nointr(fd);
        free(name);
        die_errno("receive object name");
    }
    name[resp->name_len] = '\0';
    if (read_full(sock, out_digest, resp->text_len) < 0) {
        close_nointr(sock);
        close_nointr(fd);
        free(name);
        die_errno("receive object digest");
    }
    out_digest[resp->text_len] = '\0';
    if (!memfdbus_digest_is_valid(out_digest)) {
        close_nointr(sock);
        close_nointr(fd);
        free(name);
        die("broker sent an invalid object digest");
    }
    close_nointr(sock);

    if (validate_sealed_memfd(fd, resp->size, err, sizeof(err)) < 0) {
        close_nointr(fd);
        free(name);
        die("broker sent an invalid object fd: %s", err);
    }

    *out_name = name;
    return fd;
}

static void cmd_put(int argc, char **argv)
{
    const char *socket_path = MFDB_DEFAULT_SOCKET;
    const char *allow_job = NULL;
    const char *publish_name = NULL;
    const char *job_id = job_id_from_env();
    const char *path = NULL;
    const char *name = NULL;
    bool content_addressed = false;
    struct mfdb_msg req;
    struct mfdb_msg resp;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    uint32_t allow_len = 0;
    uint32_t job_len = 0;
    uint64_t size;
    uint32_t name_len;
    int memfd;
    int sock;
    int resp_fd = -1;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_path = next_arg(&i, argc, argv, "--socket");
        } else if (strcmp(argv[i], "--name") == 0) {
            name = next_arg(&i, argc, argv, "--name");
        } else if (strcmp(argv[i], "--content-addressed") == 0) {
            content_addressed = true;
        } else if (strcmp(argv[i], "--job-id") == 0) {
            job_id = next_arg(&i, argc, argv, "--job-id");
        } else if (strcmp(argv[i], "--allow-job") == 0) {
            allow_job = next_arg(&i, argc, argv, "--allow-job");
        } else if (!path) {
            path = argv[i];
        } else {
            die("unexpected argument: %s", argv[i]);
        }
    }
    if (!path) {
        die("usage: memfdbus put FILE [--name NAME | --content-addressed]\n"
            "   [--job-id JOB] [--allow-job JOB] [--socket PATH]");
    }
    if (content_addressed && name) {
        die("--content-addressed cannot be combined with --name");
    }
    if (!name) {
        name = strcmp(path, "-") == 0 ? "stdin" : base_name(path);
    }
    if (allow_job && !job_id) {
        die("--allow-job requires --job-id or MEMFDBUS_JOB_ID");
    }
    job_len = job_id ? job_id_len_or_die("--job-id", job_id) : 0;
    allow_len = allow_job ? job_id_len_or_die("--allow-job", allow_job) : 0;
    memfd = make_sealed_memfd_from_file(path, name, &size, digest);
    publish_name = content_addressed ? digest : name;
    name_len = object_name_len_or_die(publish_name);
    sock = connect_socket(socket_path);

    init_msg(&req, MFDB_CMD_PUT);
    req.allow_len = allow_len;
    req.job_len = job_len;
    req.size = size;
    req.name_len = name_len;
    req.text_len = MEMFDBUS_DIGEST_STRLEN;
    if (send_msg_maybe_fd(sock, &req, memfd) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        die_errno("send put request");
    }
    if (req.name_len && send_full(sock, publish_name, req.name_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        die_errno("send object name");
    }
    if (send_full(sock, digest, req.text_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        die_errno("send object digest");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        die_errno("send job id");
    }
    if (req.allow_len && send_full(sock, allow_job, req.allow_len) < 0) {
        close_nointr(sock);
        close_nointr(memfd);
        die_errno("send allowed job id");
    }

    recv_response_or_die(sock, &resp, &resp_fd);
    close_nointr(resp_fd);
    printf("%" PRIu64 "\n", resp.object_id);
    close_nointr(sock);
    close_nointr(memfd);
}

static void cmd_get(int argc, char **argv)
{
    const char *socket_path = MFDB_DEFAULT_SOCKET;
    const char *job_id = job_id_from_env();
    const char *out_path = NULL;
    const char *lookup_name = NULL;
    uint64_t id = 0;
    struct mfdb_msg resp;
    int fd = -1;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    char *name = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_path = next_arg(&i, argc, argv, "--socket");
        } else if (strcmp(argv[i], "--job-id") == 0) {
            job_id = next_arg(&i, argc, argv, "--job-id");
        } else if (strcmp(argv[i], "--name") == 0) {
            lookup_name = next_arg(&i, argc, argv, "--name");
        } else if (!lookup_name && !id) {
            id = parse_id(argv[i]);
        } else if (!out_path) {
            out_path = argv[i];
        } else {
            die("unexpected argument: %s", argv[i]);
        }
    }
    if (((id != 0) == (lookup_name != NULL)) || !out_path) {
        die("usage: memfdbus get OBJECT_ID OUT [--job-id JOB] [--socket PATH]\n"
            "   or: memfdbus get --name NAME OUT [--job-id JOB] [--socket PATH]");
    }
    if (lookup_name) {
        object_name_len_or_die(lookup_name);
    }

    fd = fetch_object_fd(socket_path, id, lookup_name, job_id, &resp, &name, digest);
    copy_from_fd_to_output(fd, resp.size, out_path);
    free(name);
    close_nointr(fd);
}

static void cmd_exec(int argc, char **argv)
{
    const char *socket_path = MFDB_DEFAULT_SOCKET;
    const char *job_id = job_id_from_env();
    const char *lookup_name = NULL;
    uint64_t id = 0;
    struct mfdb_msg resp;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    char *name = NULL;
    int fd;
    int cmd_index = -1;
    int flags;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_path = next_arg(&i, argc, argv, "--socket");
        } else if (strcmp(argv[i], "--job-id") == 0) {
            job_id = next_arg(&i, argc, argv, "--job-id");
        } else if (strcmp(argv[i], "--name") == 0) {
            lookup_name = next_arg(&i, argc, argv, "--name");
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_index = i + 1;
            break;
        } else if (!id) {
            id = parse_id(argv[i]);
        } else {
            die("unexpected argument before --: %s", argv[i]);
        }
    }
    if (((id != 0) == (lookup_name != NULL)) || cmd_index < 0 || cmd_index >= argc) {
        die("usage: memfdbus exec OBJECT_ID [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]\n"
            "   or: memfdbus exec --name NAME [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]");
    }
    if (lookup_name) {
        object_name_len_or_die(lookup_name);
    }

    fd = fetch_object_fd(socket_path, id, lookup_name, job_id, &resp, &name, digest);
    flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        close_nointr(fd);
        free(name);
        die_errno("F_GETFD");
    }
    if (fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
        close_nointr(fd);
        free(name);
        die_errno("F_SETFD");
    }

    set_env_int("MEMFDBUS_FD", fd);
    set_env_u64("MEMFDBUS_OBJECT_ID", resp.object_id);
    set_env_u64("MEMFDBUS_SIZE", resp.size);
    if (setenv("MEMFDBUS_DIGEST", digest, 1) < 0) {
        close_nointr(fd);
        free(name);
        die_errno("setenv");
    }
    if (setenv("MEMFDBUS_NAME", name, 1) < 0) {
        close_nointr(fd);
        free(name);
        die_errno("setenv");
    }

    execvp(argv[cmd_index], &argv[cmd_index]);
    close_nointr(fd);
    free(name);
    die_errno("execvp");
}

static void cmd_list(int argc, char **argv)
{
    const char *socket_path = MFDB_DEFAULT_SOCKET;
    const char *job_id = job_id_from_env();
    struct mfdb_msg req;
    struct mfdb_msg resp;
    uint32_t job_len = 0;
    int sock;
    int fd = -1;
    char *text = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_path = next_arg(&i, argc, argv, "--socket");
        } else if (strcmp(argv[i], "--job-id") == 0) {
            job_id = next_arg(&i, argc, argv, "--job-id");
        } else {
            die("unexpected argument: %s", argv[i]);
        }
    }
    job_len = job_id ? job_id_len_or_die("--job-id", job_id) : 0;

    sock = connect_socket(socket_path);
    init_msg(&req, MFDB_CMD_LIST);
    req.job_len = job_len;
    if (send_msg_maybe_fd(sock, &req, -1) < 0) {
        close_nointr(sock);
        die_errno("send list request");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        die_errno("send job id");
    }
    recv_response_or_die(sock, &resp, &fd);
    close_nointr(fd);
    if (resp.text_len) {
        text = xmalloc((size_t)resp.text_len + 1);
        if (read_full(sock, text, resp.text_len) < 0) {
            close_nointr(sock);
            free(text);
            die_errno("receive list");
        }
        text[resp.text_len] = '\0';
        fputs(text, stdout);
        free(text);
    }
    close_nointr(sock);
}

static void cmd_drop(int argc, char **argv)
{
    const char *socket_path = MFDB_DEFAULT_SOCKET;
    const char *job_id = job_id_from_env();
    const char *lookup_name = NULL;
    uint64_t id = 0;
    struct mfdb_msg req;
    struct mfdb_msg resp;
    uint32_t job_len = 0;
    int sock;
    int fd = -1;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_path = next_arg(&i, argc, argv, "--socket");
        } else if (strcmp(argv[i], "--job-id") == 0) {
            job_id = next_arg(&i, argc, argv, "--job-id");
        } else if (strcmp(argv[i], "--name") == 0) {
            lookup_name = next_arg(&i, argc, argv, "--name");
        } else if (!lookup_name && !id) {
            id = parse_id(argv[i]);
        } else {
            die("unexpected argument: %s", argv[i]);
        }
    }
    if ((id != 0) == (lookup_name != NULL)) {
        die("usage: memfdbus drop OBJECT_ID [--job-id JOB] [--socket PATH]\n"
            "   or: memfdbus drop --name NAME [--job-id JOB] [--socket PATH]");
    }
    if (lookup_name) {
        object_name_len_or_die(lookup_name);
    }
    job_len = job_id ? job_id_len_or_die("--job-id", job_id) : 0;

    sock = connect_socket(socket_path);
    init_msg(&req, MFDB_CMD_DROP);
    req.job_len = job_len;
    req.object_id = id;
    req.name_len = lookup_name ? (uint32_t)strlen(lookup_name) : 0;
    if (send_msg_maybe_fd(sock, &req, -1) < 0) {
        close_nointr(sock);
        die_errno("send drop request");
    }
    if (req.name_len && send_full(sock, lookup_name, req.name_len) < 0) {
        close_nointr(sock);
        die_errno("send object name");
    }
    if (req.job_len && send_full(sock, job_id, req.job_len) < 0) {
        close_nointr(sock);
        die_errno("send job id");
    }
    recv_response_or_die(sock, &resp, &fd);
    close_nointr(fd);
    printf("%" PRIu64 "\n", resp.object_id);
    close_nointr(sock);
}

static void usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  memfdbus broker [--socket PATH] [--max-name-bytes N] [--max-objects N]\n"
            "                  [--max-request-bytes N] [--max-list-bytes N]\n"
            "                  [--max-total-bytes N] [--listen-backlog N]\n"
            "                  [--max-clients N]\n"
            "  memfdbus put FILE [--name NAME | --content-addressed]\n"
            "               [--job-id JOB] [--allow-job JOB] [--socket PATH]\n"
            "  memfdbus get OBJECT_ID OUT [--job-id JOB] [--socket PATH]\n"
            "  memfdbus get --name NAME OUT [--job-id JOB] [--socket PATH]\n"
            "  memfdbus exec OBJECT_ID [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]\n"
            "  memfdbus exec --name NAME [--job-id JOB] [--socket PATH] -- COMMAND [ARG...]\n"
            "  memfdbus drop OBJECT_ID [--job-id JOB] [--socket PATH]\n"
            "  memfdbus drop --name NAME [--job-id JOB] [--socket PATH]\n"
            "  memfdbus list [--job-id JOB] [--socket PATH]\n");
}

int main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 1 : 0;
    }

    cmd = argv[1];
    if (strcmp(cmd, "broker") == 0) {
        const char *socket_path = MFDB_DEFAULT_SOCKET;
        size_t max_name_bytes = MFDB_MAX_NAME;
        size_t max_objects = SIZE_MAX;
        size_t max_request_bytes = UINT32_MAX;
        size_t max_list_bytes = UINT32_MAX;
        size_t max_clients = 128;
        uint64_t max_total_bytes = UINT64_MAX;
        int listen_backlog = 128;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--socket") == 0) {
                socket_path = next_arg(&i, argc, argv, "--socket");
            } else if (strcmp(argv[i], "--max-name-bytes") == 0) {
                max_name_bytes = parse_bounded_size_option("--max-name-bytes",
                                                           next_arg(&i, argc, argv,
                                                                    "--max-name-bytes"),
                                                           MFDB_MAX_NAME);
            } else if (strcmp(argv[i], "--max-objects") == 0) {
                max_objects = parse_positive_size_option("--max-objects",
                                                         next_arg(&i, argc, argv, "--max-objects"));
            } else if (strcmp(argv[i], "--max-request-bytes") == 0) {
                max_request_bytes = parse_bounded_size_option("--max-request-bytes",
                                                              next_arg(&i, argc, argv,
                                                                       "--max-request-bytes"),
                                                              UINT32_MAX);
            } else if (strcmp(argv[i], "--max-list-bytes") == 0) {
                max_list_bytes = parse_bounded_size_option("--max-list-bytes",
                                                           next_arg(&i, argc, argv,
                                                                    "--max-list-bytes"),
                                                           UINT32_MAX);
            } else if (strcmp(argv[i], "--max-total-bytes") == 0) {
                max_total_bytes = parse_positive_u64_option("--max-total-bytes",
                                                            next_arg(&i, argc, argv,
                                                                     "--max-total-bytes"));
            } else if (strcmp(argv[i], "--listen-backlog") == 0) {
                listen_backlog = parse_positive_int_option("--listen-backlog",
                                                           next_arg(&i, argc, argv,
                                                                    "--listen-backlog"));
            } else if (strcmp(argv[i], "--max-clients") == 0) {
                max_clients = parse_positive_size_option("--max-clients",
                                                         next_arg(&i, argc, argv,
                                                                  "--max-clients"));
            } else {
                die("unexpected argument: %s", argv[i]);
            }
        }
        return run_broker(socket_path, max_name_bytes, max_objects, max_request_bytes,
                          max_list_bytes, max_total_bytes, listen_backlog, max_clients);
    }
    if (strcmp(cmd, "put") == 0) {
        cmd_put(argc - 2, argv + 2);
        return 0;
    }
    if (strcmp(cmd, "get") == 0) {
        cmd_get(argc - 2, argv + 2);
        return 0;
    }
    if (strcmp(cmd, "exec") == 0) {
        cmd_exec(argc - 2, argv + 2);
        return 0;
    }
    if (strcmp(cmd, "list") == 0) {
        cmd_list(argc - 2, argv + 2);
        return 0;
    }
    if (strcmp(cmd, "drop") == 0) {
        cmd_drop(argc - 2, argv + 2);
        return 0;
    }

    usage(stderr);
    return 1;
}
