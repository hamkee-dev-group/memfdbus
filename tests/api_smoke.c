#define _GNU_SOURCE

#include "memfdbus.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

static void fail_api(const char *what, const struct memfdbus_error *err)
{
    fprintf(stderr, "%s: %s\n", what, memfdbus_error_message(err));
    exit(1);
}

static void fail_errno(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static uint64_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0) {
        fail_errno("stat payload");
    }
    return (uint64_t)st.st_size;
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
            fail_errno("read payload");
        }
        if (n == 0) {
            fprintf(stderr, "unexpected EOF\n");
            exit(1);
        }
        p += n;
        len -= (size_t)n;
    }
}

static void compare_mapping(const void *mapped, uint64_t size, const char *path)
{
    const unsigned char *mem = mapped;
    unsigned char buf[65536];
    uint64_t off = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        fail_errno("open payload");
    }
    while (off < size) {
        size_t want = sizeof(buf);

        if (size - off < want) {
            want = (size_t)(size - off);
        }
        read_full_or_die(fd, buf, want);
        if (memcmp(mem + off, buf, want) != 0) {
            fprintf(stderr, "mapped object did not match payload\n");
            exit(1);
        }
        off += want;
    }
    close(fd);
}

static void compare_fd_contents(int fd, uint64_t size, const char *path)
{
    unsigned char got[65536];
    unsigned char want[65536];
    uint64_t off = 0;
    int expected_fd = open(path, O_RDONLY | O_CLOEXEC);

    if (expected_fd < 0) {
        fail_errno("open expected payload");
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fail_errno("lseek held fd");
    }
    while (off < size) {
        size_t chunk = sizeof(got);
        ssize_t got_n;
        ssize_t want_n;

        if (size - off < chunk) {
            chunk = (size_t)(size - off);
        }
        got_n = read(fd, got, chunk);
        want_n = read(expected_fd, want, chunk);
        if (got_n != (ssize_t)chunk || want_n != (ssize_t)chunk) {
            fprintf(stderr, "held fd read length mismatch\n");
            exit(1);
        }
        if (memcmp(got, want, chunk) != 0) {
            fprintf(stderr, "held fd content mismatch\n");
            exit(1);
        }
        off += chunk;
    }
    close(expected_fd);
}

static void expect_retained_object(struct memfdbus_object *object, const char *path,
                                   struct memfdbus_error *err)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals;
    void *mapped;

    compare_fd_contents(object->fd, object->size, path);
    mapped = mmap(NULL, (size_t)object->size, PROT_READ, MAP_SHARED, object->fd, 0);
    if (mapped == MAP_FAILED) {
        fail_errno("mmap retained fd");
    }
    compare_mapping(mapped, object->size, path);
    munmap(mapped, (size_t)object->size);
    if (memfdbus_validate_fd(object->fd, object->size, err) != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_validate_fd retained", err);
    }
    seals = fcntl(object->fd, F_GET_SEALS);
    if (seals < 0) {
        fail_errno("F_GET_SEALS retained");
    }
    if ((seals & required) != required) {
        fprintf(stderr, "retained fd lost immutable seals\n");
        exit(1);
    }
    errno = 0;
    if (pwrite(object->fd, "x", 1, 0) >= 0 || errno != EPERM) {
        fprintf(stderr, "retained fd unexpectedly became writable\n");
        exit(1);
    }
}

static void expect_digest(const char *digest)
{
    if (strncmp(digest, "sha256:", 7) != 0) {
        fprintf(stderr, "digest missing sha256 prefix\n");
        exit(1);
    }
    for (size_t i = 7; i < MEMFDBUS_DIGEST_STRLEN; i++) {
        if ((digest[i] < '0' || digest[i] > '9') &&
            (digest[i] < 'a' || digest[i] > 'f')) {
            fprintf(stderr, "digest contains non-hex characters\n");
            exit(1);
        }
    }
    if (digest[MEMFDBUS_DIGEST_STRLEN] != '\0') {
        fprintf(stderr, "digest length mismatch\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    struct memfdbus_error err = {0};
    struct memfdbus_object object;
    struct memfdbus_object object_copy;
    struct memfdbus_object object_v2;
    struct memfdbus_list list;
    uint64_t id;
    uint64_t copy_id;
    uint64_t held_id;
    uint64_t v2_id;
    uint64_t policy_id;
    uint64_t republish_id;
    uint64_t republish_id_v2;
    uint64_t dropped;
    uint64_t size;
    char diff_template[] = "/tmp/memfdbus-api-diff-XXXXXX";
    char republish_template[] = "/tmp/memfdbus-api-republish-XXXXXX";
    char object_digest[MEMFDBUS_DIGEST_BUFSZ];
    char object_copy_digest[MEMFDBUS_DIGEST_BUFSZ];
    char object_v2_digest[MEMFDBUS_DIGEST_BUFSZ];
    void *mapped;
    int payload_fd;
    int diff_fd;
    int republish_fd;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "usage: api_smoke SOCKET PAYLOAD\n");
        return 1;
    }

    size = file_size(argv[2]);
    ret = memfdbus_put_file(argv[1], argv[2], "api-object", &id, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file", &err);
    }
    payload_fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (payload_fd < 0) {
        fail_errno("open payload for memfdbus_put_fd");
    }
    ret = memfdbus_put_fd(argv[1], payload_fd, "api-object-copy", &copy_id, &err);
    close(payload_fd);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_fd", &err);
    }
    diff_fd = mkstemp(diff_template);
    if (diff_fd < 0) {
        fail_errno("mkstemp diff payload");
    }
    if (write(diff_fd, "api-different-payload\n",
              strlen("api-different-payload\n")) != (ssize_t)strlen("api-different-payload\n")) {
        fail_errno("write diff payload");
    }
    close(diff_fd);
    ret = memfdbus_put_file(argv[1], diff_template, "api-object-v2", &v2_id, &err);
    unlink(diff_template);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file diff", &err);
    }

    ret = memfdbus_get_fd(argv[1], 0, "api-object", &object, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd", &err);
    }
    if (object.id != id || object.size != size || strcmp(object.name, "api-object") != 0) {
        fprintf(stderr, "object metadata mismatch\n");
        return 1;
    }
    expect_digest(object.digest);
    memcpy(object_digest, object.digest, sizeof(object_digest));
    if (memfdbus_validate_fd(object.fd, object.size, &err) != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_validate_fd", &err);
    }
    mapped = mmap(NULL, (size_t)object.size, PROT_READ, MAP_SHARED, object.fd, 0);
    if (mapped == MAP_FAILED) {
        fail_errno("mmap object");
    }
    compare_mapping(mapped, object.size, argv[2]);
    munmap(mapped, (size_t)object.size);
    memfdbus_object_close(&object);
    if (object.digest[0] != '\0') {
        fprintf(stderr, "memfdbus_object_close did not clear digest\n");
        return 1;
    }

    ret = memfdbus_get_fd(argv[1], 0, "api-object-copy", &object_copy, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd copy", &err);
    }
    ret = memfdbus_get_fd(argv[1], 0, "api-object-v2", &object_v2, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd v2", &err);
    }
    expect_digest(object_copy.digest);
    expect_digest(object_v2.digest);
    memcpy(object_copy_digest, object_copy.digest, sizeof(object_copy_digest));
    memcpy(object_v2_digest, object_v2.digest, sizeof(object_v2_digest));
    if (strcmp(object_digest, object_copy.digest) != 0) {
        fprintf(stderr, "same-content API objects had different digests\n");
        return 1;
    }
    if (strcmp(object_copy.digest, object_v2.digest) == 0) {
        fprintf(stderr, "different-content API objects had identical digests\n");
        return 1;
    }
    memfdbus_object_close(&object_copy);
    memfdbus_object_close(&object_v2);

    ret = memfdbus_list(argv[1], &list, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_list", &err);
    }
    if (!strstr(list.text, "api-object") || !strstr(list.text, "api-object-copy") ||
        !strstr(list.text, "api-object-v2")) {
        fprintf(stderr, "api objects missing from list\n");
        return 1;
    }
    if (!strstr(list.text, object_copy_digest) || !strstr(list.text, object_v2_digest)) {
        fprintf(stderr, "api list output missing digests\n");
        return 1;
    }
    memfdbus_list_free(&list);

    ret = memfdbus_put_file_for_job(argv[1], argv[2], "api-policy", "alpha", "beta",
                                    &policy_id, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file_for_job", &err);
    }
    ret = memfdbus_get_fd_for_job(argv[1], policy_id, NULL, "beta", &object, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd_for_job beta", &err);
    }
    memfdbus_object_close(&object);
    ret = memfdbus_get_fd_for_job(argv[1], policy_id, NULL, "gamma", &object, &err);
    if (ret != MEMFDBUS_RESULT_FORBIDDEN ||
        strcmp(memfdbus_error_message(&err), "broker error: access denied") != 0) {
        fprintf(stderr, "expected forbidden get for gamma, got %d (%s)\n",
                ret, memfdbus_error_message(&err));
        return 1;
    }
    ret = memfdbus_list_for_job(argv[1], "beta", &list, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_list_for_job beta", &err);
    }
    if (!strstr(list.text, "api-policy")) {
        fprintf(stderr, "beta list missing api-policy\n");
        return 1;
    }
    memfdbus_list_free(&list);
    ret = memfdbus_list_for_job(argv[1], "gamma", &list, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_list_for_job gamma", &err);
    }
    if (strstr(list.text, "api-policy")) {
        fprintf(stderr, "gamma unexpectedly saw api-policy in list\n");
        return 1;
    }
    memfdbus_list_free(&list);
    ret = memfdbus_drop_for_job(argv[1], policy_id, NULL, "beta", &dropped, &err);
    if (ret != MEMFDBUS_RESULT_FORBIDDEN ||
        strcmp(memfdbus_error_message(&err), "broker error: access denied") != 0) {
        fprintf(stderr, "expected forbidden drop for beta, got %d (%s)\n",
                ret, memfdbus_error_message(&err));
        return 1;
    }
    ret = memfdbus_drop_for_job(argv[1], policy_id, NULL, "gamma", &dropped, &err);
    if (ret != MEMFDBUS_RESULT_FORBIDDEN ||
        strcmp(memfdbus_error_message(&err), "broker error: access denied") != 0) {
        fprintf(stderr, "expected forbidden drop for gamma, got %d (%s)\n",
                ret, memfdbus_error_message(&err));
        return 1;
    }
    ret = memfdbus_drop_for_job(argv[1], policy_id, NULL, "alpha", &dropped, &err);
    if (ret != MEMFDBUS_RESULT_OK || dropped != policy_id) {
        fail_api("memfdbus_drop_for_job alpha", &err);
    }

    ret = memfdbus_put_file(argv[1], argv[2], "held-by-id", &held_id, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file held-by-id", &err);
    }
    ret = memfdbus_get_fd(argv[1], held_id, NULL, &object, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd held-by-id", &err);
    }
    ret = memfdbus_drop(argv[1], held_id, NULL, &dropped, &err);
    if (ret != MEMFDBUS_RESULT_OK || dropped != held_id) {
        fail_api("memfdbus_drop held-by-id", &err);
    }
    ret = memfdbus_get_fd(argv[1], held_id, NULL, &object_copy, &err);
    if (ret != MEMFDBUS_RESULT_NOT_FOUND) {
        fprintf(stderr, "expected held-by-id lookup to return not found, got %d\n", ret);
        return 1;
    }
    expect_retained_object(&object, argv[2], &err);
    memfdbus_object_close(&object);

    ret = memfdbus_put_file(argv[1], argv[2], "held-by-name", &held_id, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file held-by-name", &err);
    }
    ret = memfdbus_get_fd(argv[1], 0, "held-by-name", &object, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd held-by-name", &err);
    }
    ret = memfdbus_drop(argv[1], 0, "held-by-name", &dropped, &err);
    if (ret != MEMFDBUS_RESULT_OK || dropped != object.id) {
        fail_api("memfdbus_drop held-by-name", &err);
    }
    ret = memfdbus_get_fd(argv[1], 0, "held-by-name", &object_copy, &err);
    if (ret != MEMFDBUS_RESULT_NOT_FOUND) {
        fprintf(stderr, "expected held-by-name lookup to return not found, got %d\n", ret);
        return 1;
    }
    expect_retained_object(&object, argv[2], &err);
    memfdbus_object_close(&object);

    ret = memfdbus_put_file(argv[1], argv[2], "held-republish", &republish_id, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file held-republish v1", &err);
    }
    ret = memfdbus_get_fd(argv[1], 0, "held-republish", &object, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_get_fd held-republish v1", &err);
    }
    republish_fd = mkstemp(republish_template);
    if (republish_fd < 0) {
        fail_errno("mkstemp republish payload");
    }
    if (write(republish_fd, "republish-different-payload\n",
              strlen("republish-different-payload\n")) !=
        (ssize_t)strlen("republish-different-payload\n")) {
        fail_errno("write republish payload");
    }
    close(republish_fd);
    ret = memfdbus_put_file(argv[1], republish_template, "held-republish", &republish_id_v2, &err);
    unlink(republish_template);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_put_file held-republish v2", &err);
    }
    if (republish_id_v2 == republish_id) {
        fprintf(stderr, "republish returned the same object id\n");
        return 1;
    }
    ret = memfdbus_drop(argv[1], republish_id, NULL, &dropped, &err);
    if (ret != MEMFDBUS_RESULT_OK || dropped != republish_id) {
        fail_api("memfdbus_drop held-republish v1", &err);
    }
    ret = memfdbus_get_fd(argv[1], republish_id, NULL, &object_copy, &err);
    if (ret != MEMFDBUS_RESULT_NOT_FOUND) {
        fprintf(stderr, "expected republished v1 lookup to return not found, got %d\n", ret);
        return 1;
    }
    expect_retained_object(&object, argv[2], &err);
    memfdbus_object_close(&object);
    if (memfdbus_drop(argv[1], republish_id_v2, NULL, &dropped, &err) != MEMFDBUS_RESULT_OK ||
        dropped != republish_id_v2) {
        fail_api("memfdbus_drop held-republish v2", &err);
    }

    ret = memfdbus_drop(argv[1], id, NULL, &dropped, &err);
    if (ret != MEMFDBUS_RESULT_OK) {
        fail_api("memfdbus_drop", &err);
    }
    if (dropped != id) {
        fprintf(stderr, "drop returned wrong id\n");
        return 1;
    }
    if (memfdbus_drop(argv[1], copy_id, NULL, &dropped, &err) != MEMFDBUS_RESULT_OK ||
        dropped != copy_id) {
        fail_api("memfdbus_drop copy", &err);
    }
    if (memfdbus_drop(argv[1], v2_id, NULL, &dropped, &err) != MEMFDBUS_RESULT_OK ||
        dropped != v2_id) {
        fail_api("memfdbus_drop v2", &err);
    }

    ret = memfdbus_get_fd(argv[1], id, NULL, &object, &err);
    if (ret != MEMFDBUS_RESULT_NOT_FOUND) {
        fprintf(stderr, "expected not found after drop, got %d\n", ret);
        return 1;
    }

    {
        struct memfdbus_error neg_err = {0};
        struct stat regfile_st;
        uint64_t neg_id = 0;
        int closed_fd;
        int pipefd[2];
        int regfile_fd;
        int unsealed_memfd;

        ret = memfdbus_put_fd_for_job(argv[1], -1, "bad-fd", NULL, NULL, &neg_id, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EBADF ||
            !strstr(memfdbus_error_message(&neg_err), "invalid input fd")) {
            fprintf(stderr,
                    "expected BAD_REQUEST/EBADF for put_fd_for_job(-1), got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }

        memset(&neg_err, 0, sizeof(neg_err));
        ret = memfdbus_validate_fd(-1, 0, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EBADF ||
            !strstr(memfdbus_error_message(&neg_err), "invalid object fd")) {
            fprintf(stderr,
                    "expected BAD_REQUEST/EBADF for validate_fd(-1), got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }

        closed_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (closed_fd < 0) {
            fail_errno("open /dev/null");
        }
        if (close(closed_fd) < 0) {
            fail_errno("close /dev/null");
        }
        memset(&neg_err, 0, sizeof(neg_err));
        ret = memfdbus_validate_fd(closed_fd, 0, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EBADF ||
            !strstr(memfdbus_error_message(&neg_err), "invalid object fd")) {
            fprintf(stderr,
                    "expected BAD_REQUEST/EBADF for closed fd, got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }

        if (pipe(pipefd) < 0) {
            fail_errno("pipe");
        }
        memset(&neg_err, 0, sizeof(neg_err));
        ret = memfdbus_validate_fd(pipefd[0], 0, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EINVAL ||
            !strstr(memfdbus_error_message(&neg_err), "not a regular memfd-like file")) {
            fprintf(stderr,
                    "expected BAD_REQUEST for pipe fd, got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }
        close(pipefd[0]);
        close(pipefd[1]);

        regfile_fd = open("/etc/hostname", O_RDONLY | O_CLOEXEC);
        if (regfile_fd < 0) {
            fail_errno("open /etc/hostname");
        }
        if (fstat(regfile_fd, &regfile_st) < 0) {
            fail_errno("fstat /etc/hostname");
        }
        memset(&neg_err, 0, sizeof(neg_err));
        ret = memfdbus_validate_fd(regfile_fd, (uint64_t)regfile_st.st_size, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EINVAL ||
            !strstr(memfdbus_error_message(&neg_err), "descriptor is not a sealed memfd")) {
            fprintf(stderr,
                    "expected BAD_REQUEST/EINVAL for regular file, got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }
        close(regfile_fd);

        unsealed_memfd = (int)syscall(SYS_memfd_create, "unsealed",
                                      MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (unsealed_memfd < 0) {
            fail_errno("memfd_create unsealed");
        }
        memset(&neg_err, 0, sizeof(neg_err));
        ret = memfdbus_validate_fd(unsealed_memfd, 0, &neg_err);
        if (ret != MEMFDBUS_RESULT_BAD_REQUEST || neg_err.code != MEMFDBUS_RESULT_BAD_REQUEST ||
            neg_err.sys_errno != EINVAL ||
            !strstr(memfdbus_error_message(&neg_err), "fd is not fully immutable-sealed")) {
            fprintf(stderr,
                    "expected BAD_REQUEST/EINVAL for unsealed memfd, got %d/%d (%s)\n",
                    ret, neg_err.sys_errno, memfdbus_error_message(&neg_err));
            return 1;
        }
        close(unsealed_memfd);
    }

    return 0;
}
