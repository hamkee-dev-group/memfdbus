#ifndef MEMFDBUS_H
#define MEMFDBUS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMFDBUS_DEFAULT_SOCKET "/tmp/memfdbus.sock"
#define MEMFDBUS_MAX_NAME (64u * 1024u)
#define MEMFDBUS_DIGEST_STRLEN 71u
#define MEMFDBUS_DIGEST_BUFSZ (MEMFDBUS_DIGEST_STRLEN + 1u)

enum memfdbus_result {
    MEMFDBUS_RESULT_OK = 0,
    MEMFDBUS_RESULT_ERROR = -1,
    MEMFDBUS_RESULT_NOT_FOUND = -2,
    MEMFDBUS_RESULT_BAD_REQUEST = -3,
    MEMFDBUS_RESULT_FORBIDDEN = -4,
    MEMFDBUS_RESULT_DENIED = -4,
};

struct memfdbus_error {
    int code;
    int sys_errno;
    char message[256];
};

struct memfdbus_object {
    uint64_t id;
    uint64_t size;
    int fd;
    char digest[MEMFDBUS_DIGEST_BUFSZ];
    char *name;
};

struct memfdbus_list {
    char *text;
    size_t len;
};

 
int memfdbus_put_file_for_job(const char *socket_path, const char *path, const char *name,
                              const char *job_id, const char *allow_job, uint64_t *out_id,
                              struct memfdbus_error *err);
int memfdbus_put_fd_for_job(const char *socket_path, int input_fd, const char *name,
                            const char *job_id, const char *allow_job, uint64_t *out_id,
                            struct memfdbus_error *err);
int memfdbus_get_fd_for_job(const char *socket_path, uint64_t id, const char *name,
                            const char *job_id, struct memfdbus_object *out,
                            struct memfdbus_error *err);
int memfdbus_get_file_for_job(const char *socket_path, uint64_t id, const char *name,
                              const char *job_id, const char *out_path,
                              struct memfdbus_error *err);
int memfdbus_drop_for_job(const char *socket_path, uint64_t id, const char *name,
                          const char *job_id, uint64_t *out_id,
                          struct memfdbus_error *err);
int memfdbus_list_for_job(const char *socket_path, const char *job_id,
                          struct memfdbus_list *out, struct memfdbus_error *err);

 
int memfdbus_put_file(const char *socket_path, const char *path, const char *name,
                      uint64_t *out_id, struct memfdbus_error *err);
 
int memfdbus_put_fd(const char *socket_path, int input_fd, const char *name,
                    uint64_t *out_id, struct memfdbus_error *err);

 
int memfdbus_get_fd(const char *socket_path, uint64_t id, const char *name,
                    struct memfdbus_object *out, struct memfdbus_error *err);
int memfdbus_get_file(const char *socket_path, uint64_t id, const char *name,
                      const char *out_path, struct memfdbus_error *err);

 
int memfdbus_drop(const char *socket_path, uint64_t id, const char *name,
                  uint64_t *out_id, struct memfdbus_error *err);
int memfdbus_list(const char *socket_path, struct memfdbus_list *out,
                  struct memfdbus_error *err);

int memfdbus_validate_fd(int fd, uint64_t expected_size, struct memfdbus_error *err);
void memfdbus_object_close(struct memfdbus_object *object);
void memfdbus_list_free(struct memfdbus_list *list);
const char *memfdbus_error_message(const struct memfdbus_error *err);

#ifdef __cplusplus
}
#endif

#endif
