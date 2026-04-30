#ifndef MEMFDBUS_SHA256_H
#define MEMFDBUS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define MEMFDBUS_SHA256_RAW_LEN 32u
#ifndef MEMFDBUS_DIGEST_STRLEN
#define MEMFDBUS_DIGEST_STRLEN 71u
#endif
#ifndef MEMFDBUS_DIGEST_BUFSZ
#define MEMFDBUS_DIGEST_BUFSZ (MEMFDBUS_DIGEST_STRLEN + 1u)
#endif

struct memfdbus_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_len;
    unsigned char block[64];
    size_t block_len;
};

void memfdbus_sha256_init(struct memfdbus_sha256_ctx *ctx);
void memfdbus_sha256_update(struct memfdbus_sha256_ctx *ctx, const void *data, size_t len);
void memfdbus_sha256_final(struct memfdbus_sha256_ctx *ctx,
                           unsigned char digest[MEMFDBUS_SHA256_RAW_LEN]);
void memfdbus_sha256_format(char out[MEMFDBUS_DIGEST_BUFSZ],
                            const unsigned char digest[MEMFDBUS_SHA256_RAW_LEN]);
int memfdbus_digest_is_valid(const char *digest);

#endif
