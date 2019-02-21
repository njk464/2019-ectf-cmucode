#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>

#define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
#define ROUNDS 20

#define U32_STR_MAXSIZE 11U

# define POLY1305_NOINLINE __attribute__((noinline))

#define poly1305_block_size 16
#define crypto_verify_16_BYTES 16U
#define U32C(v) (v##U)

/* 17 + sizeof(unsigned long long) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
    unsigned long      r[5];
    unsigned long      h[5];
    unsigned long      pad[4];
    unsigned long long leftover;
    unsigned char      buffer[poly1305_block_size];
    unsigned char      final;
} poly1305_state_internal_t;

int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                          const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));
