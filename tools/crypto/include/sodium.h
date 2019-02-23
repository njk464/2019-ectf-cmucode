// TODO: remove after testing
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>

#define __attribute__(a)

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])
#define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
#define ROUNDS 20

#define U32_STR_MAXSIZE 11U

#define crypto_secretbox_NONCEBYTES 24U
#define crypto_secretbox_KEYBYTES 32U
#define crypto_secretbox_MACBYTES 16U
#define crypto_secretbox_ZEROBYTES 32U
#define crypto_secretbox_BOXZEROBYTES 16U
#define crypto_pwhash_SALTBYTES 16U
#define crypto_sign_PUBLICKEYBYTES 32U
#define crypto_hash_sha256_BYTES 32U
#define crypto_sign_BYTES 64U

# define POLY1305_NOINLINE __attribute__((noinline))

#define poly1305_block_size 16
#define crypto_verify_16_BYTES 16U
#define U32C(v) (v##U)


/************SIGNING MACROS ******************************/
#ifndef SIZE_MAX
#define SIZE_MAX    (~(size_t)0)
#endif

#ifndef UINT64_MAX
#define UINT64_MAX 0xffffffffffffffff
#endif

#define SODIUM_MIN(A, B) ((A) < (B) ? (A): (B))
#define SODIUM_SIZE_MAX SODIUM_MIN(UINT64_MAX, SIZE_MAX)

#define crypto_sign_ed25519_BYTES 64U
#define crypto_sign_ed25519_MESSAGEBYTES_MAX (SODIUM_SIZE_MAX - crypto_sign_ed25519_BYTES)

#define crypto_verify_32_BYTES 32U

typedef int32_t fe25519[10];

typedef struct crypto_hash_sha512_state {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[128];
} crypto_hash_sha512_state;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
} ge25519_p2;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p3;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p1p1;

typedef struct {
    fe25519 yplusx;
    fe25519 yminusx;
    fe25519 xy2d;
} ge25519_precomp;

typedef struct {
    fe25519 YplusX;
    fe25519 YminusX;
    fe25519 Z;
    fe25519 T2d;
} ge25519_cached;

/* 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
static const fe25519 d = {
    -10913610, 13857413, -15372611, 6949391,   114729, -8787816, -6275908, -3247719, -18696448, -12055116
};

/* 2 * d =
 * 16295367250680780974490674513165176452449235426866156013048779062215315747161
 */
static const fe25519 d2 = {
    -21827239, -5839606,  -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199 };

/* sqrt(-1) */
static const fe25519 sqrtm1 = {
    -32595792, -7943725,  9377950,  3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
};




/********************************************************/

/* 17 + sizeof(unsigned long long) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
    unsigned long      r[5];
    unsigned long      h[5];
    unsigned long      pad[4];
    unsigned long long leftover;
    unsigned char      buffer[poly1305_block_size];
    unsigned char      final;
} poly1305_state_internal_t;
int
crypto_secretbox(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *k);


int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                          const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));


/******************** SIGNING PROTOTYPE *****************************/

int crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));

int crypto_hash_sha256(unsigned char *out, const unsigned char *in, 
                       unsigned long long inlen);

int sodium_init();
