#include <stdlib.h>
#include <stdint.h>
#include "libsodium.h"

static volatile int initialized;

int
crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
                      const unsigned char *n, const unsigned char *k);
int
sodium_crit_enter(void);
int
sodium_crit_leave(void);
int
crypto_secretbox_xsalsa20poly1305(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n,
                                  const unsigned char *k);
int
crypto_secretbox_xsalsa20poly1305_open(unsigned char *m, const unsigned char *c,
                                       unsigned long long clen,
                                       const unsigned char *n,
                                       const unsigned char *k);
int
crypto_secretbox(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *k);
int
crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                      unsigned long long clen, const unsigned char *n,
                      const unsigned char *k);
int
crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k);
int
crypto_stream_xsalsa20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              uint64_t ic, const unsigned char *k);
int
crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k);
static int
stream(unsigned char *c, unsigned long long clen, const unsigned char *n,
           const unsigned char *k);
static int
stream_xor_ic(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n, uint64_t ic,
                  const unsigned char *k);
static void
crypto_core_salsa(unsigned char *out, const unsigned char *in,
                  const unsigned char *k, const unsigned char *c,
                  const int rounds);
int
crypto_core_salsa20(unsigned char *out, const unsigned char *in,
                    const unsigned char *k, const unsigned char *c);
void
sodium_memzero(void * const pnt, const size_t len);
int
crypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                   const unsigned char *in,
                                   unsigned long long   inlen,
                                   const unsigned char *k);
static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes);
static int
crypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key);
static int
onetimeauth_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         unsigned long long   inlen,
                                         const unsigned char *k);
static void
poly1305_init(poly1305_state_internal_t *st, const unsigned char key[32]);
static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes);
static POLY1305_NOINLINE void
poly1305_finish(poly1305_state_internal_t *st, unsigned char mac[16]);
static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes);
static POLY1305_NOINLINE void
poly1305_finish(poly1305_state_internal_t *st, unsigned char mac[16]);
int
crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in,
                            unsigned long long inlen, const unsigned char *k);

int
crypto_core_hsalsa20(unsigned char *out,
                     const unsigned char *in,
                     const unsigned char *k,
                     const unsigned char *c);
int
crypto_stream_salsa20_xor_ic(unsigned char *c, const unsigned char *m,
                             unsigned long long mlen,
                             const unsigned char *n, uint64_t ic,
                             const unsigned char *k);
int
crypto_verify_16(const unsigned char *x, const unsigned char *y);

/* common */

typedef unsigned __int128 uint128_t;

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#define ROTL64(X, B) rotl64((X), (B))
static inline uint64_t
rotl64(const uint64_t x, const int b)
{
    return (x << b) | (x >> (64 - b));
}

#define ROTR32(X, B) rotr32((X), (B))
static inline uint32_t
rotr32(const uint32_t x, const int b)
{
    return (x >> b) | (x << (32 - b));
}

#define ROTR64(X, B) rotr64((X), (B))
static inline uint64_t
rotr64(const uint64_t x, const int b)
{
    return (x >> b) | (x << (64 - b));
}

#define LOAD64_LE(SRC) load64_le(SRC)
static inline uint64_t
load64_le(const uint8_t src[8])
{
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
    memcpy(dst, &w, sizeof w);
}

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
    memcpy(dst, &w, sizeof w);
}

/* ----- */

#define LOAD64_BE(SRC) load64_be(SRC)
static inline uint64_t
load64_be(const uint8_t src[8])
{
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] <<  8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
}

#define STORE64_BE(DST, W) store64_be((DST), (W))
static inline void
store64_be(uint8_t dst[8], uint64_t w)
{
    dst[7] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
}

#define LOAD32_BE(SRC) load32_be(SRC)
static inline uint32_t
load32_be(const uint8_t src[4])
{
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] <<  8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
}

#define STORE32_BE(DST, W) store32_be((DST), (W))
static inline void
store32_be(uint8_t dst[4], uint32_t w)
{
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
}

#define XOR_BUF(OUT, IN, N) xor_buf((OUT), (IN), (N))
static inline void
xor_buf(unsigned char *out, const unsigned char *in, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] ^= in[i];
    }
}


#define __attribute__(a)



# define HAVE_INTRIN_H    1
# define HAVE_MMINTRIN_H  1
# define HAVE_EMMINTRIN_H 1
# define HAVE_PMMINTRIN_H 1
# define HAVE_TMMINTRIN_H 1
# define HAVE_SMMINTRIN_H 1
# define HAVE_AVXINTRIN_H 1

int
sodium_init(void)
{
    initialized = 1;
}


int
sodium_crit_enter(void)
{
    return 0;
}

int
sodium_crit_leave(void)
{
    return 0;
}

////////////////////////////////
/* secretbox_xsalsa20poly1305 */
////////////////////////////////

int
crypto_secretbox_xsalsa20poly1305(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n,
                                  const unsigned char *k)
{
    int i;

    if (mlen < 32) {
        return -1;
    }
    crypto_stream_xsalsa20_xor(c, m, mlen, n, k);
    crypto_onetimeauth_poly1305(c + 16, c + 32, mlen - 32, c);
    for (i = 0; i < 16; ++i) {
        c[i] = 0;
    }
    return 0;
}

int
crypto_secretbox_xsalsa20poly1305_open(unsigned char *m, const unsigned char *c,
                                       unsigned long long clen,
                                       const unsigned char *n,
                                       const unsigned char *k)
{
    unsigned char subkey[32];
    int           i;

    if (clen < 32) {
        return -1;
    }
    crypto_stream_xsalsa20(subkey, 32, n, k);
    if (crypto_onetimeauth_poly1305_verify(c + 16, c + 32,
                                           clen - 32, subkey) != 0) {
        return -1;
    }
    crypto_stream_xsalsa20_xor(m, c, clen, n, k);
    for (i = 0; i < 32; ++i) {
        m[i] = 0;
    }
    return 0;
}

////////////////////////////////
/*         secretbox          */
////////////////////////////////

int
crypto_secretbox(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *k)
{
    return crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k);
}

int
crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                      unsigned long long clen, const unsigned char *n,
                      const unsigned char *k)
{
    return crypto_secretbox_xsalsa20poly1305_open(m, c, clen, n, k);
}


////////////////////////////////
/*         xsalsa20           */
////////////////////////////////

int
crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k)
{
    unsigned char subkey[32];
    int           ret;

    crypto_core_hsalsa20(subkey, n, k, NULL);
    ret = crypto_stream_salsa20(c, clen, n + 16, subkey);
    sodium_memzero(subkey, sizeof subkey);

    return ret;
}

int
crypto_stream_xsalsa20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              uint64_t ic, const unsigned char *k)
{
    unsigned char subkey[32];
    int           ret;

    crypto_core_hsalsa20(subkey, n, k, NULL);
    ret = crypto_stream_salsa20_xor_ic(c, m, mlen, n + 16, ic, subkey);
    sodium_memzero(subkey, sizeof subkey);

    return ret;
}

int
crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k)
{
    return crypto_stream_xsalsa20_xor_ic(c, m, mlen, n, 0ULL, k);
}


int
crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
                      const unsigned char *n, const unsigned char *k)
{
    return stream(c, clen, n, k);
}

int
crypto_stream_salsa20_xor_ic(unsigned char *c, const unsigned char *m,
                             unsigned long long mlen,
                             const unsigned char *n, uint64_t ic,
                             const unsigned char *k)
{
    return stream_xor_ic(c, m, mlen, n, ic, k);
}

static int
stream(unsigned char *c, unsigned long long clen, const unsigned char *n,
           const unsigned char *k)
{
    unsigned char in[16];
    unsigned char block[64];
    unsigned char kcopy[32];
    unsigned int  i;
    unsigned int  u;

    if (!clen) {
        return 0;
    }
    for (i = 0; i < 32; i++) {
        kcopy[i] = k[i];
    }
    for (i = 0; i < 8; i++) {
        in[i] = n[i];
    }
    for (i = 8; i < 16; i++) {
        in[i] = 0;
    }
    while (clen >= 64) {
        crypto_core_salsa20(c, in, kcopy, NULL);
        u = 1;
        for (i = 8; i < 16; i++) {
            u += (unsigned int) in[i];
            in[i] = u;
            u >>= 8;
        }
        clen -= 64;
        c += 64;
    }
    if (clen) {
        crypto_core_salsa20(block, in, kcopy, NULL);
        for (i = 0; i < (unsigned int) clen; i++) {
            c[i] = block[i];
        }
    }
    sodium_memzero(block, sizeof block);
    sodium_memzero(kcopy, sizeof kcopy);

    return 0;
}

static int
stream_xor_ic(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n, uint64_t ic,
                  const unsigned char *k)
{
    unsigned char in[16];
    unsigned char block[64];
    unsigned char kcopy[32];
    unsigned int  i;
    unsigned int  u;

    if (!mlen) {
        return 0;
    }
    for (i = 0; i < 32; i++) {
        kcopy[i] = k[i];
    }
    for (i = 0; i < 8; i++) {
        in[i] = n[i];
    }
    for (i = 8; i < 16; i++) {
        in[i] = (unsigned char) (ic & 0xff);
        ic >>= 8;
    }
    while (mlen >= 64) {
        crypto_core_salsa20(block, in, kcopy, NULL);
        for (i = 0; i < 64; i++) {
            c[i] = m[i] ^ block[i];
        }
        u = 1;
        for (i = 8; i < 16; i++) {
            u += (unsigned int) in[i];
            in[i] = u;
            u >>= 8;
        }
        mlen -= 64;
        c += 64;
        m += 64;
    }
    if (mlen) {
        crypto_core_salsa20(block, in, kcopy, NULL);
        for (i = 0; i < (unsigned int) mlen; i++) {
            c[i] = m[i] ^ block[i];
        }
    }
    sodium_memzero(block, sizeof block);
    sodium_memzero(kcopy, sizeof kcopy);

    return 0;
}

static void
crypto_core_salsa(unsigned char *out, const unsigned char *in,
                  const unsigned char *k, const unsigned char *c,
                  const int rounds)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14,
        x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14,
        j15;
    int i;

    j0  = x0  = 0x61707865;
    j5  = x5  = 0x3320646e;
    j10 = x10 = 0x79622d32;
    j15 = x15 = 0x6b206574;
    if (c != NULL) {
        j0  = x0  = LOAD32_LE(c + 0);
        j5  = x5  = LOAD32_LE(c + 4);
        j10 = x10 = LOAD32_LE(c + 8);
        j15 = x15 = LOAD32_LE(c + 12);
    }
    j1  = x1  = LOAD32_LE(k + 0);
    j2  = x2  = LOAD32_LE(k + 4);
    j3  = x3  = LOAD32_LE(k + 8);
    j4  = x4  = LOAD32_LE(k + 12);
    j11 = x11 = LOAD32_LE(k + 16);
    j12 = x12 = LOAD32_LE(k + 20);
    j13 = x13 = LOAD32_LE(k + 24);
    j14 = x14 = LOAD32_LE(k + 28);

    j6  = x6  = LOAD32_LE(in + 0);
    j7  = x7  = LOAD32_LE(in + 4);
    j8  = x8  = LOAD32_LE(in + 8);
    j9  = x9  = LOAD32_LE(in + 12);

    for (i = 0; i < rounds; i += 2) {
        x4  ^= ROTL32(x0  + x12, 7);
        x8  ^= ROTL32(x4  + x0, 9);
        x12 ^= ROTL32(x8  + x4, 13);
        x0  ^= ROTL32(x12 + x8, 18);
        x9  ^= ROTL32(x5  + x1, 7);
        x13 ^= ROTL32(x9  + x5, 9);
        x1  ^= ROTL32(x13 + x9, 13);
        x5  ^= ROTL32(x1  + x13, 18);
        x14 ^= ROTL32(x10 + x6, 7);
        x2  ^= ROTL32(x14 + x10, 9);
        x6  ^= ROTL32(x2  + x14, 13);
        x10 ^= ROTL32(x6  + x2, 18);
        x3  ^= ROTL32(x15 + x11, 7);
        x7  ^= ROTL32(x3  + x15, 9);
        x11 ^= ROTL32(x7  + x3, 13);
        x15 ^= ROTL32(x11 + x7, 18);
        x1  ^= ROTL32(x0  + x3, 7);
        x2  ^= ROTL32(x1  + x0, 9);
        x3  ^= ROTL32(x2  + x1, 13);
        x0  ^= ROTL32(x3  + x2, 18);
        x6  ^= ROTL32(x5  + x4, 7);
        x7  ^= ROTL32(x6  + x5, 9);
        x4  ^= ROTL32(x7  + x6, 13);
        x5  ^= ROTL32(x4  + x7, 18);
        x11 ^= ROTL32(x10 + x9, 7);
        x8  ^= ROTL32(x11 + x10, 9);
        x9  ^= ROTL32(x8  + x11, 13);
        x10 ^= ROTL32(x9  + x8, 18);
        x12 ^= ROTL32(x15 + x14, 7);
        x13 ^= ROTL32(x12 + x15, 9);
        x14 ^= ROTL32(x13 + x12, 13);
        x15 ^= ROTL32(x14 + x13, 18);
    }
    STORE32_LE(out + 0,  x0  + j0);
    STORE32_LE(out + 4,  x1  + j1);
    STORE32_LE(out + 8,  x2  + j2);
    STORE32_LE(out + 12, x3  + j3);
    STORE32_LE(out + 16, x4  + j4);
    STORE32_LE(out + 20, x5  + j5);
    STORE32_LE(out + 24, x6  + j6);
    STORE32_LE(out + 28, x7  + j7);
    STORE32_LE(out + 32, x8  + j8);
    STORE32_LE(out + 36, x9  + j9);
    STORE32_LE(out + 40, x10 + j10);
    STORE32_LE(out + 44, x11 + j11);
    STORE32_LE(out + 48, x12 + j12);
    STORE32_LE(out + 52, x13 + j13);
    STORE32_LE(out + 56, x14 + j14);
    STORE32_LE(out + 60, x15 + j15);
}

int
crypto_core_salsa20(unsigned char *out, const unsigned char *in,
                    const unsigned char *k, const unsigned char *c)
{
    crypto_core_salsa(out, in, k, c, 20);
    return 0;
}


void
sodium_memzero(void * const pnt, const size_t len)
{
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}


int
crypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                   const unsigned char *in,
                                   unsigned long long   inlen,
                                   const unsigned char *k)
{
    return onetimeauth_verify(h, in, inlen, k);
}

int
crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in,
                            unsigned long long inlen, const unsigned char *k)
{
    return crypto_onetimeauth_poly1305_donna(out, in, inlen, k);
}

static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes)
{
    unsigned long long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long long want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        unsigned long long want = (bytes & ~(poly1305_block_size - 1));

        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

static int
crypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key)
{
    CRYPTO_ALIGN(64) poly1305_state_internal_t state;

    poly1305_init(&state, key);
    poly1305_update(&state, m, inlen);
    poly1305_finish(&state, out);

    return 0;
}


static int
onetimeauth_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         unsigned long long   inlen,
                                         const unsigned char *k)
{
    unsigned char correct[16];

    crypto_onetimeauth_poly1305_donna(correct, in, inlen, k);

    return crypto_verify_16(h, correct);
}


static void
poly1305_init(poly1305_state_internal_t *st, const unsigned char key[32])
{
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff - wiped after finalization */
    st->r[0] = (LOAD32_LE(&key[0])) & 0x3ffffff;
    st->r[1] = (LOAD32_LE(&key[3]) >> 2) & 0x3ffff03;
    st->r[2] = (LOAD32_LE(&key[6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (LOAD32_LE(&key[9]) >> 6) & 0x3f03fff;
    st->r[4] = (LOAD32_LE(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = LOAD32_LE(&key[16]);
    st->pad[1] = LOAD32_LE(&key[20]);
    st->pad[2] = LOAD32_LE(&key[24]);
    st->pad[3] = LOAD32_LE(&key[28]);

    st->leftover = 0;
    st->final    = 0;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes)
{
    const unsigned long hibit = (st->final) ? 0UL : (1UL << 24); /* 1 << 128 */
    unsigned long       r0, r1, r2, r3, r4;
    unsigned long       s1, s2, s3, s4;
    unsigned long       h0, h1, h2, h3, h4;
    unsigned long long  d0, d1, d2, d3, d4;
    unsigned long       c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (bytes >= poly1305_block_size) {
        /* h += m[i] */
        h0 += (LOAD32_LE(m + 0)) & 0x3ffffff;
        h1 += (LOAD32_LE(m + 3) >> 2) & 0x3ffffff;
        h2 += (LOAD32_LE(m + 6) >> 4) & 0x3ffffff;
        h3 += (LOAD32_LE(m + 9) >> 6) & 0x3ffffff;
        h4 += (LOAD32_LE(m + 12) >> 8) | hibit;

        /* h *= r */
        d0 = ((unsigned long long) h0 * r0) + ((unsigned long long) h1 * s4) +
             ((unsigned long long) h2 * s3) + ((unsigned long long) h3 * s2) +
             ((unsigned long long) h4 * s1);
        d1 = ((unsigned long long) h0 * r1) + ((unsigned long long) h1 * r0) +
             ((unsigned long long) h2 * s4) + ((unsigned long long) h3 * s3) +
             ((unsigned long long) h4 * s2);
        d2 = ((unsigned long long) h0 * r2) + ((unsigned long long) h1 * r1) +
             ((unsigned long long) h2 * r0) + ((unsigned long long) h3 * s4) +
             ((unsigned long long) h4 * s3);
        d3 = ((unsigned long long) h0 * r3) + ((unsigned long long) h1 * r2) +
             ((unsigned long long) h2 * r1) + ((unsigned long long) h3 * r0) +
             ((unsigned long long) h4 * s4);
        d4 = ((unsigned long long) h0 * r4) + ((unsigned long long) h1 * r3) +
             ((unsigned long long) h2 * r2) + ((unsigned long long) h3 * r1) +
             ((unsigned long long) h4 * r0);

        /* (partial) h %= p */
        c  = (unsigned long) (d0 >> 26);
        h0 = (unsigned long) d0 & 0x3ffffff;
        d1 += c;
        c  = (unsigned long) (d1 >> 26);
        h1 = (unsigned long) d1 & 0x3ffffff;
        d2 += c;
        c  = (unsigned long) (d2 >> 26);
        h2 = (unsigned long) d2 & 0x3ffffff;
        d3 += c;
        c  = (unsigned long) (d3 >> 26);
        h3 = (unsigned long) d3 & 0x3ffffff;
        d4 += c;
        c  = (unsigned long) (d4 >> 26);
        h4 = (unsigned long) d4 & 0x3ffffff;
        h0 += c * 5;
        c  = (h0 >> 26);
        h0 = h0 & 0x3ffffff;
        h1 += c;

        m += poly1305_block_size;
        bytes -= poly1305_block_size;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static POLY1305_NOINLINE void
poly1305_finish(poly1305_state_internal_t *st, unsigned char mac[16])
{
    unsigned long      h0, h1, h2, h3, h4, c;
    unsigned long      g0, g1, g2, g3, g4;
    unsigned long long f;
    unsigned long      mask;

    /* process the remaining block */
    if (st->leftover) {
        unsigned long long i = st->leftover;

        st->buffer[i++] = 1;
        for (; i < poly1305_block_size; i++) {
            st->buffer[i] = 0;
        }
        st->final = 1;
        poly1305_blocks(st, st->buffer, poly1305_block_size);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    c  = h1 >> 26;
    h1 = h1 & 0x3ffffff;
    h2 += c;
    c  = h2 >> 26;
    h2 = h2 & 0x3ffffff;
    h3 += c;
    c  = h3 >> 26;
    h3 = h3 & 0x3ffffff;
    h4 += c;
    c  = h4 >> 26;
    h4 = h4 & 0x3ffffff;
    h0 += c * 5;
    c  = h0 >> 26;
    h0 = h0 & 0x3ffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5;
    c  = g0 >> 26;
    g0 &= 0x3ffffff;
    g1 = h1 + c;
    c  = g1 >> 26;
    g1 &= 0x3ffffff;
    g2 = h2 + c;
    c  = g2 >> 26;
    g2 &= 0x3ffffff;
    g3 = h3 + c;
    c  = g3 >> 26;
    g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;

    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f  = (unsigned long long) h0 + st->pad[0];
    h0 = (unsigned long) f;
    f  = (unsigned long long) h1 + st->pad[1] + (f >> 32);
    h1 = (unsigned long) f;
    f  = (unsigned long long) h2 + st->pad[2] + (f >> 32);
    h2 = (unsigned long) f;
    f  = (unsigned long long) h3 + st->pad[3] + (f >> 32);
    h3 = (unsigned long) f;

    STORE32_LE(mac + 0, (uint32_t) h0);
    STORE32_LE(mac + 4, (uint32_t) h1);
    STORE32_LE(mac + 8, (uint32_t) h2);
    STORE32_LE(mac + 12, (uint32_t) h3);

    /* zero out the state */
    sodium_memzero((void *) st, sizeof *st);
}

static inline int
crypto_verify_n(const unsigned char *x_, const unsigned char *y_,
                const int n)
{
    const volatile unsigned char *volatile x =
        (const volatile unsigned char *volatile) x_;
    const volatile unsigned char *volatile y =
        (const volatile unsigned char *volatile) y_;
    volatile uint_fast16_t d = 0U;
    int i;

    for (i = 0; i < n; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

int
crypto_verify_16(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_n(x, y, crypto_verify_16_BYTES);
}

int
crypto_core_hsalsa20(unsigned char *out,
                     const unsigned char *in,
                     const unsigned char *k,
                     const unsigned char *c)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8,
             x9, x10, x11, x12, x13, x14,  x15;
    int      i;

    if (c == NULL) {
        x0 = U32C(0x61707865);
        x5 = U32C(0x3320646e);
        x10 = U32C(0x79622d32);
        x15 = U32C(0x6b206574);
    } else {
        x0 = LOAD32_LE(c + 0);
        x5 = LOAD32_LE(c + 4);
        x10 = LOAD32_LE(c + 8);
        x15 = LOAD32_LE(c + 12);
    }
    x1 = LOAD32_LE(k + 0);
    x2 = LOAD32_LE(k + 4);
    x3 = LOAD32_LE(k + 8);
    x4 = LOAD32_LE(k + 12);
    x11 = LOAD32_LE(k + 16);
    x12 = LOAD32_LE(k + 20);
    x13 = LOAD32_LE(k + 24);
    x14 = LOAD32_LE(k + 28);
    x6 = LOAD32_LE(in + 0);
    x7 = LOAD32_LE(in + 4);
    x8 = LOAD32_LE(in + 8);
    x9 = LOAD32_LE(in + 12);

    for (i = ROUNDS; i > 0; i -= 2) {
        x4 ^= ROTL32(x0 + x12, 7);
        x8 ^= ROTL32(x4 + x0, 9);
        x12 ^= ROTL32(x8 + x4, 13);
        x0 ^= ROTL32(x12 + x8, 18);
        x9 ^= ROTL32(x5 + x1, 7);
        x13 ^= ROTL32(x9 + x5, 9);
        x1 ^= ROTL32(x13 + x9, 13);
        x5 ^= ROTL32(x1 + x13, 18);
        x14 ^= ROTL32(x10 + x6, 7);
        x2 ^= ROTL32(x14 + x10, 9);
        x6 ^= ROTL32(x2 + x14, 13);
        x10 ^= ROTL32(x6 + x2, 18);
        x3 ^= ROTL32(x15 + x11, 7);
        x7 ^= ROTL32(x3 + x15, 9);
        x11 ^= ROTL32(x7 + x3, 13);
        x15 ^= ROTL32(x11 + x7, 18);
        x1 ^= ROTL32(x0 + x3, 7);
        x2 ^= ROTL32(x1 + x0, 9);
        x3 ^= ROTL32(x2 + x1, 13);
        x0 ^= ROTL32(x3 + x2, 18);
        x6 ^= ROTL32(x5 + x4, 7);
        x7 ^= ROTL32(x6 + x5, 9);
        x4 ^= ROTL32(x7 + x6, 13);
        x5 ^= ROTL32(x4 + x7, 18);
        x11 ^= ROTL32(x10 + x9, 7);
        x8 ^= ROTL32(x11 + x10, 9);
        x9 ^= ROTL32(x8 + x11, 13);
        x10 ^= ROTL32(x9 + x8, 18);
        x12 ^= ROTL32(x15 + x14, 7);
        x13 ^= ROTL32(x12 + x15, 9);
        x14 ^= ROTL32(x13 + x12, 13);
        x15 ^= ROTL32(x14 + x13, 18);
    }

    STORE32_LE(out + 0, x0);
    STORE32_LE(out + 4, x5);
    STORE32_LE(out + 8, x10);
    STORE32_LE(out + 12, x15);
    STORE32_LE(out + 16, x6);
    STORE32_LE(out + 20, x7);
    STORE32_LE(out + 24, x8);
    STORE32_LE(out + 28, x9);

    return 0;
}


int main() {
    sodium_init();

}
