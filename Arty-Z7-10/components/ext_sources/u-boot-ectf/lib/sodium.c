#include <linux/string.h>
#include <sodium.h>
#include <linux/ctype.h>
#include <stdlib.h>
#include <common.h>

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
sodium_memcmp(const void *const b1_, const void *const b2_, size_t len);
int
sodium_is_zero(const unsigned char *n, const size_t nlen);
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
sodium_memcmp(const void *const b1_, const void *const b2_, size_t len)
{
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
    size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

int
sodium_is_zero(const unsigned char *n, const size_t nlen)
{
    size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
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
    volatile uint16_t d = 0U;
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

/*************************************************************
 ***************************SHA512****************************
 ************************************************************/

static void
be64enc_vect(unsigned char *dst, const uint64_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        STORE64_BE(dst + i * 8, src[i]);
    }
}

static void
be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        dst[i] = LOAD64_BE(src + i * 8);
    }
}

static const uint64_t Krnd[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n) (x >> n)
#define ROTR(x, n) ROTR64(x, n)
#define S0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define s1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define RND(a, b, c, d, e, f, g, h, k) \
    h += S1(e) + Ch(e, f, g) + k;      \
    d += h;                            \
    h += S0(a) + Maj(a, b, c);

#define RNDr(S, W, i, ii)                                                   \
    RND(S[(80 - i) % 8], S[(81 - i) % 8], S[(82 - i) % 8], S[(83 - i) % 8], \
        S[(84 - i) % 8], S[(85 - i) % 8], S[(86 - i) % 8], S[(87 - i) % 8], \
        W[i + ii] + Krnd[i + ii])

#define MSCH(W, ii, i) \
    W[i + ii + 16] =   \
        s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii]

static void
SHA512_Transform(uint64_t *state, const uint8_t block[128], uint64_t W[80],
                 uint64_t S[8])
{
    int i;

    be64dec_vect(W, block, 128);
    memcpy(S, state, 64);
    for (i = 0; i < 80; i += 16) {
        RNDr(S, W, 0, i);
        RNDr(S, W, 1, i);
        RNDr(S, W, 2, i);
        RNDr(S, W, 3, i);
        RNDr(S, W, 4, i);
        RNDr(S, W, 5, i);
        RNDr(S, W, 6, i);
        RNDr(S, W, 7, i);
        RNDr(S, W, 8, i);
        RNDr(S, W, 9, i);
        RNDr(S, W, 10, i);
        RNDr(S, W, 11, i);
        RNDr(S, W, 12, i);
        RNDr(S, W, 13, i);
        RNDr(S, W, 14, i);
        RNDr(S, W, 15, i);
        if (i == 64) {
            break;
        }
        MSCH(W, 0, i);
        MSCH(W, 1, i);
        MSCH(W, 2, i);
        MSCH(W, 3, i);
        MSCH(W, 4, i);
        MSCH(W, 5, i);
        MSCH(W, 6, i);
        MSCH(W, 7, i);
        MSCH(W, 8, i);
        MSCH(W, 9, i);
        MSCH(W, 10, i);
        MSCH(W, 11, i);
        MSCH(W, 12, i);
        MSCH(W, 13, i);
        MSCH(W, 14, i);
        MSCH(W, 15, i);
    }
    for (i = 0; i < 8; i++) {
        state[i] += S[i];
    }
}

static const uint8_t PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
SHA512_Pad(crypto_hash_sha512_state *state, uint64_t tmp64[80 + 8])
{
    unsigned int r;
    unsigned int i;

    r = (unsigned int) ((state->count[1] >> 3) & 0x7f);
    if (r < 112) {
        for (i = 0; i < 112 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
    } else {
        for (i = 0; i < 128 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
        SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
        memset(&state->buf[0], 0, 112);
    }
    be64enc_vect(&state->buf[112], state->count, 16);
    SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
}

int
crypto_hash_sha512_init(crypto_hash_sha512_state *state)
{
    static const uint64_t sha512_initial_state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    state->count[0] = state->count[1] = (uint64_t) 0U;
    memcpy(state->state, sha512_initial_state, sizeof sha512_initial_state);

    return 0;
}

int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                          const unsigned char *in, unsigned long long inlen)
{
    uint64_t           tmp64[80 + 8];
    uint64_t           bitlen[2];
    unsigned long long i;
    unsigned long long r;

    if (inlen <= 0U) {
        return 0;
    }
    r = (unsigned long long) ((state->count[1] >> 3) & 0x7f);

    bitlen[1] = ((uint64_t) inlen) << 3;
    bitlen[0] = ((uint64_t) inlen) >> 61;
    /* LCOV_EXCL_START */
    if ((state->count[1] += bitlen[1]) < bitlen[1]) {
        state->count[0]++;
    }
    /* LCOV_EXCL_STOP */
    state->count[0] += bitlen[0];
    if (inlen < 128 - r) {
        for (i = 0; i < inlen; i++) {
            state->buf[r + i] = in[i];
        }
        return 0;
    }
    for (i = 0; i < 128 - r; i++) {
        state->buf[r + i] = in[i];
    }
    SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
    in += 128 - r;
    inlen -= 128 - r;

    while (inlen >= 128) {
        SHA512_Transform(state->state, in, &tmp64[0], &tmp64[80]);
        in += 128;
        inlen -= 128;
    }
    inlen &= 127;
    for (i = 0; i < inlen; i++) {
        state->buf[i] = in[i];
    }
    sodium_memzero((void *) tmp64, sizeof tmp64);

    return 0;
}

int
crypto_hash_sha512_final(crypto_hash_sha512_state *state, unsigned char *out)
{
    uint64_t tmp64[80 + 8];

    SHA512_Pad(state, tmp64);
    be64enc_vect(out, state->state, 64);
    sodium_memzero((void *) tmp64, sizeof tmp64);
    sodium_memzero((void *) state, sizeof *state);

    return 0;
}

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                   unsigned long long inlen)
{
    crypto_hash_sha512_state state;

    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, in, inlen);
    crypto_hash_sha512_final(&state, out);

    return 0;
}

int
crypto_hash_sha256(unsigned char *out, const unsigned char *in, 
                   unsigned long long inlen)
{
    unsigned char sha512out[64];
    crypto_hash_sha512(sha512out, in, inlen);
    memcpy(out, sha512out, 32);

    return 1;
}

/**************************************************************
 ************************SIGNING FUNCTIONS*********************
 *************************************************************/

static inline uint64_t
load_3(const unsigned char *in)
{
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;

    return result;
}

static inline uint64_t
load_4(const unsigned char *in)
{
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;

    return result;
}


void
fe25519_frombytes(fe25519 h, const unsigned char *s)
{
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 3;
    int64_t h4 = load_3(s + 13) << 2;
    int64_t h5 = load_4(s + 16);
    int64_t h6 = load_3(s + 20) << 7;
    int64_t h7 = load_3(s + 23) << 5;
    int64_t h8 = load_3(s + 26) << 4;
    int64_t h9 = (load_3(s + 29) & 8388607) << 2;

    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;

    carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
    h0 += carry9 * 19;
    h9 -= carry9 * ((uint64_t) 1L << 25);
    carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
    h2 += carry1;
    h1 -= carry1 * ((uint64_t) 1L << 25);
    carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
    h4 += carry3;
    h3 -= carry3 * ((uint64_t) 1L << 25);
    carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
    h6 += carry5;
    h5 -= carry5 * ((uint64_t) 1L << 25);
    carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
    h8 += carry7;
    h7 -= carry7 * ((uint64_t) 1L << 25);

    carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
    h1 += carry0;
    h0 -= carry0 * ((uint64_t) 1L << 26);
    carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
    h3 += carry2;
    h2 -= carry2 * ((uint64_t) 1L << 26);
    carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
    h5 += carry4;
    h4 -= carry4 * ((uint64_t) 1L << 26);
    carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
    h7 += carry6;
    h6 -= carry6 * ((uint64_t) 1L << 26);
    carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
    h9 += carry8;
    h8 -= carry8 * ((uint64_t) 1L << 26);

    h[0] = (int32_t) h0;
    h[1] = (int32_t) h1;
    h[2] = (int32_t) h2;
    h[3] = (int32_t) h3;
    h[4] = (int32_t) h4;
    h[5] = (int32_t) h5;
    h[6] = (int32_t) h6;
    h[7] = (int32_t) h7;
    h[8] = (int32_t) h8;
    h[9] = (int32_t) h9;
}

static void
fe25519_reduce(fe25519 h, const fe25519 f)
{
    int32_t h0 = f[0];
    int32_t h1 = f[1];
    int32_t h2 = f[2];
    int32_t h3 = f[3];
    int32_t h4 = f[4];
    int32_t h5 = f[5];
    int32_t h6 = f[6];
    int32_t h7 = f[7];
    int32_t h8 = f[8];
    int32_t h9 = f[9];

    int32_t q;
    int32_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;

    q = (19 * h9 + ((uint32_t) 1L << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
    h0 += 19 * q;
    /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

    carry0 = h0 >> 26;
    h1 += carry0;
    h0 -= carry0 * ((uint32_t) 1L << 26);
    carry1 = h1 >> 25;
    h2 += carry1;
    h1 -= carry1 * ((uint32_t) 1L << 25);
    carry2 = h2 >> 26;
    h3 += carry2;
    h2 -= carry2 * ((uint32_t) 1L << 26);
    carry3 = h3 >> 25;
    h4 += carry3;
    h3 -= carry3 * ((uint32_t) 1L << 25);
    carry4 = h4 >> 26;
    h5 += carry4;
    h4 -= carry4 * ((uint32_t) 1L << 26);
    carry5 = h5 >> 25;
    h6 += carry5;
    h5 -= carry5 * ((uint32_t) 1L << 25);
    carry6 = h6 >> 26;
    h7 += carry6;
    h6 -= carry6 * ((uint32_t) 1L << 26);
    carry7 = h7 >> 25;
    h8 += carry7;
    h7 -= carry7 * ((uint32_t) 1L << 25);
    carry8 = h8 >> 26;
    h9 += carry8;
    h8 -= carry8 * ((uint32_t) 1L << 26);
    carry9 = h9 >> 25;
    h9 -= carry9 * ((uint32_t) 1L << 25);

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
    h[5] = h5;
    h[6] = h6;
    h[7] = h7;
    h[8] = h8;
    h[9] = h9;
}

void
fe25519_tobytes(unsigned char *s, const fe25519 h)
{
    fe25519 t;

    fe25519_reduce(t, h);
    s[0]  = t[0] >> 0;
    s[1]  = t[0] >> 8;
    s[2]  = t[0] >> 16;
    s[3]  = (t[0] >> 24) | (t[1] * ((uint32_t) 1 << 2));
    s[4]  = t[1] >> 6;
    s[5]  = t[1] >> 14;
    s[6]  = (t[1] >> 22) | (t[2] * ((uint32_t) 1 << 3));
    s[7]  = t[2] >> 5;
    s[8]  = t[2] >> 13;
    s[9]  = (t[2] >> 21) | (t[3] * ((uint32_t) 1 << 5));
    s[10] = t[3] >> 3;
    s[11] = t[3] >> 11;
    s[12] = (t[3] >> 19) | (t[4] * ((uint32_t) 1 << 6));
    s[13] = t[4] >> 2;
    s[14] = t[4] >> 10;
    s[15] = t[4] >> 18;
    s[16] = t[5] >> 0;
    s[17] = t[5] >> 8;
    s[18] = t[5] >> 16;
    s[19] = (t[5] >> 24) | (t[6] * ((uint32_t) 1 << 1));
    s[20] = t[6] >> 7;
    s[21] = t[6] >> 15;
    s[22] = (t[6] >> 23) | (t[7] * ((uint32_t) 1 << 3));
    s[23] = t[7] >> 5;
    s[24] = t[7] >> 13;
    s[25] = (t[7] >> 21) | (t[8] * ((uint32_t) 1 << 4));
    s[26] = t[8] >> 4;
    s[27] = t[8] >> 12;
    s[28] = (t[8] >> 20) | (t[9] * ((uint32_t) 1 << 6));
    s[29] = t[9] >> 2;
    s[30] = t[9] >> 10;
    s[31] = t[9] >> 18;
}

#include <ed25519_ref10_fe_25_5.h>

int
ge25519_is_canonical(const unsigned char *s)
{
    unsigned char c;
    unsigned char d;
    unsigned int  i;

    c = (s[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
        c |= s[i] ^ 0xff;
    }
    c = (((unsigned int) c) - 1U) >> 8;
    d = (0xed - 1U - (unsigned int) s[0]) >> 8;

    return 1 - (c & d & 1);
}
 
int
sc25519_is_canonical(const unsigned char s[32])
{
    /* 2^252+27742317777372353535851937790883648493 */
    static const unsigned char L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    unsigned char c = 0;
    unsigned char n = 1;
    unsigned int  i = 32;

    do {
        i--;
        c |= ((s[i] - L[i]) >> 8) & n;
        n &= ((s[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

int
ge25519_has_small_order(const unsigned char s[32])
{
    CRYPTO_ALIGN(16)
    static const unsigned char blacklist[][32] = {
        /* 0 (order 4) */
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 1 (order 1) */
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 2707385501144840649318225287225658788936804267575313519463743609750303402022
           (order 8) */
        { 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
          0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
          0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 },
        /* 55188659117513257062467267217118295137698188065244968500265048394206261417927
           (order 8) */
        { 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
          0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
          0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a },
        /* p-1 (order 2) */
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p (=0, order 4) */
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p+1 (=1, order 1) */
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[7] = { 0 };
    unsigned int  k;
    size_t        i, j;

    COMPILER_ASSERT(7 == sizeof blacklist / sizeof blacklist[0]);
    for (j = 0; j < 31; j++) {
        for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
            c[i] |= s[j] ^ blacklist[i][j];
        }
    }
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        c[i] |= (s[j] & 0x7f) ^ blacklist[i][j];
    }
    k = 0;
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        k |= (c[i] - 1);
    }
    return (int) ((k >> 8) & 1);
}

void
fe25519_invert(fe25519 out, const fe25519 z)
{
    fe25519 t0;
    fe25519 t1;
    fe25519 t2;
    fe25519 t3;
    int     i;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t2, t0);
    fe25519_mul(t1, t1, t2);
    fe25519_sq(t2, t1);
    for (i = 1; i < 5; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 1; i < 20; ++i) {
        fe25519_sq(t3, t3);
    }
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 1; i < 100; ++i) {
        fe25519_sq(t3, t3);
    }
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 5; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(out, t1, t0);
}


static void
fe25519_pow22523(fe25519 out, const fe25519 z)
{
    fe25519 t0;
    fe25519 t1;
    fe25519 t2;
    int     i;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t0, t0);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe25519_sq(t2, t2);
    }
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe25519_sq(t1, t1);
    }
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t0, t0);
    fe25519_sq(t0, t0);
    fe25519_mul(out, t0, z);
}

void
sc25519_reduce(unsigned char s[64])
{
    int64_t s0  = 2097151 & load_3(s);
    int64_t s1  = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2  = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3  = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4  = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5  = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6  = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7  = 2097151 & (load_3(s + 18) >> 3);
    int64_t s8  = 2097151 & load_3(s + 21);
    int64_t s9  = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (load_3(s + 39) >> 3);
    int64_t s16 = 2097151 & load_3(s + 42);
    int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);

    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    carry6 = (s6 + (int64_t) (1L << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ((uint64_t) 1L << 21);
    carry8 = (s8 + (int64_t) (1L << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ((uint64_t) 1L << 21);
    carry10 = (s10 + (int64_t) (1L << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ((uint64_t) 1L << 21);
    carry12 = (s12 + (int64_t) (1L << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 * ((uint64_t) 1L << 21);
    carry14 = (s14 + (int64_t) (1L << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 * ((uint64_t) 1L << 21);
    carry16 = (s16 + (int64_t) (1L << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 * ((uint64_t) 1L << 21);

    carry7 = (s7 + (int64_t) (1L << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * ((uint64_t) 1L << 21);
    carry9 = (s9 + (int64_t) (1L << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * ((uint64_t) 1L << 21);
    carry11 = (s11 + (int64_t) (1L << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * ((uint64_t) 1L << 21);
    carry13 = (s13 + (int64_t) (1L << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 * ((uint64_t) 1L << 21);
    carry15 = (s15 + (int64_t) (1L << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 * ((uint64_t) 1L << 21);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (int64_t) (1L << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 * ((uint64_t) 1L << 21);
    carry2 = (s2 + (int64_t) (1L << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 * ((uint64_t) 1L << 21);
    carry4 = (s4 + (int64_t) (1L << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 * ((uint64_t) 1L << 21);
    carry6 = (s6 + (int64_t) (1L << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 * ((uint64_t) 1L << 21);
    carry8 = (s8 + (int64_t) (1L << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 * ((uint64_t) 1L << 21);
    carry10 = (s10 + (int64_t) (1L << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 * ((uint64_t) 1L << 21);

    carry1 = (s1 + (int64_t) (1L << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 * ((uint64_t) 1L << 21);
    carry3 = (s3 + (int64_t) (1L << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 * ((uint64_t) 1L << 21);
    carry5 = (s5 + (int64_t) (1L << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 * ((uint64_t) 1L << 21);
    carry7 = (s7 + (int64_t) (1L << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 * ((uint64_t) 1L << 21);
    carry9 = (s9 + (int64_t) (1L << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 * ((uint64_t) 1L << 21);
    carry11 = (s11 + (int64_t) (1L << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 * ((uint64_t) 1L << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * ((uint64_t) 1L << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * ((uint64_t) 1L << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * ((uint64_t) 1L << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * ((uint64_t) 1L << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * ((uint64_t) 1L << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * ((uint64_t) 1L << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * ((uint64_t) 1L << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * ((uint64_t) 1L << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * ((uint64_t) 1L << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * ((uint64_t) 1L << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * ((uint64_t) 1L << 21);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 * ((uint64_t) 1L << 21);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 * ((uint64_t) 1L << 21);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 * ((uint64_t) 1L << 21);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 * ((uint64_t) 1L << 21);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 * ((uint64_t) 1L << 21);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 * ((uint64_t) 1L << 21);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 * ((uint64_t) 1L << 21);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 * ((uint64_t) 1L << 21);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 * ((uint64_t) 1L << 21);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 * ((uint64_t) 1L << 21);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 * ((uint64_t) 1L << 21);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 * ((uint64_t) 1L << 21);

    s[0]  = s0 >> 0;
    s[1]  = s0 >> 8;
    s[2]  = (s0 >> 16) | (s1 * ((uint64_t) 1 << 5));
    s[3]  = s1 >> 3;
    s[4]  = s1 >> 11;
    s[5]  = (s1 >> 19) | (s2 * ((uint64_t) 1 << 2));
    s[6]  = s2 >> 6;
    s[7]  = (s2 >> 14) | (s3 * ((uint64_t) 1 << 7));
    s[8]  = s3 >> 1;
    s[9]  = s3 >> 9;
    s[10] = (s3 >> 17) | (s4 * ((uint64_t) 1 << 4));
    s[11] = s4 >> 4;
    s[12] = s4 >> 12;
    s[13] = (s4 >> 20) | (s5 * ((uint64_t) 1 << 1));
    s[14] = s5 >> 7;
    s[15] = (s5 >> 15) | (s6 * ((uint64_t) 1 << 6));
    s[16] = s6 >> 2;
    s[17] = s6 >> 10;
    s[18] = (s6 >> 18) | (s7 * ((uint64_t) 1 << 3));
    s[19] = s7 >> 5;
    s[20] = s7 >> 13;
    s[21] = s8 >> 0;
    s[22] = s8 >> 8;
    s[23] = (s8 >> 16) | (s9 * ((uint64_t) 1 << 5));
    s[24] = s9 >> 3;
    s[25] = s9 >> 11;
    s[26] = (s9 >> 19) | (s10 * ((uint64_t) 1 << 2));
    s[27] = s10 >> 6;
    s[28] = (s10 >> 14) | (s11 * ((uint64_t) 1 << 7));
    s[29] = s11 >> 1;
    s[30] = s11 >> 9;
    s[31] = s11 >> 17;
}

int
ge25519_frombytes_negate_vartime(ge25519_p3 *h, const unsigned char *s)
{
    fe25519 u;
    fe25519 v;
    fe25519 v3;
    fe25519 vxx;
    fe25519 m_root_check, p_root_check;

    fe25519_frombytes(h->Y, s);
    fe25519_1(h->Z);
    fe25519_sq(u, h->Y);
    fe25519_mul(v, u, d);
    fe25519_sub(u, u, h->Z); /* u = y^2-1 */
    fe25519_add(v, v, h->Z); /* v = dy^2+1 */

    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v); /* v3 = v^3 */
    fe25519_sq(h->X, v3);
    fe25519_mul(h->X, h->X, v);
    fe25519_mul(h->X, h->X, u); /* x = uv^7 */

    fe25519_pow22523(h->X, h->X); /* x = (uv^7)^((q-5)/8) */
    fe25519_mul(h->X, h->X, v3);
    fe25519_mul(h->X, h->X, u); /* x = uv^3(uv^7)^((q-5)/8) */

    fe25519_sq(vxx, h->X);
    fe25519_mul(vxx, vxx, v);
    fe25519_sub(m_root_check, vxx, u); /* vx^2-u */
    if (fe25519_iszero(m_root_check) == 0) {
        fe25519_add(p_root_check, vxx, u); /* vx^2+u */
        if (fe25519_iszero(p_root_check) == 0) {
            return -1;
        }
        fe25519_mul(h->X, h->X, sqrtm1);
    }

    if (fe25519_isnegative(h->X) == (s[31] >> 7)) {
        fe25519_neg(h->X, h->X);
    }
    fe25519_mul(h->T, h->X, h->Y);

    return 0;
}


static void
slide_vartime(signed char *r, const unsigned char *a)
{
    int i;
    int b;
    int k;
    int ribs;
    int cmp;

    for (i = 0; i < 256; ++i) {
        r[i] = 1 & (a[i >> 3] >> (i & 7));
    }
    for (i = 0; i < 256; ++i) {
        if (! r[i]) {
            continue;
        }
        for (b = 1; b <= 6 && i + b < 256; ++b) {
            if (! r[i + b]) {
                continue;
            }
            ribs = r[i + b] << b;
            cmp = r[i] + ribs;
            if (cmp <= 15) {
                r[i] = cmp;
                r[i + b] = 0;
            } else {
                cmp = r[i] - ribs;
                if (cmp < -15) {
                    break;
                }
                r[i] = cmp;
                for (k = i + b; k < 256; ++k) {
                    if (! r[k]) {
                        r[k] = 1;
                        break;
                    }
                    r[k] = 0;
                }
            }
        }
    }
}

static void
ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p)
{
    fe25519 t0;

    fe25519_sq(r->X, p->X);
    fe25519_sq(r->Z, p->Y);
    fe25519_sq2(r->T, p->Z);
    fe25519_add(r->Y, p->X, p->Y);
    fe25519_sq(t0, r->Y);
    fe25519_add(r->Y, r->Z, r->X);
    fe25519_sub(r->Z, r->Z, r->X);
    fe25519_sub(r->X, t0, r->Y);
    fe25519_sub(r->T, r->T, r->Z);
}

static void
ge25519_p2_0(ge25519_p2 *h)
{
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
}

void
ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p)
{
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
}

void
ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p)
{
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
    fe25519_mul(r->T, p->X, p->Y);
}

void
ge25519_p3_to_cached(ge25519_cached *r, const ge25519_p3 *p)
{
    fe25519_add(r->YplusX, p->Y, p->X);
    fe25519_sub(r->YminusX, p->Y, p->X);
    fe25519_copy(r->Z, p->Z);
    fe25519_mul(r->T2d, p->T, d2);
}

void
ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->YplusX);
    fe25519_mul(r->Y, r->Y, q->YminusX);
    fe25519_mul(r->T, q->T2d, p->T);
    fe25519_mul(r->X, p->Z, q->Z);
    fe25519_add(t0, r->X, r->X);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_add(r->Z, t0, r->T);
    fe25519_sub(r->T, t0, r->T);
}

static void
ge25519_madd(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yplusx);
    fe25519_mul(r->Y, r->Y, q->yminusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_add(r->Z, t0, r->T);
    fe25519_sub(r->T, t0, r->T);
}

static void
ge25519_msub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->yminusx);
    fe25519_mul(r->Y, r->Y, q->yplusx);
    fe25519_mul(r->T, q->xy2d, p->T);
    fe25519_add(t0, p->Z, p->Z);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_sub(r->Z, t0, r->T);
    fe25519_add(r->T, t0, r->T);
}

void
ge25519_sub(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_cached *q)
{
    fe25519 t0;

    fe25519_add(r->X, p->Y, p->X);
    fe25519_sub(r->Y, p->Y, p->X);
    fe25519_mul(r->Z, r->X, q->YminusX);
    fe25519_mul(r->Y, r->Y, q->YplusX);
    fe25519_mul(r->T, q->T2d, p->T);
    fe25519_mul(r->X, p->Z, q->Z);
    fe25519_add(t0, r->X, r->X);
    fe25519_sub(r->X, r->Z, r->Y);
    fe25519_add(r->Y, r->Z, r->Y);
    fe25519_sub(r->Z, t0, r->T);
    fe25519_add(r->T, t0, r->T);
}
void
ge25519_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p)
{
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
}

static void
ge25519_p3_dbl(ge25519_p1p1 *r, const ge25519_p3 *p)
{
    ge25519_p2 q;
    ge25519_p3_to_p2(&q, p);
    ge25519_p2_dbl(r, &q);
}

void
ge25519_double_scalarmult_vartime(ge25519_p2 *r, const unsigned char *a,
                                  const ge25519_p3 *A, const unsigned char *b)
{
    static const ge25519_precomp Bi[8] = { 
        # include "base2.h"
    };

    signed char    aslide[256];
    signed char    bslide[256];
    ge25519_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
    ge25519_p1p1   t;
    ge25519_p3     u;
    ge25519_p3     A2;
    int            i;

    slide_vartime(aslide, a);
    slide_vartime(bslide, b);

    ge25519_p3_to_cached(&Ai[0], A);

    ge25519_p3_dbl(&t, A);
    ge25519_p1p1_to_p3(&A2, &t);

    ge25519_add(&t, &A2, &Ai[0]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[1], &u);

    ge25519_add(&t, &A2, &Ai[1]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[2], &u);

    ge25519_add(&t, &A2, &Ai[2]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[3], &u);

    ge25519_add(&t, &A2, &Ai[3]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[4], &u);

    ge25519_add(&t, &A2, &Ai[4]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[5], &u);

    ge25519_add(&t, &A2, &Ai[5]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[6], &u);

    ge25519_add(&t, &A2, &Ai[6]);
    ge25519_p1p1_to_p3(&u, &t);
    ge25519_p3_to_cached(&Ai[7], &u);

    ge25519_p2_0(r);

    for (i = 255; i >= 0; --i) {
        if (aslide[i] || bslide[i]) {
            break;
        }
    }

    for (; i >= 0; --i) {
        ge25519_p2_dbl(&t, r);

        if (aslide[i] > 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_add(&t, &u, &Ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        if (bslide[i] > 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_madd(&t, &u, &Bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_msub(&t, &u, &Bi[(-bslide[i]) / 2]);
        }

        ge25519_p1p1_to_p2(r, &t);
    }
}

void
ge25519_tobytes(unsigned char *s, const ge25519_p2 *h)
{
    fe25519 recip;
    fe25519 x;
    fe25519 y;

    fe25519_invert(recip, h->Z);
    fe25519_mul(x, h->X, recip);
    fe25519_mul(y, h->Y, recip);
    fe25519_tobytes(s, y);
    s[31] ^= fe25519_isnegative(x) << 7;
}

void
_crypto_sign_ed25519_ref10_hinit(crypto_hash_sha512_state *hs, int prehashed)
{
    static const unsigned char DOM2PREFIX[32 + 2] = {
        'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
        'n', 'o', ' ',
        'E', 'd', '2', '5', '5', '1', '9', ' ',
        'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
    };

    crypto_hash_sha512_init(hs);
    if (prehashed) {
        crypto_hash_sha512_update(hs, DOM2PREFIX, sizeof DOM2PREFIX);
    }
}

int
crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    return crypto_verify_n(x, y, crypto_verify_32_BYTES);
}

int
_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    crypto_hash_sha512_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    ge25519_p3               A;
    ge25519_p2               R;

#ifdef ED25519_COMPAT
    if (sig[63] & 224) {
        return -1;
    }
#else
    if (sc25519_is_canonical(sig + 32) == 0 ||
        ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (ge25519_is_canonical(pk) == 0 ||
        ge25519_has_small_order(pk) != 0) {
        return -1;
    }
#endif
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }
    _crypto_sign_ed25519_ref10_hinit(&hs, prehashed);
    crypto_hash_sha512_update(&hs, sig, 32);
    crypto_hash_sha512_update(&hs, pk, 32);
    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, h);
    sc25519_reduce(h);

    ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge25519_tobytes(rcheck, &R);

    return crypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           sodium_memcmp(sig, rcheck, 32);
}
    
static int
crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long   mlen,
                                    const unsigned char *pk)
{
    return _crypto_sign_ed25519_verify_detached(sig, m, mlen, pk, 0);
}

static int
crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *sm, unsigned long long smlen,
                         const unsigned char *pk)
{
    unsigned long long mlen;

    if (smlen < 64 || smlen - 64 > crypto_sign_ed25519_MESSAGEBYTES_MAX) {
        goto badsig;
    }
    mlen = smlen - 64;
    if (crypto_sign_ed25519_verify_detached(sm, sm + 64, mlen, pk) != 0) {
        if (m != NULL) {
            memset(m, 0, mlen);
        }
        goto badsig;
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    if (m != NULL) {
        memmove(m, sm + 64, mlen);
    }
    return 0;

badsig:
    if (mlen_p != NULL) {
        *mlen_p = 0;
    }
    return -1;
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk)
{
    return crypto_sign_ed25519_open(m, mlen_p, sm, smlen, pk);
}

int
sodium_init() {
  return 1;
}

