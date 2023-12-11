#include <string.h>
#include "sm3.h"

static const uint32 T_J[] = {
    0x79cc4519, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

static const uint32 IV[] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

#if WORD_SIZE == 8
static const word IPAD = 0x3636363636363636LL;
static const word OPAD = 0x5c5c5c5c5c5c5c5cLL;
#else
static const word IPAD = 0x36363636;
static const word OPAD = 0x5c5c5c5c;
#endif

inline uint32 rotl(uint32 x, int n) {
    return x << n | x >> (32 - n);
}

inline uint32 byte_int32(cbytes b) {
    return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
}

inline void int32_bytes(bytes out, uint32 x) {
    out[0] = (byte)(x >> 24);
    out[1] = (byte)(x >> 16);
    out[2] = (byte)(x >> 8);
    out[3] = (byte)x;
}

inline void int64_bytes(bytes out, uint64 x) {
    out[0] = (byte)(x >> 56);
    out[1] = (byte)(x >> 48);
    out[2] = (byte)(x >> 40);
    out[3] = (byte)(x >> 32);
    out[4] = (byte)(x >> 24);
    out[5] = (byte)(x >> 16);
    out[6] = (byte)(x >> 8);
    out[7] = (byte)x;
}

inline uint32 ff_j(uint32 x, uint32 y, uint32 z, uint32 j) {
    return (j >= 16)
           ? (x & y) | (x & z) | (y & z)
           : x ^ y ^ z;
}

inline uint32 gg_j(uint32 x, uint32 y, uint32 z, uint32 j) {
    return (j >= 16)
           ? (x & y) | (~x & z)
           : x ^ y ^ z;
}

inline uint32 p_0(uint32 x) {
    return x ^ rotl(x, 9) ^ rotl(x, 17);
}

inline uint32 p_1(uint32 x) {
    return x ^ rotl(x, 15) ^ rotl(x, 23);
}

inline void bytes_4int(uint32 *w, cbytes b) {
    w[0] = byte_int32(b);
    w[1] = byte_int32(b + 4);
    w[2] = byte_int32(b + 8);
    w[3] = byte_int32(b + 12);
}

static void get_w(uint32 *w, uint32 *w1, cbytes bi) {
    bytes_4int(w, bi);
    bytes_4int(w + 4, bi + 16);
    bytes_4int(w + 8, bi + 32);
    bytes_4int(w + 12, bi + 48);
    for (int j = 16; j < 68; j++) {
        w[j] = p_1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15))
               ^ rotl(w[j - 13], 7) ^ w[j - 6];
    }
    for (int j = 0; j < 64; j += 4) {
        w1[j] = w[j] ^ w[j + 4];
        w1[j + 1] = w[j + 1] ^ w[j + 5];
        w1[j + 2] = w[j + 2] ^ w[j + 6];
        w1[j + 3] = w[j + 3] ^ w[j + 7];
    }
}

static uint32 *cf(uint32 *v_out, const uint32 *vi, cbytes bi) {
    uint32 w[68], w1[64];
    get_w(w, w1, bi);
    uint32 a = vi[0];
    uint32 b = vi[1];
    uint32 c = vi[2];
    uint32 d = vi[3];
    uint32 e = vi[4];
    uint32 f = vi[5];
    uint32 g = vi[6];
    uint32 h = vi[7];

    for (int j = 0; j < 64; j++) {
        uint32 s1 = rotl(rotl(a, 12) + e + rotl(T_J[j >> 4], (j & 31)), 7);
        uint32 s2 = s1 ^ rotl(a, 12);
        uint32 t1 = ff_j(a, b, c, j) + d + s2 + w1[j];
        uint32 t2 = gg_j(e, f, g, j) + h + s1 + w[j];
        d = c;
        c = rotl(b, 9);
        b = a;
        a = t1;
        h = g;
        g = rotl(f, 19);
        f = e;
        e = p_0(t2);
    }

    v_out[0] = a ^ vi[0];
    v_out[1] = b ^ vi[1];
    v_out[2] = c ^ vi[2];
    v_out[3] = d ^ vi[3];
    v_out[4] = e ^ vi[4];
    v_out[5] = f ^ vi[5];
    v_out[6] = g ^ vi[6];
    v_out[7] = h ^ vi[7];
    return v_out;
}

static int padding(bytes dst, cbytes src, int srclen, size_t total) {
    memcpy(dst, src, srclen);
    dst[srclen++] = '\x80';
    int lenpos = (srclen <= 56) ? 56 : 120;
    int64_bytes(dst + lenpos, (uint64)total << 3);
    return lenpos + 8;
}

static void sm3_update(uint32 *state, cbytes src, size_t srclen, const uint32 *iv) {
    if (iv == NULL)
        iv = IV;
    for (size_t i = 0; i < srclen; i += 64) {
        iv = cf(state, iv, src + i);
    }
}

static void sm3_finish(bytes hash, cbytes src, size_t srclen, size_t total, const uint32 *iv) {
    uint32 state[8];
    size_t len64 = srclen & (SIZE_MAX - 63);
    for (size_t i = 0; i < len64; i += 64) {
        iv = cf(state, iv, src + i);
    }
    byte buff[128] = {0};
    int lastlen = padding(buff, src + len64, (int)(srclen - len64), total);
    for (int i = 0; i < lastlen; i += 64) {
        iv = cf(state, iv, buff + i);
    }
    int32_bytes(hash, state[0]);
    int32_bytes(hash + 4, state[1]);
    int32_bytes(hash + 8, state[2]);
    int32_bytes(hash + 12, state[3]);
    int32_bytes(hash + 16, state[4]);
    int32_bytes(hash + 20, state[5]);
    int32_bytes(hash + 24, state[6]);
    int32_bytes(hash + 28, state[7]);
}

bytes sm3_hash(bytes hash, cbytes src, size_t srclen) {
    sm3_finish(hash, src, srclen, srclen, IV);
    return hash;
}

#define BLOCK_SIZE 64
#define DIGEST_SIZE 32
static void xorpad(word *out, const word *src, const word pad) {
    for (int i = 0; i < BLOCK_SIZE / WORD_SIZE; i += 4) {
        out[i] = src[i] ^ pad;
        out[i + 1] = src[i + 1] ^ pad;
        out[i + 2] = src[i + 2] ^ pad;
        out[i + 3] = src[i + 3] ^ pad;
    }
}

bytes sm3_hmac(bytes hmac, cbytes key, size_t keylen, cbytes src, size_t srclen) {
    byte keyblk[BLOCK_SIZE] = {0};
    if (keylen > BLOCK_SIZE) {
        sm3_hash(keyblk, src, srclen);
    } else {
        memcpy(keyblk, key, keylen);
    }

    byte inner[BLOCK_SIZE];
    byte outer[BLOCK_SIZE + DIGEST_SIZE];
    xorpad((word *)inner, (word *)keyblk, IPAD);
    xorpad((word *)outer, (word *)keyblk, OPAD);

    uint32 state[8];
    sm3_update(state, inner, BLOCK_SIZE, NULL);
    sm3_finish(outer + BLOCK_SIZE, src, srclen, BLOCK_SIZE + srclen, state);
    sm3_hash(hmac, outer, BLOCK_SIZE + DIGEST_SIZE);
    return hmac;
}
