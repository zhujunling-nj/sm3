#ifndef __SM3_H__
#define __SM3_H__
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN64
#define WORD_SIZE 8
typedef uint64_t word;
#elif __SIZEOF_POINTER__ == 8
#define WORD_SIZE 8
typedef uint64_t word;
#else
#define WORD_SIZE 4
typedef uint32_t word;
#endif

typedef uint32_t uint32;
typedef uint64_t uint64;
typedef unsigned char byte;
typedef const byte *cbytes;
typedef byte *bytes;

bytes sm3_hash(bytes hash, cbytes src, size_t srclen);
bytes sm3_hmac(bytes hmac, cbytes key, size_t keylen, cbytes src, size_t srclen);

#ifdef __cplusplus
}
#endif
#endif
