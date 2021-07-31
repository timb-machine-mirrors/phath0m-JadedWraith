#ifndef _SHA256_H
#define _SHA256_H

#include <stdint.h>

#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8
#define SHA256_DIGEST_LENGTH 32

void calc_sha_256(uint8_t[32], const void *, size_t);

#endif