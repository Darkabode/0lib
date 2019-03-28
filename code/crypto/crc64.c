#include "..\zmodule.h"
#include "crc64.h"

#define POLY 0xc96c5795d7870f42ULL

uint64_t crc64_little_table[8][256] = { 0 };

int _tableInited = 0;

void __stdcall crc64_init()
{
    unsigned n, k;
    uint64_t crc;

    /* generate CRC-64's for all single byte sequences */
    for (n = 0; n < 256; ++n) {
        crc = n;
        for (k = 0; k < 8; ++k) {
            crc = crc & 1 ? POLY ^ (crc >> 1) : crc >> 1;
        }
        crc64_little_table[0][n] = crc;
    }

    /* generate CRC-64's for those followed by 1 to 7 zeros */
    for (n = 0; n < 256; ++n) {
        crc = crc64_little_table[0][n];
        for (k = 1; k < 8; ++k) {
            crc = crc64_little_table[0][crc & 0xff] ^ (crc >> 8);
            crc64_little_table[k][n] = crc;
        }
    }
}

uint64_t __stdcall crc64(uint64_t crc, void* buf, size_t len)
{
    unsigned char *next = buf;

    if (!_tableInited) {
        _tableInited = 1;
        crc64_init();
    }

    crc = ~crc;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc64_little_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    while (len >= 8) {
        crc ^= *(uint64_t *)next;
        crc = crc64_little_table[7][crc & 0xff] ^
            crc64_little_table[6][(crc >> 8) & 0xff] ^
            crc64_little_table[5][(crc >> 16) & 0xff] ^
            crc64_little_table[4][(crc >> 24) & 0xff] ^
            crc64_little_table[3][(crc >> 32) & 0xff] ^
            crc64_little_table[2][(crc >> 40) & 0xff] ^
            crc64_little_table[1][(crc >> 48) & 0xff] ^
            crc64_little_table[0][crc >> 56];
        next += 8;
        len -= 8;
    }
    while (len) {
        crc = crc64_little_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        --len;
    }
    return ~crc;
}