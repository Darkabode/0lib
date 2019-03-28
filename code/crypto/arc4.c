#include "..\zmodule.h"
#include "arc4.h"


void arc4_setup(arc4_context_t* ctx, const uint8_t *key, uint32_t keylen)
{
    int i, j, a;
    uint32_t k;
    uint8_t *m;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for (i = 0; i < 256; ++i) {
        m[i] = (uint8_t)i;
    }

    j = k = 0;

    for (i = 0; i < 256; ++i, ++k) {
        if (k >= keylen) {
            k = 0;
        }

        a = m[i];
        j = ( j + a + key[k] ) & 0xFF;
        m[i] = m[j];
        m[j] = (uint8_t)a;
    }
}

int arc4_crypt(arc4_context_t* ctx, size_t length, const uint8_t* input, uint8_t* output)
{
    int x, y, a, b;
    size_t i;
    uint8_t *m;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for (i = 0; i < length; ++i) {
        x = ( x + 1 ) & 0xFF;
        a = m[x];
        y = ( y + a ) & 0xFF;
        b = m[y];

        m[x] = (uint8_t) b;
        m[y] = (uint8_t) a;

        output[i] = (uint8_t)(input[i] ^ m[(uint8_t)( a + b )]);
    }

    ctx->x = x;
    ctx->y = y;

    return 0;
}

void arc4_crypt_self(uint8_t* buffer, uint32_t length, const uint8_t* key, uint32_t keylen)
{
    int a, b;
    uint32_t i, j = 0, k = 0;
    uint8_t m[256];

    for (i = 0; i < 256; ++i) {
        m[i] = (uint8_t)i;
    }

    for (i = 0; i < 256; ++i, ++k) {
        if (k >= keylen) {
            k = 0;
        }

        a = m[i];
        j = (j + a + key[k]) & 0xFF;
        m[i] = m[j];
        m[j] = (uint8_t)a;
    }

    j = k = 0;

    for (i = 0; i < length; ++i) {
        j = (j + 1) & 0xFF;
        a = m[j];
        k = (k + a) & 0xFF;
        b = m[k];

        m[j] = (uint8_t)b;
        m[k] = (uint8_t)a;

        buffer[i] = (uint8_t)(buffer[i] ^ m[(uint8_t)(a + b)]);
    }
}