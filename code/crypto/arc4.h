#ifndef __CRYPTO_ARC4_H_
#define __CRYPTO_ARC4_H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          ARC4 context structure
 */
typedef struct
{
    int x;                      /*!< permutation index */
    int y;                      /*!< permutation index */
    uint8_t m[256];       /*!< permutation table */
} arc4_context_t;


void arc4_setup(arc4_context_t* ctx, const uint8_t *key, uint32_t keylen);
int arc4_crypt(arc4_context_t* ctx, size_t length, const uint8_t* input, uint8_t* output);
void arc4_crypt_self(uint8_t* buffer, uint32_t length, const uint8_t* key, uint32_t keylen);

#ifdef __cplusplus
}
#endif


#endif // __CRYPTO_ARC4_H_
