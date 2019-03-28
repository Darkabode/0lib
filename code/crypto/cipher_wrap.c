#include "..\zmodule.h"
#include "config.h"
#include "cipher_wrap.h"
#include "aes.h"


static int aes_crypt_ecb_wrap( void *ctx, operation_t operation,
        const uint8_t *input, uint8_t *output )
{
    return aes_crypt_ecb( (aes_context_t *) ctx, operation, input, output );
}

static int aes_crypt_cbc_wrap( void *ctx, operation_t operation, size_t length,
        uint8_t *iv, const uint8_t *input, uint8_t *output )
{
    return aes_crypt_cbc( (aes_context_t *) ctx, operation, length, iv, input, output );
}

static int aes_setkey_dec_wrap( void *ctx, const uint8_t *key)
{
    return aes_setkey_dec( (aes_context_t *) ctx, key);
}

static int aes_setkey_enc_wrap( void *ctx, const uint8_t *key)
{
    return aes_setkey_enc( (aes_context_t *) ctx, key);
}

static void * aes_ctx_alloc( void )
{
    return memory_alloc( sizeof( aes_context_t ) );
}

static void aes_ctx_free( void *ctx )
{
    memory_free( ctx );
}

const cipher_base_t aes_info = {
    POLARSSL_CIPHER_ID_AES,
    aes_crypt_ecb_wrap,
    aes_crypt_cbc_wrap,
    aes_setkey_enc_wrap,
    aes_setkey_dec_wrap,
    aes_ctx_alloc,
    aes_ctx_free
};
const cipher_info_t aes_256_ecb_info = {
    POLARSSL_CIPHER_AES_256_ECB,
    POLARSSL_MODE_ECB,
    256,
    "AES-256-ECB",
    16,
    16,
    &aes_info
};
const cipher_info_t aes_256_cbc_info = {
    POLARSSL_CIPHER_AES_256_CBC,
    POLARSSL_MODE_CBC,
    256,
    "AES-256-CBC",
    16,
    16,
    &aes_info
};

const cipher_definition_t cipher_definitions[] =
{
    { POLARSSL_CIPHER_AES_256_ECB,          &aes_256_ecb_info },
    { POLARSSL_CIPHER_AES_256_CBC,          &aes_256_cbc_info },
    { 0, NULL }
};

#define NUM_CIPHERS sizeof cipher_definitions / sizeof cipher_definitions[0]
int supported_ciphers[NUM_CIPHERS];
