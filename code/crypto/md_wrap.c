#include "..\zmodule.h"
#include "config.h"
#include "md_wrap.h"
#include "sha256.h"
#include "sha512.h"

#include <stdlib.h>

/*
 * Wrappers for generic message digests
 */
#if defined(POLARSSL_SHA256_C)

void sha224_starts_wrap( void *ctx )
{
    sha256_starts( (sha256_context *) ctx, 1 );
}

void sha224_update_wrap( void *ctx, const uint8_t *input,
                                size_t ilen )
{
    sha256_update( (sha256_context *) ctx, input, ilen );
}

void sha224_finish_wrap( void *ctx, uint8_t *output )
{
    sha256_finish( (sha256_context *) ctx, output );
}

void sha224_wrap( const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha256( input, ilen, output, 1 );
}

void sha224_hmac_starts_wrap( void *ctx, const uint8_t *key, size_t keylen )
{
    sha256_hmac_starts( (sha256_context *) ctx, key, keylen, 1 );
}

void sha224_hmac_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha256_hmac_update( (sha256_context *) ctx, input, ilen );
}

void sha224_hmac_finish_wrap( void *ctx, uint8_t *output )
{
    sha256_hmac_finish( (sha256_context *) ctx, output );
}

void sha224_hmac_reset_wrap( void *ctx )
{
    sha256_hmac_reset( (sha256_context *) ctx );
}

void sha224_hmac_wrap( const uint8_t *key, size_t keylen, const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha256_hmac( key, keylen, input, ilen, output, 1 );
}

void * sha224_ctx_alloc( void )
{
    return memory_alloc( sizeof( sha256_context ) );
}

void sha224_ctx_free( void *ctx )
{
    memory_free( ctx );
}

void sha224_process_wrap( void *ctx, const uint8_t *data )
{
    sha256_process( (sha256_context *) ctx, data );
}

const md_info_t sha224_info = {
    POLARSSL_MD_SHA224,
    "SHA224",
    28,
    sha224_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha224_wrap,
    sha224_hmac_starts_wrap,
    sha224_hmac_update_wrap,
    sha224_hmac_finish_wrap,
    sha224_hmac_reset_wrap,
    sha224_hmac_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_process_wrap,
};

void sha256_starts_wrap( void *ctx )
{
    sha256_starts( (sha256_context *) ctx, 0 );
}

void sha256_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha256_update( (sha256_context *) ctx, input, ilen );
}

void sha256_finish_wrap( void *ctx, uint8_t *output )
{
    sha256_finish( (sha256_context *) ctx, output );
}

void sha256_wrap( const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha256( input, ilen, output, 0 );
}

void sha256_hmac_starts_wrap( void *ctx, const uint8_t *key, size_t keylen )
{
    sha256_hmac_starts( (sha256_context *) ctx, key, keylen, 0 );
}

void sha256_hmac_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha256_hmac_update( (sha256_context *) ctx, input, ilen );
}

void sha256_hmac_finish_wrap( void *ctx, uint8_t *output )
{
    sha256_hmac_finish( (sha256_context *) ctx, output );
}

void sha256_hmac_reset_wrap( void *ctx )
{
    sha256_hmac_reset( (sha256_context *) ctx );
}

void sha256_hmac_wrap( const uint8_t *key, size_t keylen, const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha256_hmac( key, keylen, input, ilen, output, 0 );
}

void * sha256_ctx_alloc( void )
{
    return memory_alloc( sizeof( sha256_context ) );
}

void sha256_ctx_free( void *ctx )
{
    memory_free( ctx );
}

void sha256_process_wrap( void *ctx, const uint8_t *data )
{
    sha256_process( (sha256_context *) ctx, data );
}

const md_info_t sha256_info = {
    POLARSSL_MD_SHA256,
    "SHA256",
    32,
    sha256_starts_wrap,
    sha256_update_wrap,
    sha256_finish_wrap,
    sha256_wrap,
    sha256_hmac_starts_wrap,
    sha256_hmac_update_wrap,
    sha256_hmac_finish_wrap,
    sha256_hmac_reset_wrap,
    sha256_hmac_wrap,
    sha256_ctx_alloc,
    sha256_ctx_free,
    sha256_process_wrap,
};

#endif /* POLARSSL_SHA256_C */

#if defined(POLARSSL_SHA512_C)

void sha384_starts_wrap( void *ctx )
{
    sha512_starts( (sha512_context *) ctx, 1 );
}

void sha384_update_wrap( void *ctx, const uint8_t *input,
                                size_t ilen )
{
    sha512_update( (sha512_context *) ctx, input, ilen );
}

void sha384_finish_wrap( void *ctx, uint8_t *output )
{
    sha512_finish( (sha512_context *) ctx, output );
}

void sha384_wrap( const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha512( input, ilen, output, 1 );
}

void sha384_hmac_starts_wrap( void *ctx, const uint8_t *key, size_t keylen )
{
    sha512_hmac_starts( (sha512_context *) ctx, key, keylen, 1 );
}

void sha384_hmac_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha512_hmac_update( (sha512_context *) ctx, input, ilen );
}

void sha384_hmac_finish_wrap( void *ctx, uint8_t *output )
{
    sha512_hmac_finish( (sha512_context *) ctx, output );
}

void sha384_hmac_reset_wrap( void *ctx )
{
    sha512_hmac_reset( (sha512_context *) ctx );
}

void sha384_hmac_wrap( const uint8_t *key, size_t keylen,
        const uint8_t *input, size_t ilen,
        uint8_t *output )
{
    sha512_hmac( key, keylen, input, ilen, output, 1 );
}

void * sha384_ctx_alloc( void )
{
    return memory_alloc( sizeof( sha512_context ) );
}

void sha384_ctx_free( void *ctx )
{
    memory_free( ctx );
}

void sha384_process_wrap( void *ctx, const uint8_t *data )
{
    sha512_process( (sha512_context *) ctx, data );
}

const md_info_t sha384_info = {
    POLARSSL_MD_SHA384,
    "SHA384",
    48,
    sha384_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha384_wrap,
    sha384_hmac_starts_wrap,
    sha384_hmac_update_wrap,
    sha384_hmac_finish_wrap,
    sha384_hmac_reset_wrap,
    sha384_hmac_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_process_wrap,
};

void sha512_starts_wrap( void *ctx )
{
    sha512_starts( (sha512_context *) ctx, 0 );
}

void sha512_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha512_update( (sha512_context *) ctx, input, ilen );
}

void sha512_finish_wrap( void *ctx, uint8_t *output )
{
    sha512_finish( (sha512_context *) ctx, output );
}

void sha512_wrap( const uint8_t *input, size_t ilen, uint8_t *output )
{
    sha512( input, ilen, output, 0 );
}

void sha512_hmac_starts_wrap( void *ctx, const uint8_t *key, size_t keylen )
{
    sha512_hmac_starts( (sha512_context *) ctx, key, keylen, 0 );
}

void sha512_hmac_update_wrap( void *ctx, const uint8_t *input, size_t ilen )
{
    sha512_hmac_update( (sha512_context *) ctx, input, ilen );
}

void sha512_hmac_finish_wrap( void *ctx, uint8_t *output )
{
    sha512_hmac_finish( (sha512_context *) ctx, output );
}

void sha512_hmac_reset_wrap( void *ctx )
{
    sha512_hmac_reset( (sha512_context *) ctx );
}

void sha512_hmac_wrap( const uint8_t *key, size_t keylen,
        const uint8_t *input, size_t ilen,
        uint8_t *output )
{
    sha512_hmac( key, keylen, input, ilen, output, 0 );
}

void * sha512_ctx_alloc( void )
{
    return memory_alloc( sizeof( sha512_context ) );
}

void sha512_ctx_free( void *ctx )
{
    memory_free( ctx );
}

void sha512_process_wrap( void *ctx, const uint8_t *data )
{
    sha512_process( (sha512_context *) ctx, data );
}

const md_info_t sha512_info = {
    POLARSSL_MD_SHA512,
    "SHA512",
    64,
    sha512_starts_wrap,
    sha512_update_wrap,
    sha512_finish_wrap,
    sha512_wrap,
    sha512_hmac_starts_wrap,
    sha512_hmac_update_wrap,
    sha512_hmac_finish_wrap,
    sha512_hmac_reset_wrap,
    sha512_hmac_wrap,
    sha512_ctx_alloc,
    sha512_ctx_free,
    sha512_process_wrap,
};

#endif /* POLARSSL_SHA512_C */
