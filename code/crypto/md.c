#include "..\zmodule.h"
#include "config.h"
#include "md.h"
#include "md_wrap.h"

#include <stdlib.h>

static const int supported_digests[] = {

#if defined(POLARSSL_SHA256_C)
        POLARSSL_MD_SHA224,
        POLARSSL_MD_SHA256,
#endif

#if defined(POLARSSL_SHA512_C)
        POLARSSL_MD_SHA384,
        POLARSSL_MD_SHA512,
#endif

        0
};

const int *md_list( void )
{
    return supported_digests;
}

const md_info_t *md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return NULL;

    /* Get the appropriate digest information */
#if defined(POLARSSL_SHA256_C)
    if( !_stricmp( "SHA224", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA224 );
    if( !_stricmp( "SHA256", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA256 );
#endif
#if defined(POLARSSL_SHA512_C)
    if( !_stricmp( "SHA384", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA384 );
    if( !_stricmp( "SHA512", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA512 );
#endif
    return NULL;
}

const md_info_t* md_info_from_type(md_type_t md_type)
{
    switch( md_type )
    {
#if defined(POLARSSL_SHA256_C)
        case POLARSSL_MD_SHA224:
            return &sha224_info;
        case POLARSSL_MD_SHA256:
            return &sha256_info;
#endif
#if defined(POLARSSL_SHA512_C)
        case POLARSSL_MD_SHA384:
            return &sha384_info;
        case POLARSSL_MD_SHA512:
            return &sha512_info;
#endif
        default:
            return NULL;
    }
}

int md_init_ctx( md_context_t *ctx, const md_info_t *md_info )
{
    if( md_info == NULL || ctx == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    __stosb( ctx, 0, sizeof( md_context_t ) );

    if( ( ctx->md_ctx = md_info->ctx_alloc_func() ) == NULL )
        return POLARSSL_ERR_MD_ALLOC_FAILED;

    ctx->md_info = md_info;

    md_info->starts_func( ctx->md_ctx );

    return 0;
}

int md_free_ctx( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->ctx_free_func( ctx->md_ctx );
    ctx->md_ctx = NULL;

    return 0;
}

int md_starts( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->starts_func( ctx->md_ctx );

    return 0;
}

int md_update( md_context_t *ctx, const uint8_t *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return 0;
}

int md_finish( md_context_t *ctx, uint8_t *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->finish_func( ctx->md_ctx, output );

    return 0;
}

int md( const md_info_t *md_info, const uint8_t *input, size_t ilen,
            uint8_t *output )
{
    if ( md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    md_info->digest_func( input, ilen, output );

    return 0;
}
/*
int md_file( const md_info_t *md_info, const char *path, uint8_t *output )
{
    int ret;

    if( md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ret = md_info->file_func( path, output );
    if( ret != 0 )
        return( POLARSSL_ERR_MD_FILE_IO_ERROR + ret );

    return( ret );
}
*/
int md_hmac_starts( md_context_t *ctx, const uint8_t *key, size_t keylen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->hmac_starts_func( ctx->md_ctx, key, keylen);

    return 0;
}

int md_hmac_update( md_context_t *ctx, const uint8_t *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->hmac_update_func( ctx->md_ctx, input, ilen );

    return 0;
}

int md_hmac_finish( md_context_t *ctx, uint8_t *output)
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->hmac_finish_func( ctx->md_ctx, output);

    return 0;
}

int md_hmac_reset( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->hmac_reset_func( ctx->md_ctx);

    return 0;
}

int md_hmac( const md_info_t *md_info, const uint8_t *key, size_t keylen,
                const uint8_t *input, size_t ilen,
                uint8_t *output )
{
    if( md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    md_info->hmac_func( key, keylen, input, ilen, output );

    return 0;
}

int md_process( md_context_t *ctx, const uint8_t *data )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

    ctx->md_info->process_func( ctx->md_ctx, data );

    return 0;
}
