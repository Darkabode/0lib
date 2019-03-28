#include "..\zmodule.h"
#include "config.h"

#include <stdlib.h>

#if defined(POLARSSL_PK_C)

#include "pk_wrap.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "rsa.h"
#include "ecp.h"

/* Used by RSA-alt too */
static int rsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_RSA );
}

static size_t rsa_get_size( const void *ctx )
{
    return( 8 * ((const rsa_context_t *) ctx)->len );
}

static int rsa_verify_wrap( void *ctx, md_type_t md_alg,
                   const uint8_t *hash, size_t hash_len,
                   const uint8_t *sig, size_t sig_len )
{
    int ret;

    if( sig_len < ((rsa_context_t *) ctx)->len )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    if( ( ret = rsa_pkcs1_verify( (rsa_context_t *) ctx, NULL, NULL,
                                  RSA_PUBLIC, md_alg,
                                  (uint32_t) hash_len, hash, sig ) ) != 0 )
        return( ret );

    if( sig_len > ((rsa_context_t *) ctx)->len )
        return( POLARSSL_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int rsa_sign_wrap( void *ctx, md_type_t md_alg,
                   const uint8_t *hash, size_t hash_len,
                   uint8_t *sig, size_t *sig_len,
                   int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    *sig_len = ((rsa_context_t *) ctx)->len;

    return( rsa_pkcs1_sign( (rsa_context_t *) ctx, f_rng, p_rng, RSA_PRIVATE,
                md_alg, (uint32_t) hash_len, hash, sig ) );
}

static int rsa_decrypt_wrap( void *ctx,
                    const uint8_t *input, size_t ilen,
                    uint8_t *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    if( ilen != ((rsa_context_t *) ctx)->len )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    return( rsa_pkcs1_decrypt( (rsa_context_t *) ctx, f_rng, p_rng,
                RSA_PRIVATE, olen, input, output, osize ) );
}

static int rsa_encrypt_wrap( void *ctx,
                    const uint8_t *input, size_t ilen,
                    uint8_t *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    ((void) osize);

    *olen = ((rsa_context_t *) ctx)->len;

    return( rsa_pkcs1_encrypt( (rsa_context_t *) ctx,
                f_rng, p_rng, RSA_PUBLIC, ilen, input, output ) );
}

static void *rsa_alloc_wrap( void )
{
    void *ctx = memory_alloc( sizeof( rsa_context_t ) );

    if( ctx != NULL )
        rsa_init( (rsa_context_t *) ctx, 0 );

    return ctx;
}

static void rsa_free_wrap( void *ctx )
{
    rsa_free( (rsa_context_t *) ctx );
    memory_free( ctx );
}

static void rsa_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((rsa_context_t *) ctx)->N );

    items++;

    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((rsa_context_t *) ctx)->E );
}

const pk_info_t rsa_info = {
    POLARSSL_PK_RSA,
    "RSA",
    rsa_get_size,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_sign_wrap,
    rsa_decrypt_wrap,
    rsa_encrypt_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
    rsa_debug,
};

/*
 * Generic EC key
 */
static int eckey_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH);
}

static size_t eckey_get_size( const void *ctx )
{
    return( ((ecp_keypair *) ctx)->grp.pbits );
}

static void *eckey_alloc_wrap( void )
{
    void *ctx = memory_alloc( sizeof( ecp_keypair ) );

    if( ctx != NULL )
        ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    ecp_keypair_free( (ecp_keypair *) ctx );
    memory_free( ctx );
}

static void eckey_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((ecp_keypair *) ctx)->Q );
}

const pk_info_t eckey_info = {
    POLARSSL_PK_ECKEY,
    "EC",
    eckey_get_size,
    eckey_can_do,
    NULL,
    NULL,
    NULL,
    NULL,
    eckey_alloc_wrap,
    eckey_free_wrap,
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH );
}

const pk_info_t eckeydh_info = {
    POLARSSL_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_size,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
    NULL,
    NULL,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
    eckey_debug,            /* Same underlying key structure */
};

/*
 * Support for alternative RSA-private implementations
 */

static size_t rsa_alt_get_size( const void *ctx )
{
    const rsa_alt_context *rsa_alt = (const rsa_alt_context *) ctx;

    return( 8 * rsa_alt->key_len_func( rsa_alt->key ) );
}

static int rsa_alt_sign_wrap( void *ctx, md_type_t md_alg,
                   const uint8_t *hash, size_t hash_len,
                   uint8_t *sig, size_t *sig_len,
                   int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    rsa_alt_context *rsa_alt = (rsa_alt_context *) ctx;

    *sig_len = rsa_alt->key_len_func( rsa_alt->key );

    return( rsa_alt->sign_func( rsa_alt->key, f_rng, p_rng, RSA_PRIVATE,
                md_alg, (uint32_t) hash_len, hash, sig ) );
}

static int rsa_alt_decrypt_wrap( void *ctx,
                    const uint8_t *input, size_t ilen,
                    uint8_t *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    rsa_alt_context *rsa_alt = (rsa_alt_context *) ctx;

    ((void) f_rng);
    ((void) p_rng);

    if( ilen != rsa_alt->key_len_func( rsa_alt->key ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    return( rsa_alt->decrypt_func( rsa_alt->key,
                RSA_PRIVATE, olen, input, output, osize ) );
}

static void *rsa_alt_alloc_wrap( void )
{
    void *ctx = memory_alloc( sizeof( rsa_alt_context ) );

    if( ctx != NULL )
        __stosb( ctx, 0, sizeof( rsa_alt_context ) );

    return ctx;
}

static void rsa_alt_free_wrap( void *ctx )
{
    memory_free( ctx );
}

const pk_info_t rsa_alt_info = {
    POLARSSL_PK_RSA_ALT,
    "RSA-alt",
    rsa_alt_get_size,
    rsa_can_do,
    NULL,
    rsa_alt_sign_wrap,
    rsa_alt_decrypt_wrap,
    NULL,
    rsa_alt_alloc_wrap,
    rsa_alt_free_wrap,
    NULL,
};

#endif /* POLARSSL_PK_C */
