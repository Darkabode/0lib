#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_PEM_PARSE_C) || defined(POLARSSL_PEM_WRITE_C)
#include "pem.h"
#include "base64.h"
#include "aes.h"
#include "cipher.h"

#include <stdlib.h>

#if defined(POLARSSL_PEM_PARSE_C)
void pem_init( pem_context *ctx )
{
    __stosb( ctx, 0, sizeof( pem_context ) );
}

int pem_read_buffer( pem_context *ctx, const char *header, const char *footer,
                     const uint8_t *data, const uint8_t *pwd,
                     size_t pwdlen, size_t *use_len )
{
    int ret, enc;
    size_t len;
    uint8_t *buf;
    const uint8_t *s1, *s2, *end;
    ((void) pwd);
    ((void) pwdlen);

    if( ctx == NULL )
        return( POLARSSL_ERR_PEM_BAD_INPUT_DATA );

    s1 = (uint8_t *) strstr( (const char *) data, header );

    if( s1 == NULL )
        return( POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s2 = (uint8_t *) strstr( (const char *) data, footer );

    if( s2 == NULL || s2 <= s1 )
        return( POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s1 += strlen( header );
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;
    else return( POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    end = s2;
    end += strlen( footer );
    if( *end == '\r' ) end++;
    if( *end == '\n' ) end++;
    *use_len = end - data;

    enc = 0;

    if( memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
    {
        return( POLARSSL_ERR_PEM_FEATURE_UNAVAILABLE );
    }

    len = 0;
    ret = base64_decode( NULL, &len, s1, s2 - s1 );

    if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
        return( POLARSSL_ERR_PEM_INVALID_DATA + ret );

    if( ( buf = (uint8_t *) memory_alloc( len ) ) == NULL )
        return( POLARSSL_ERR_PEM_MALLOC_FAILED );

    if( ( ret = base64_decode( buf, &len, s1, s2 - s1 ) ) != 0 )
    {
        memory_free( buf );
        return( POLARSSL_ERR_PEM_INVALID_DATA + ret );
    }

    if( enc != 0 )
    {
        memory_free( buf );
        return( POLARSSL_ERR_PEM_FEATURE_UNAVAILABLE );
    }

    ctx->buf = buf;
    ctx->buflen = len;

    return( 0 );
}

void pem_free( pem_context *ctx )
{
    if( ctx->buf )
        memory_free( ctx->buf );

    if( ctx->info )
        memory_free( ctx->info );

    __stosb( ctx, 0, sizeof( pem_context ) );
}
#endif /* POLARSSL_PEM_PARSE_C */

#if defined(POLARSSL_PEM_WRITE_C)
int pem_write_buffer( const char *header, const char *footer,
                      const uint8_t *der_data, size_t der_len,
                      uint8_t *buf, size_t buf_len, size_t *olen )
{
    int ret;
    uint8_t *encode_buf, *c, *p = buf;
    size_t len = 0, use_len = 0, add_len = 0;

    base64_encode( NULL, &use_len, der_data, der_len );
    add_len = strlen( header ) + strlen( footer ) + ( use_len / 64 ) + 1;

    if( use_len + add_len > buf_len )
    {
        *olen = use_len + add_len;
        return( POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    if( ( encode_buf = memory_alloc( use_len ) ) == NULL )
        return( POLARSSL_ERR_PEM_MALLOC_FAILED );

    if( ( ret = base64_encode( encode_buf, &use_len, der_data,
                               der_len ) ) != 0 )
    {
        memory_free( encode_buf );
        return( ret );
    }

    __movsb( p, header, strlen( header ) );
    p += strlen( header );
    c = encode_buf;

    while( use_len )
    {
        len = ( use_len > 64 ) ? 64 : use_len;
        __movsb( p, c, len );
        use_len -= len;
        p += len;
        c += len;
        *p++ = '\n';
    }

    __movsb( p, footer, strlen( footer ) );
    p += strlen( footer );

    *p++ = '\0';
    *olen = p - buf;

    memory_free( encode_buf );
    return( 0 );
}
#endif /* POLARSSL_PEM_WRITE_C */
#endif /* POLARSSL_PEM_PARSE_C || POLARSSL_PEM_WRITE_C */
