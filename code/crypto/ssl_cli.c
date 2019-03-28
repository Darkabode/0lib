#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_SSL_CLI_C)

#include "ssl.h"

#include <stdlib.h>

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
static void ssl_write_hostname_ext( ssl_context *ssl,
                                    uint8_t *buf,
                                    size_t *olen )
{
    uint8_t *p = buf;

    *olen = 0;

    if ( ssl->hostname == NULL )
        return;

    /*
     * struct {
     *     NameType name_type;
     *     select (name_type) {
     *         case host_name: HostName;
     *     } name;
     * } ServerName;
     *
     * enum {
     *     host_name(0), (255)
     * } NameType;
     *
     * opaque HostName<1..2^16-1>;
     *
     * struct {
     *     ServerName server_name_list<1..2^16-1>
     * } ServerNameList;
     */
    *p++ = (uint8_t)( ( TLS_EXT_SERVERNAME >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_SERVERNAME      ) & 0xFF );

    *p++ = (uint8_t)( ( (ssl->hostname_len + 5) >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( (ssl->hostname_len + 5)      ) & 0xFF );

    *p++ = (uint8_t)( ( (ssl->hostname_len + 3) >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( (ssl->hostname_len + 3)      ) & 0xFF );

    *p++ = (uint8_t)( ( TLS_EXT_SERVERNAME_HOSTNAME ) & 0xFF );
    *p++ = (uint8_t)( ( ssl->hostname_len >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( ssl->hostname_len      ) & 0xFF );

    __movsb( p, ssl->hostname, ssl->hostname_len );

    *olen = ssl->hostname_len + 9;
}
#endif /* POLARSSL_SSL_SERVER_NAME_INDICATION */

static void ssl_write_renegotiation_ext( ssl_context *ssl,
                                         uint8_t *buf,
                                         size_t *olen )
{
    uint8_t *p = buf;

    *olen = 0;

    if( ssl->renegotiation != SSL_RENEGOTIATION )
        return;

    /*
     * Secure renegotiation
     */
    *p++ = (uint8_t)( ( TLS_EXT_RENEGOTIATION_INFO >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_RENEGOTIATION_INFO      ) & 0xFF );

    *p++ = 0x00;
    *p++ = ( ssl->verify_data_len + 1 ) & 0xFF;
    *p++ = ssl->verify_data_len & 0xFF;

    __movsb( p, ssl->own_verify_data, ssl->verify_data_len );

    *olen = 5 + ssl->verify_data_len;
}

static void ssl_write_signature_algorithms_ext( ssl_context *ssl,
                                                uint8_t *buf,
                                                size_t *olen )
{
    uint8_t *p = buf;
    uint8_t *sig_alg_list = buf + 6;
    size_t sig_alg_len = 0;

    *olen = 0;

    if( ssl->max_minor_ver != SSL_MINOR_VERSION_3 )
        return;

    /*
     * Prepare signature_algorithms extension (TLS 1.2)
     */
#if defined(POLARSSL_SHA512_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA512;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA384;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif
#if defined(POLARSSL_SHA256_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA256;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA224;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif

    /*
     * enum {
     *     none(0), sha1(2), sha224(3), sha256(4), sha384(5),
     *     sha512(6), (255)
     * } HashAlgorithm;
     *
     * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
     *   SignatureAlgorithm;
     *
     * struct {
     *     HashAlgorithm hash;
     *     SignatureAlgorithm signature;
     * } SignatureAndHashAlgorithm;
     *
     * SignatureAndHashAlgorithm
     *   supported_signature_algorithms<2..2^16-2>;
     */
    *p++ = (uint8_t)( ( TLS_EXT_SIG_ALG >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_SIG_ALG      ) & 0xFF );

    *p++ = (uint8_t)( ( ( sig_alg_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( ( sig_alg_len + 2 )      ) & 0xFF );

    *p++ = (uint8_t)( ( sig_alg_len >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( sig_alg_len      ) & 0xFF );

    *olen = 6 + sig_alg_len;
}

static void ssl_write_supported_elliptic_curves_ext( ssl_context *ssl,
                                                     uint8_t *buf,
                                                     size_t *olen )
{
    uint8_t *p = buf;
    uint8_t *elliptic_curve_list = p + 6;
    size_t elliptic_curve_len = 0;
    const ecp_curve_info *info;
    const ecp_group_id *grp_id;

    *olen = 0;

    for( grp_id = ssl->curve_list; *grp_id != POLARSSL_ECP_DP_NONE; grp_id++ )
    {
        info = ecp_curve_info_from_grp_id( *grp_id );
        elliptic_curve_list[elliptic_curve_len++] = info->tls_id >> 8;
        elliptic_curve_list[elliptic_curve_len++] = info->tls_id & 0xFF;
    }

    if( elliptic_curve_len == 0 )
        return;

    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_ELLIPTIC_CURVES >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_ELLIPTIC_CURVES      ) & 0xFF );

    *p++ = (uint8_t)( ( ( elliptic_curve_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( ( elliptic_curve_len + 2 )      ) & 0xFF );

    *p++ = (uint8_t)( ( ( elliptic_curve_len     ) >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( ( elliptic_curve_len     )      ) & 0xFF );

    *olen = 6 + elliptic_curve_len;
}

static void ssl_write_supported_point_formats_ext( ssl_context *ssl,
                                                   uint8_t *buf,
                                                   size_t *olen )
{
    uint8_t *p = buf;
    ((void) ssl);

    *olen = 0;

    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_POINT_FORMATS >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_POINT_FORMATS      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 2;

    *p++ = 1;
    *p++ = POLARSSL_ECP_PF_UNCOMPRESSED;

    *olen = 6;
}

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext( ssl_context *ssl,
                                               uint8_t *buf,
                                               size_t *olen )
{
    uint8_t *p = buf;

    if( ssl->mfl_code == SSL_MAX_FRAG_LEN_NONE ) {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_MAX_FRAGMENT_LENGTH >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_MAX_FRAGMENT_LENGTH      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 1;

    *p++ = ssl->mfl_code;

    *olen = 5;
}
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
static void ssl_write_truncated_hmac_ext( ssl_context *ssl,
                                          uint8_t *buf, size_t *olen )
{
    uint8_t *p = buf;

    if( ssl->trunc_hmac == SSL_TRUNC_HMAC_DISABLED )
    {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_TRUNCATED_HMAC >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_TRUNCATED_HMAC      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 0x00;

    *olen = 4;
}
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

#if defined(POLARSSL_SSL_ALPN)
static void ssl_write_alpn_ext( ssl_context *ssl,
                                uint8_t *buf, size_t *olen )
{
    uint8_t *p = buf;
    const char **cur;

    if( ssl->alpn_list == NULL )
    {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_ALPN >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_ALPN      ) & 0xFF );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */

    /* Skip writing extension and list length for now */
    p += 4;

    for( cur = ssl->alpn_list; *cur != NULL; cur++ )
    {
        *p = (uint8_t)( strlen( *cur ) & 0xFF );
        __movsb( p + 1, *cur, *p );
        p += 1 + *p;
    }

    *olen = p - buf;

    /* List length = olen - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
    buf[4] = (uint8_t)( ( ( *olen - 6 ) >> 8 ) & 0xFF );
    buf[5] = (uint8_t)( ( ( *olen - 6 )      ) & 0xFF );

    /* Extension length = olen - 2 (ext_type) - 2 (ext_len) */
    buf[2] = (uint8_t)( ( ( *olen - 4 ) >> 8 ) & 0xFF );
    buf[3] = (uint8_t)( ( ( *olen - 4 )      ) & 0xFF );
}
#endif /* POLARSSL_SSL_ALPN */

static int ssl_write_client_hello( ssl_context *ssl )
{
    int ret;
    size_t i, n, olen, ext_len = 0;
    uint8_t *buf;
    uint8_t *p, *q;
    time_t t;
    const int *ciphersuites;
    const ssl_ciphersuite_t *ciphersuite_info;

    if( ssl->f_rng == NULL )
    {
        return( POLARSSL_ERR_SSL_NO_RNG );
    }

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        ssl->major_ver = ssl->min_major_ver;
        ssl->minor_ver = ssl->min_minor_ver;
    }

    if( ssl->max_major_ver == 0 && ssl->max_minor_ver == 0 )
    {
        ssl->max_major_ver = SSL_MAX_MAJOR_VERSION;
        ssl->max_minor_ver = SSL_MAX_MINOR_VERSION;
    }

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   highest version supported
     *     6  .   9   current UNIX time
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;
    p = buf + 4;

    *p++ = (uint8_t) ssl->max_major_ver;
    *p++ = (uint8_t) ssl->max_minor_ver;

    t = time( NULL );
    *p++ = (uint8_t)( t >> 24 );
    *p++ = (uint8_t)( t >> 16 );
    *p++ = (uint8_t)( t >>  8 );
    *p++ = (uint8_t)( t       );

    if( ( ret = ssl->f_rng( ssl->p_rng, p, 28 ) ) != 0 )
        return( ret );

    p += 28;

    __movsb( ssl->handshake->randbytes, buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 39+n  session id
     *   40+n . 41+n  ciphersuitelist length
     *   42+n . ..    ciphersuitelist
     *   ..   . ..    compression methods length
     *   ..   . ..    compression methods
     *   ..   . ..    extensions length
     *   ..   . ..    extensions
     */
    n = ssl->session_negotiate->length;

    if( ssl->renegotiation != SSL_INITIAL_HANDSHAKE || n < 16 || n > 32 ||
        ssl->handshake->resume == 0 )
    {
        n = 0;
    }

    *p++ = (uint8_t) n;

    for( i = 0; i < n; i++ )
        *p++ = ssl->session_negotiate->id[i];

    ciphersuites = ssl->ciphersuite_list[ssl->minor_ver];
    n = 0;
    q = p;

    // Skip writing ciphersuite length for now
    p += 2;

    /*
     * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
     */
    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        *p++ = (uint8_t)( SSL_EMPTY_RENEGOTIATION_INFO >> 8 );
        *p++ = (uint8_t)( SSL_EMPTY_RENEGOTIATION_INFO      );
        n++;
    }

    for( i = 0; ciphersuites[i] != 0; i++ )
    {
        ciphersuite_info = ssl_ciphersuite_from_id( ciphersuites[i] );

        if( ciphersuite_info == NULL )
            continue;

        if( ciphersuite_info->min_minor_ver > ssl->max_minor_ver ||
            ciphersuite_info->max_minor_ver < ssl->min_minor_ver )
            continue;

        n++;
        *p++ = (uint8_t)( ciphersuites[i] >> 8 );
        *p++ = (uint8_t)( ciphersuites[i]      );
    }

    *q++ = (uint8_t)( n >> 7 );
    *q++ = (uint8_t)( n << 1 );

    *p++ = 1;
    *p++ = SSL_COMPRESS_NULL;

    // First write extensions, then the total length
    //
#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
    ssl_write_hostname_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

    ssl_write_renegotiation_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_signature_algorithms_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_supported_elliptic_curves_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_supported_point_formats_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    ssl_write_max_fragment_length_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
    ssl_write_truncated_hmac_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

#if defined(POLARSSL_SSL_ALPN)
    ssl_write_alpn_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

    if( ext_len > 0 )
    {
        *p++ = (uint8_t)( ( ext_len >> 8 ) & 0xFF );
        *p++ = (uint8_t)( ( ext_len      ) & 0xFF );
        p += ext_len;
    }

    ssl->out_msglen  = p - buf;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_HELLO;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

static int ssl_parse_renegotiation_info( ssl_context *ssl,
                                         const uint8_t *buf,
                                         size_t len )
{
    int ret;

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        if( len != 1 || buf[0] != 0x0 )
        {
            if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
    }
    else
    {
        /* Check verify-data in constant-time. The length OTOH is no secret */
        if( len    != 1 + ssl->verify_data_len * 2 ||
            buf[0] !=     ssl->verify_data_len * 2 ||
            safer_memcmp( buf + 1,
                          ssl->own_verify_data, ssl->verify_data_len ) != 0 ||
            safer_memcmp( buf + 1 + ssl->verify_data_len,
                          ssl->peer_verify_data, ssl->verify_data_len ) != 0 )
        {
            if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    return( 0 );
}

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext( ssl_context *ssl,
                                              const uint8_t *buf,
                                              size_t len )
{
    /*
     * server should use the extension only if we did,
     * and if so the server's value should match ours (and len is always 1)
     */
    if( ssl->mfl_code == SSL_MAX_FRAG_LEN_NONE ||
        len != 1 ||
        buf[0] != ssl->mfl_code )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    return( 0 );
}
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
static int ssl_parse_truncated_hmac_ext( ssl_context *ssl,
                                         const uint8_t *buf,
                                         size_t len )
{
    if( ssl->trunc_hmac == SSL_TRUNC_HMAC_DISABLED ||
        len != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    ((void) buf);

    ssl->session_negotiate->trunc_hmac = SSL_TRUNC_HMAC_ENABLED;

    return( 0 );
}
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

int ssl_parse_supported_point_formats_ext(ssl_context *ssl, const uint8_t *buf, size_t len)
{
    size_t list_size;
    const uint8_t *p;

    list_size = buf[0];
    if (list_size + 1 != len) {
        return POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO;
    }

    p = buf + 1;
    while (list_size > 0) {
        if (p[0] == POLARSSL_ECP_PF_UNCOMPRESSED || p[0] == POLARSSL_ECP_PF_COMPRESSED) {
            ssl->handshake->ecdh_ctx.point_format = p[0];
            return 0;
        }

        --list_size;
        ++p;
    }

    return POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO;
}

#if defined(POLARSSL_SSL_ALPN)
static int ssl_parse_alpn_ext( ssl_context *ssl,
                               const uint8_t *buf, size_t len )
{
    size_t list_len, name_len;
    const char **p;

    /* If we didn't send it, the server shouldn't send it */
    if( ssl->alpn_list == NULL )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     *
     * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
     */

    /* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
    if( len < 4 )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );

    list_len = ( buf[0] << 8 ) | buf[1];
    if( list_len != len - 2 )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );

    name_len = buf[2];
    if( name_len != list_len - 1 )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );

    /* Check that the server chosen protocol was in our list and save it */
    for( p = ssl->alpn_list; *p != NULL; p++ )
    {
        if( name_len == strlen( *p ) &&
            memcmp( buf + 3, *p, name_len ) == 0 )
        {
            ssl->alpn_chosen = *p;
            return( 0 );
        }
    }

    return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
}
#endif /* POLARSSL_SSL_ALPN */

static int ssl_parse_server_hello( ssl_context *ssl )
{
    int ret, i, comp;
    size_t n;
    size_t ext_len = 0;
    uint8_t *buf, *ext;
    int renegotiation_info_seen = 0;
    int handshake_failure = 0;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->in_msg;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_hslen < 42 ||
        buf[0] != SSL_HS_SERVER_HELLO ||
        buf[4] != SSL_MAJOR_VERSION_3 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    if( buf[5] > ssl->max_minor_ver )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    ssl->minor_ver = buf[5];

    if( ssl->minor_ver < ssl->min_minor_ver )
    {
        ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                                     SSL_ALERT_MSG_PROTOCOL_VERSION );

        return( POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
    }

    __movsb( ssl->handshake->randbytes + 32, buf + 6, 32 );

    n = buf[38];

    if( n > 32 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /*
     *    38  .  38   session id length
     *    39  . 38+n  session id
     *   39+n . 40+n  chosen ciphersuite
     *   41+n . 41+n  chosen compression alg.
     *   42+n . 43+n  extensions length
     *   44+n . 44+n+m extensions
     */
    if( ssl->in_hslen > 42 + n )
    {
        ext_len = ( ( buf[42 + n] <<  8 )
                  | ( buf[43 + n]       ) );

        if( ( ext_len > 0 && ext_len < 4 ) ||
            ssl->in_hslen != 44 + n + ext_len )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    i = ( buf[39 + n] << 8 ) | buf[40 + n];
    comp = buf[41 + n];

    /*
     * Initialize update checksum functions
     */
    ssl->transform_negotiate->ciphersuite_info = ssl_ciphersuite_from_id( i );

    if( ssl->transform_negotiate->ciphersuite_info == NULL )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    ssl_optimize_checksum( ssl, ssl->transform_negotiate->ciphersuite_info );

    /*
     * Check if the session can be resumed
     */
    if( ssl->renegotiation != SSL_INITIAL_HANDSHAKE ||
        ssl->handshake->resume == 0 || n == 0 ||
        ssl->session_negotiate->ciphersuite != i ||
        ssl->session_negotiate->compression != comp ||
        ssl->session_negotiate->length != n ||
        memcmp( ssl->session_negotiate->id, buf + 39, n ) != 0 )
    {
        ssl->state++;
        ssl->handshake->resume = 0;
        ssl->session_negotiate->start = time( NULL );
        ssl->session_negotiate->ciphersuite = i;
        ssl->session_negotiate->compression = comp;
        ssl->session_negotiate->length = n;
        __movsb( ssl->session_negotiate->id, buf + 39, n );
    }
    else
    {
        ssl->state = SSL_SERVER_CHANGE_CIPHER_SPEC;

        if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    i = 0;
    while( 1 )
    {
        if( ssl->ciphersuite_list[ssl->minor_ver][i] == 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        if( ssl->ciphersuite_list[ssl->minor_ver][i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    if( comp != SSL_COMPRESS_NULL)
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }
    ssl->session_negotiate->compression = comp;

    ext = buf + 44 + n;

    while( ext_len )
    {
        uint32_t ext_id   = ( ( ext[0] <<  8 )
                                | ( ext[1]       ) );
        uint32_t ext_size = ( ( ext[2] <<  8 )
                                | ( ext[3]       ) );

        if( ext_size + 4 > ext_len )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        switch( ext_id )
        {
        case TLS_EXT_RENEGOTIATION_INFO:
            renegotiation_info_seen = 1;

            if( ( ret = ssl_parse_renegotiation_info( ssl, ext + 4,
                                                      ext_size ) ) != 0 )
                return( ret );

            break;

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
        case TLS_EXT_MAX_FRAGMENT_LENGTH:
            if( ( ret = ssl_parse_max_fragment_length_ext( ssl,
                            ext + 4, ext_size ) ) != 0 )
            {
                return( ret );
            }

            break;
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
        case TLS_EXT_TRUNCATED_HMAC:
            if( ( ret = ssl_parse_truncated_hmac_ext( ssl,
                            ext + 4, ext_size ) ) != 0 )
            {
                return( ret );
            }

            break;
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

        case TLS_EXT_SUPPORTED_POINT_FORMATS:
            if( ( ret = ssl_parse_supported_point_formats_ext( ssl,
                            ext + 4, ext_size ) ) != 0 )
            {
                return( ret );
            }

            break;

#if defined(POLARSSL_SSL_ALPN)
        case TLS_EXT_ALPN:
            if( ( ret = ssl_parse_alpn_ext( ssl, ext + 4, ext_size ) ) != 0 )
                return( ret );

            break;
#endif /* POLARSSL_SSL_ALPN */
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    /*
     * Renegotiation security checks
     */
    if( ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
        ssl->allow_legacy_renegotiation == SSL_LEGACY_BREAK_HANDSHAKE )
    {
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_SECURE_RENEGOTIATION &&
             renegotiation_info_seen == 0 )
    {
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
             ssl->allow_legacy_renegotiation == SSL_LEGACY_NO_RENEGOTIATION )
    {
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
             renegotiation_info_seen == 1 )
    {
        handshake_failure = 1;
    }

    if( handshake_failure == 1 )
    {
        if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
            return( ret );

        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    return( 0 );
}

static int ssl_check_server_ecdh_params( const ssl_context *ssl )
{
    const ecp_curve_info *curve_info;

    curve_info = ecp_curve_info_from_grp_id( ssl->handshake->ecdh_ctx.grp.id );
    if( curve_info == NULL )
    {
        return( -1 );
    }

#if defined(POLARSSL_SSL_ECP_SET_CURVES)
    if( ! ssl_curve_is_acceptable( ssl, ssl->handshake->ecdh_ctx.grp.id ) )
#else
    if( ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
        ssl->handshake->ecdh_ctx.grp.nbits > 521 )
#endif
        return( -1 );

    return( 0 );
}

int ssl_parse_server_ecdh_params( ssl_context *ssl, uint8_t **p, uint8_t *end )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

    /*
     * Ephemeral ECDH parameters:
     *
     * struct {
     *     ECParameters curve_params;
     *     ECPoint      public;
     * } ServerECDHParams;
     */
    if( ( ret = ecdh_read_params( &ssl->handshake->ecdh_ctx,
                                  (const uint8_t **) p, end ) ) != 0 )
    {
        return( ret );
    }

    if( ssl_check_server_ecdh_params( ssl ) != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    return( ret );
}

int ssl_parse_signature_algorithm( ssl_context *ssl, uint8_t **p, uint8_t *end, md_type_t *md_alg, pk_type_t *pk_alg )
{
    ((void) ssl);
    *md_alg = POLARSSL_MD_NONE;
    *pk_alg = POLARSSL_PK_NONE;

    /* Only in TLS 1.2 */
    if( ssl->minor_ver != SSL_MINOR_VERSION_3 )
    {
        return( 0 );
    }

    if( (*p) + 2 > end )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );

    /*
     * Get hash algorithm
     */
    if( ( *md_alg = ssl_md_alg_from_hash( (*p)[0] ) ) == POLARSSL_MD_NONE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    /*
     * Get signature algorithm
     */
    if( ( *pk_alg = ssl_pk_alg_from_sig( (*p)[1] ) ) == POLARSSL_PK_NONE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    *p += 2;

    return( 0 );
}

int ssl_parse_server_key_exchange( ssl_context *ssl )
{
    int ret;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    uint8_t *p, *end;
    size_t sig_len, params_len;
    uint8_t hash[64];
    md_type_t md_alg = POLARSSL_MD_NONE;
    size_t hashlen;
    pk_type_t pk_alg = POLARSSL_PK_NONE;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /*
     * ServerKeyExchange may be skipped with PSK and RSA-PSK when the server
     * doesn't use a psk_identity_hint
     */
    if( ssl->in_msg[0] != SSL_HS_SERVER_KEY_EXCHANGE )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    p   = ssl->in_msg + 4;
    end = ssl->in_msg + ssl->in_hslen;

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA)
    {
        if( ssl_parse_server_ecdh_params( ssl, &p, end ) != 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA) {
        params_len = p - ( ssl->in_msg + 4 );

        /*
         * Handle the digitally-signed structure
         */
        if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
        {
            if( ssl_parse_signature_algorithm( ssl, &p, end,
                                               &md_alg, &pk_alg ) != 0 )
            {
                return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
            }

            if( pk_alg != ssl_get_ciphersuite_sig_pk_alg( ciphersuite_info ) )
            {
                return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
            }
        }
        else {
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        /*
         * Read signature
         */
        sig_len = ( p[0] << 8 ) | p[1];
        p += 2;

        if( end != p + sig_len )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }

        /*
         * Compute the hash that has been signed
         */
        if( md_alg != POLARSSL_MD_NONE )
        {
            md_context_t ctx;

            /* Info from md_alg will be used instead */
            hashlen = 0;

            /*
             * digitally-signed struct {
             *     opaque client_random[32];
             *     opaque server_random[32];
             *     ServerDHParams params;
             * };
             */
            if( ( ret = md_init_ctx( &ctx,
                                     md_info_from_type( md_alg ) ) ) != 0 )
            {
                return( ret );
            }

            md_starts( &ctx );
            md_update( &ctx, ssl->handshake->randbytes, 64 );
            md_update( &ctx, ssl->in_msg + 4, params_len );
            md_finish( &ctx, hash );
            md_free_ctx( &ctx );
        }
        else {
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        /*
         * Verify signature
         */
        if( ! pk_can_do( &ssl->session_negotiate->peer_cert->pk, pk_alg ) )
        {
            return( POLARSSL_ERR_SSL_PK_TYPE_MISMATCH );
        }

        if( ( ret = pk_verify( &ssl->session_negotiate->peer_cert->pk,
                               md_alg, hash, hashlen, p, sig_len ) ) != 0 )
        {
            return( ret );
        }
    }

    ++ssl->state;

    return 0;
}

int ssl_parse_certificate_request( ssl_context *ssl )
{
    int ret;
    uint8_t *buf, *p;
    size_t n = 0, m = 0;
    size_t cert_type_len = 0, dn_len = 0;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   4   cert type count
     *     5  .. m-1  cert types
     *     m  .. m+1  sig alg length (TLS 1.2 only)
     *    m+1 .. n-1  SignatureAndHashAlgorithms (TLS 1.2 only)
     *     n  .. n+1  length of all DNs
     *    n+2 .. n+3  length of DN 1
     *    n+4 .. ...  Distinguished Name #1
     *    ... .. ...  length of DN 2, etc.
     */
    if( ssl->record_read == 0 )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            return( ret );
        }

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        {
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->record_read = 1;
    }

    ssl->client_auth = 0;
    ssl->state++;

    if( ssl->in_msg[0] == SSL_HS_CERTIFICATE_REQUEST )
        ssl->client_auth++;

    if( ssl->client_auth == 0 )
        goto exit;

    ssl->record_read = 0;

    // TODO: handshake_failure alert for an anonymous server to request
    // client authentication

    buf = ssl->in_msg;

    // Retrieve cert types
    //
    cert_type_len = buf[4];
    n = cert_type_len;

    if( ssl->in_hslen < 6 + n )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

    p = buf + 5;
    while( cert_type_len > 0 )
    {
        if( *p == SSL_CERT_TYPE_RSA_SIGN &&
            pk_can_do( ssl_own_key( ssl ), POLARSSL_PK_RSA ) )
        {
            ssl->handshake->cert_type = SSL_CERT_TYPE_RSA_SIGN;
            break;
        }
        else
        {
            ; /* Unsupported cert type, ignore */
        }

        cert_type_len--;
        p++;
    }

    if( ssl->minor_ver == SSL_MINOR_VERSION_3 ) {
        /* Ignored, see comments about hash in write_certificate_verify */
        // TODO: should check the signature part against our pk_key though
        size_t sig_alg_len = ( ( buf[5 + n] <<  8 )
                             | ( buf[6 + n]       ) );

        p = buf + 7 + n;
        m += 2;
        n += sig_alg_len;

        if( ssl->in_hslen < 6 + n )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        }
    }

    /* Ignore certificate_authorities, we only have one cert anyway */
    // TODO: should not send cert if no CA matches
    dn_len = ( ( buf[5 + m + n] <<  8 )
             | ( buf[6 + m + n]       ) );

    n += dn_len;
    if( ssl->in_hslen != 7 + m + n )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

exit:
    return( 0 );
}

static int ssl_parse_server_hello_done( ssl_context *ssl )
{
    int ret;

    if( ssl->record_read == 0 )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            return( ret );
        }

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        {
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }
    }
    ssl->record_read = 0;

    if( ssl->in_hslen  != 4 ||
        ssl->in_msg[0] != SSL_HS_SERVER_HELLO_DONE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE );
    }

    ssl->state++;

    return( 0 );
}

static int ssl_write_client_key_exchange( ssl_context *ssl )
{
    int ret;
    size_t i, n;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA || ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_RSA)
    {
        /*
         * ECDH key exchange -- send client public value
         */
        i = 4;

        ret = ecdh_make_public( &ssl->handshake->ecdh_ctx,
                                &n,
                                &ssl->out_msg[i], 1000,
                                ssl->f_rng, ssl->p_rng );
        if( ret != 0 )
        {
            return( ret );
        }

        if( ( ret = ecdh_calc_secret( &ssl->handshake->ecdh_ctx,
                                      &ssl->handshake->pmslen,
                                       ssl->handshake->premaster,
                                       POLARSSL_MPI_MAX_SIZE,
                                       ssl->f_rng, ssl->p_rng ) ) != 0 )
        {
            return( ret );
        }
    }
    else {
        ((void) ciphersuite_info);
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
    {
        return( ret );
    }

    ssl->out_msglen  = i + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_KEY_EXCHANGE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int ssl_write_certificate_verify( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    size_t n = 0, offset = 0;
    uint8_t hash[48];
    uint8_t *hash_start = hash;
    md_type_t md_alg = POLARSSL_MD_NONE;
    uint32_t hashlen;

    if( ssl->client_auth == 0 || ssl_own_cert( ssl ) == NULL )
    {
        ssl->state++;
        return( 0 );
    }

    if( ssl_own_key( ssl ) == NULL )
    {
        return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    /*
     * Make an RSA signature of the handshake digests
     */
    ssl->handshake->calc_verify( ssl, hash );
    if( ssl->minor_ver == SSL_MINOR_VERSION_3 ) {
        /*
         * digitally-signed struct {
         *     opaque handshake_messages[handshake_messages_length];
         * };
         *
         * Taking shortcut here. We assume that the server always allows the
         * PRF Hash function and has sent it in the allowed signature
         * algorithms list received in the Certificate Request message.
         *
         * Until we encounter a server that does not, we will take this
         * shortcut.
         *
         * Reason: Otherwise we should have running hashes for SHA512 and SHA224
         *         in order to satisfy 'weird' needs from the server side.
         */
        if( ssl->transform_negotiate->ciphersuite_info->mac ==
            POLARSSL_MD_SHA384 )
        {
            md_alg = POLARSSL_MD_SHA384;
            ssl->out_msg[4] = SSL_HASH_SHA384;
        }
        else
        {
            md_alg = POLARSSL_MD_SHA256;
            ssl->out_msg[4] = SSL_HASH_SHA256;
        }
        ssl->out_msg[5] = ssl_sig_from_pk( ssl_own_key( ssl ) );

        /* Info from md_alg will be used instead */
        hashlen = 0;
        offset = 2;
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ( ret = pk_sign( ssl_own_key( ssl ), md_alg, hash_start, hashlen,
                         ssl->out_msg + 6 + offset, &n,
                         ssl->f_rng, ssl->p_rng ) ) != 0 )
    {
        return( ret );
    }

    ssl->out_msg[4 + offset] = (uint8_t)( n >> 8 );
    ssl->out_msg[5 + offset] = (uint8_t)( n      );

    ssl->out_msglen  = 6 + n + offset;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE_VERIFY;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( ret );
}

/*
 * SSL handshake -- client side -- single step
 */
int ssl_handshake_client_step( ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == SSL_HANDSHAKE_OVER )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    switch( ssl->state )
    {
        case SSL_HELLO_REQUEST:
            ssl->state = SSL_CLIENT_HELLO;
            break;

       /*
        *  ==>   ClientHello
        */
       case SSL_CLIENT_HELLO:
           ret = ssl_write_client_hello( ssl );
           break;

       /*
        *  <==   ServerHello
        *        Certificate
        *      ( ServerKeyExchange  )
        *      ( CertificateRequest )
        *        ServerHelloDone
        */
       case SSL_SERVER_HELLO:
           ret = ssl_parse_server_hello( ssl );
           break;

       case SSL_SERVER_CERTIFICATE:
           ret = ssl_parse_certificate( ssl );
           break;

       case SSL_SERVER_KEY_EXCHANGE:
           ret = ssl_parse_server_key_exchange( ssl );
           break;

       case SSL_CERTIFICATE_REQUEST:
           ret = ssl_parse_certificate_request( ssl );
           break;

       case SSL_SERVER_HELLO_DONE:
           ret = ssl_parse_server_hello_done( ssl );
           break;

       /*
        *  ==> ( Certificate/Alert  )
        *        ClientKeyExchange
        *      ( CertificateVerify  )
        *        ChangeCipherSpec
        *        Finished
        */
       case SSL_CLIENT_CERTIFICATE:
           ret = ssl_write_certificate( ssl );
           break;

       case SSL_CLIENT_KEY_EXCHANGE:
           ret = ssl_write_client_key_exchange( ssl );
           break;

       case SSL_CERTIFICATE_VERIFY:
           ret = ssl_write_certificate_verify( ssl );
           break;

       case SSL_CLIENT_CHANGE_CIPHER_SPEC:
           ret = ssl_write_change_cipher_spec( ssl );
           break;

       case SSL_CLIENT_FINISHED:
           ret = ssl_write_finished( ssl );
           break;

       /*
        *  <==   ( NewSessionTicket )
        *        ChangeCipherSpec
        *        Finished
        */
       case SSL_SERVER_CHANGE_CIPHER_SPEC:
           ret = ssl_parse_change_cipher_spec( ssl );
           break;

       case SSL_SERVER_FINISHED:
           ret = ssl_parse_finished( ssl );
           break;

       case SSL_FLUSH_BUFFERS:
           ssl->state = SSL_HANDSHAKE_WRAPUP;
           break;

       case SSL_HANDSHAKE_WRAPUP:
           ssl_handshake_wrapup( ssl );
           break;

       default:
           return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
   }

    return( ret );
}
#endif /* POLARSSL_SSL_CLI_C */
