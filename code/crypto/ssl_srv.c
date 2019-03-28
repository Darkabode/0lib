#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_SSL_SRV_C)

#include "ssl.h"
#include "ecp.h"

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
/*
 * Wrapper around f_sni, allowing use of ssl_set_own_cert() but
 * making it act on ssl->hanshake->sni_key_cert instead.
 */
static int ssl_sni_wrapper( ssl_context *ssl,
                            const uint8_t* name, size_t len )
{
    int ret;
    ssl_key_cert *key_cert_ori = ssl->key_cert;

    ssl->key_cert = NULL;
    ret = ssl->f_sni( ssl->p_sni, ssl, name, len );
    ssl->handshake->sni_key_cert = ssl->key_cert;

    ssl->key_cert = key_cert_ori;

    return( ret );
}

static int ssl_parse_servername_ext( ssl_context *ssl,
                                     const uint8_t *buf,
                                     size_t len )
{
    int ret;
    size_t servername_list_size, hostname_len;
    const uint8_t *p;

    servername_list_size = ( ( buf[0] << 8 ) | ( buf[1] ) );
    if( servername_list_size + 2 != len )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    p = buf + 2;
    while( servername_list_size > 0 )
    {
        hostname_len = ( ( p[1] << 8 ) | p[2] );
        if( hostname_len + 3 > servername_list_size )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( p[0] == TLS_EXT_SERVERNAME_HOSTNAME )
        {
            ret = ssl_sni_wrapper( ssl, p + 3, hostname_len );
            if( ret != 0 )
            {
                ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                        SSL_ALERT_MSG_UNRECOGNIZED_NAME );
                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
            }
            return( 0 );
        }

        servername_list_size -= hostname_len + 3;
        p += hostname_len + 3;
    }

    if( servername_list_size != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    return( 0 );
}
#endif /* POLARSSL_SSL_SERVER_NAME_INDICATION */

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

            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
    }
    else
    {
        /* Check verify-data in constant-time. The length OTOH is no secret */
        if( len    != 1 + ssl->verify_data_len ||
            buf[0] !=     ssl->verify_data_len ||
            safer_memcmp( buf + 1, ssl->peer_verify_data,
                          ssl->verify_data_len ) != 0 )
        {
            if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }
    }

    return( 0 );
}

static int ssl_parse_signature_algorithms_ext( ssl_context *ssl, const uint8_t *buf, size_t len )
{
    size_t sig_alg_list_size;
    const uint8_t *p;
    const uint8_t *end = buf + len;
    const int *md_cur;


    sig_alg_list_size = ((buf[0] << 8) | (buf[1]));
    if (sig_alg_list_size + 2 != len || sig_alg_list_size % 2 != 0)
    {
        return(POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO);
    }

    /*
    * For now, ignore the SignatureAlgorithm part and rely on offered
    * ciphersuites only for that part. To be fixed later.
    *
    * So, just look at the HashAlgorithm part.
    */
    for (md_cur = md_list(); *md_cur != POLARSSL_MD_NONE; md_cur++) {
        for (p = buf + 2; p < end; p += 2) {
            if (*md_cur == (int)ssl_md_alg_from_hash(p[0])) {
                ssl->handshake->sig_alg = p[0];
                break;
            }
        }
    }

    return 0;
}

int ssl_parse_supported_elliptic_curves( ssl_context *ssl, const uint8_t *buf, size_t len )
{
    size_t list_size, our_size;
    const uint8_t *p;
    const ecp_curve_info *curve_info, **curves;

    list_size = ( ( buf[0] << 8 ) | ( buf[1] ) );
    if( list_size + 2 != len ||
        list_size % 2 != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /* Don't allow our peer to make us allocate too much memory,
     * and leave room for a final 0 */
    our_size = list_size / 2 + 1;
    if( our_size > POLARSSL_ECP_DP_MAX )
        our_size = POLARSSL_ECP_DP_MAX;

    if( ( curves = memory_alloc( our_size * sizeof( *curves ) ) ) == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    /* explicit void pointer cast for buggy MS compiler */
    __stosb( (void *) curves, 0, our_size * sizeof( *curves ) );
    ssl->handshake->curves = curves;

    p = buf + 2;
    while( list_size > 0 && our_size > 1 )
    {
        curve_info = ecp_curve_info_from_tls_id( ( p[0] << 8 ) | p[1] );

        if( curve_info != NULL )
        {
            *curves++ = curve_info;
            our_size--;
        }

        list_size -= 2;
        p += 2;
    }

    return( 0 );
}

static int ssl_parse_supported_point_formats( ssl_context *ssl,
                                              const uint8_t *buf,
                                              size_t len )
{
    size_t list_size;
    const uint8_t *p;

    list_size = buf[0];
    if( list_size + 1 != len )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    p = buf + 2;
    while( list_size > 0 )
    {
        if( p[0] == POLARSSL_ECP_PF_UNCOMPRESSED ||
            p[0] == POLARSSL_ECP_PF_COMPRESSED )
        {
            ssl->handshake->ecdh_ctx.point_format = p[0];
            return( 0 );
        }

        list_size--;
        p++;
    }

    return( 0 );
}

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext( ssl_context *ssl,
                                              const uint8_t *buf,
                                              size_t len )
{
    if( len != 1 || buf[0] >= SSL_MAX_FRAG_LEN_INVALID )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->session_negotiate->mfl_code = buf[0];

    return( 0 );
}
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
static int ssl_parse_truncated_hmac_ext( ssl_context *ssl,
                                         const uint8_t *buf,
                                         size_t len )
{
    if( len != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ((void) buf);

    ssl->session_negotiate->trunc_hmac = SSL_TRUNC_HMAC_ENABLED;

    return( 0 );
}
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

#if defined(POLARSSL_SSL_ALPN)
static int ssl_parse_alpn_ext( ssl_context *ssl,
                               const uint8_t *buf, size_t len )
{
    size_t list_len, cur_len;
    const uint8_t *theirs, *start, *end;
    const char **ours;

    /* If ALPN not configured, just ignore the extension */
    if( ssl->alpn_list == NULL )
        return( 0 );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */

    /* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
    if( len < 4 )
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );

    list_len = ( buf[0] << 8 ) | buf[1];
    if( list_len != len - 2 )
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );

    /*
     * Use our order of preference
     */
    start = buf + 2;
    end = buf + len;
    for( ours = ssl->alpn_list; *ours != NULL; ours++ )
    {
        for( theirs = start; theirs != end; theirs += cur_len )
        {
            /* If the list is well formed, we should get equality first */
            if( theirs > end )
                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );

            cur_len = *theirs++;

            /* Empty strings MUST NOT be included */
            if( cur_len == 0 )
                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );

            if( cur_len == strlen( *ours ) &&
                memcmp( theirs, *ours, cur_len ) == 0 )
            {
                ssl->alpn_chosen = *ours;
                return( 0 );
            }
        }
    }

    /* If we get there, no match was found */
    ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                            SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL );
    return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
}
#endif /* POLARSSL_SSL_ALPN */

/*
 * Auxiliary functions for ServerHello parsing and related actions
 */

#if defined(POLARSSL_X509_CRT_PARSE_C)

/*
 * Try picking a certificate for this ciphersuite,
 * return 0 on success and -1 on failure.
 */
static int ssl_pick_cert( ssl_context *ssl,
                          const ssl_ciphersuite_t * ciphersuite_info )
{
    ssl_key_cert *cur, *list;
    pk_type_t pk_alg = ssl_get_ciphersuite_sig_pk_alg( ciphersuite_info );

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_key_cert != NULL )
        list = ssl->handshake->sni_key_cert;
    else
#endif
        list = ssl->handshake->key_cert;

    if( pk_alg == POLARSSL_PK_NONE )
        return( 0 );

    for( cur = list; cur != NULL; cur = cur->next )
    {
        if( ! pk_can_do( cur->key, pk_alg ) )
            continue;

        /*
         * This avoids sending the client a cert it'll reject based on
         * keyUsage or other extensions.
         *
         * It also allows the user to provision different certificates for
         * different uses based on keyUsage, eg if they want to avoid signing
         * and decrypting with the same RSA key.
         */
        if( ssl_check_cert_usage( cur->cert, ciphersuite_info,
                                  SSL_IS_SERVER ) != 0 )
        {
            continue;
        }
        break;
    }

    if( cur == NULL )
        return( -1 );

    ssl->handshake->key_cert = cur;
    return( 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

/*
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets ciphersuite_info only if the suite matches.
 */
static int ssl_ciphersuite_match( ssl_context *ssl, int suite_id,
                                  const ssl_ciphersuite_t **ciphersuite_info )
{
    const ssl_ciphersuite_t *suite_info;

    suite_info = ssl_ciphersuite_from_id( suite_id );
    if( suite_info == NULL )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    if( suite_info->min_minor_ver > ssl->minor_ver ||
        suite_info->max_minor_ver < ssl->minor_ver )
        return( 0 );

    if( ssl_ciphersuite_uses_ec( suite_info ) &&
        ( ssl->handshake->curves == NULL ||
          ssl->handshake->curves[0] == NULL ) )
        return( 0 );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * Final check: if ciphersuite requires us to have a
     * certificate/key of a particular type:
     * - select the appropriate certificate if we have one, or
     * - try the next ciphersuite if we don't
     * This must be done last since we modify the key_cert list.
     */
    if( ssl_pick_cert( ssl, suite_info ) != 0 )
        return( 0 );
#endif

    *ciphersuite_info = suite_info;
    return( 0 );
}

#if defined(POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO)
static int ssl_parse_client_hello_v2( ssl_context *ssl )
{
    int ret;
    uint32_t i, j;
    size_t n;
    uint32_t ciph_len, sess_len, chal_len;
    uint8_t *buf, *p;
    const int *ciphersuites;
    const ssl_ciphersuite_t *ciphersuite_info;

    if( ssl->renegotiation != SSL_INITIAL_HANDSHAKE )
    {
        if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
            return( ret );

        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    buf = ssl->in_hdr;

    /*
     * SSLv2 Client Hello
     *
     * Record layer:
     *     0  .   1   message length
     *
     * SSL layer:
     *     2  .   2   message type
     *     3  .   4   protocol version
     */
    if( buf[2] != SSL_HS_CLIENT_HELLO ||
        buf[3] != SSL_MAJOR_VERSION_3 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    n = ( ( buf[0] << 8 ) | buf[1] ) & 0x7FFF;

    if( n < 17 || n > 512 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->major_ver = SSL_MAJOR_VERSION_3;
    ssl->minor_ver = ( buf[4] <= ssl->max_minor_ver )
                     ? buf[4]  : ssl->max_minor_ver;

    if( ssl->minor_ver < ssl->min_minor_ver )
    {
        ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                                     SSL_ALERT_MSG_PROTOCOL_VERSION );
        return( POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
    }

    ssl->handshake->max_major_ver = buf[3];
    ssl->handshake->max_minor_ver = buf[4];

    if( ( ret = ssl_fetch_input( ssl, 2 + n ) ) != 0 )
    {
        return( ret );
    }

    ssl->handshake->update_checksum( ssl, buf + 2, n );

    buf = ssl->in_msg;
    n = ssl->in_left - 5;

    /*
     *    0  .   1   ciphersuitelist length
     *    2  .   3   session id length
     *    4  .   5   challenge length
     *    6  .  ..   ciphersuitelist
     *   ..  .  ..   session id
     *   ..  .  ..   challenge
     */

    ciph_len = ( buf[0] << 8 ) | buf[1];
    sess_len = ( buf[2] << 8 ) | buf[3];
    chal_len = ( buf[4] << 8 ) | buf[5];

    /*
     * Make sure each parameter length is valid
     */
    if( ciph_len < 3 || ( ciph_len % 3 ) != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    if( sess_len > 32 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    if( chal_len < 8 || chal_len > 32 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    if( n != 6 + ciph_len + sess_len + chal_len )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    p = buf + 6 + ciph_len;
    ssl->session_negotiate->length = sess_len;
    __stosb( ssl->session_negotiate->id, 0,
            sizeof( ssl->session_negotiate->id ) );
    __movsb( ssl->session_negotiate->id, p, ssl->session_negotiate->length );

    p += sess_len;
    __stosb( ssl->handshake->randbytes, 0, 64 );
    __movsb( ssl->handshake->randbytes + 32 - chal_len, p, chal_len );

    /*
     * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
     */
    for( i = 0, p = buf + 6; i < ciph_len; i += 3, p += 3 )
    {
        if( p[0] == 0 && p[1] == 0 && p[2] == SSL_EMPTY_RENEGOTIATION_INFO )
        {
            if( ssl->renegotiation == SSL_RENEGOTIATION )
            {
                if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                    return( ret );

                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
            }
            ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
            break;
        }
    }

    ciphersuites = ssl->ciphersuite_list[ssl->minor_ver];
    ciphersuite_info = NULL;
    for( i = 0; ciphersuites[i] != 0; i++ )
    {
        for( j = 0, p = buf + 6; j < ciph_len; j += 3, p += 3 )
        {
            if( p[0] != 0 ||
                p[1] != ( ( ciphersuites[i] >> 8 ) & 0xFF ) ||
                p[2] != ( ( ciphersuites[i]      ) & 0xFF ) )
                continue;

            if( ( ret = ssl_ciphersuite_match( ssl, ciphersuites[i],
                                               &ciphersuite_info ) ) != 0 )
                return( ret );

            if( ciphersuite_info != NULL )
                goto have_ciphersuite_v2;
        }
    }

    return( POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN );

have_ciphersuite_v2:
    ssl->session_negotiate->ciphersuite = ciphersuites[i];
    ssl->transform_negotiate->ciphersuite_info = ciphersuite_info;
    ssl_optimize_checksum( ssl, ssl->transform_negotiate->ciphersuite_info );

    /*
     * SSLv2 Client Hello relevant renegotiation security checks
     */
    if( ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
        ssl->allow_legacy_renegotiation == SSL_LEGACY_BREAK_HANDSHAKE )
    {
        if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
            return( ret );

        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->in_left = 0;
    ssl->state++;

    return( 0 );
}
#endif /* POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO */

static int ssl_parse_client_hello( ssl_context *ssl )
{
    int ret;
    uint32_t i, j;
    size_t n;
    uint32_t ciph_len, sess_len;
    uint32_t comp_len;
    uint32_t ext_len = 0;
    uint8_t *buf, *p, *ext;
    int renegotiation_info_seen = 0;
    int handshake_failure = 0;
    const int *ciphersuites;
    const ssl_ciphersuite_t *ciphersuite_info;

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
        ( ret = ssl_fetch_input( ssl, 5 ) ) != 0 )
    {
        return( ret );
    }

    buf = ssl->in_hdr;

#if defined(POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO)
    if( ( buf[0] & 0x80 ) != 0 )
        return ssl_parse_client_hello_v2( ssl );
#endif

    /*
     * SSLv3/TLS Client Hello
     *
     * Record layer:
     *     0  .   0   message type
     *     1  .   2   protocol version
     *     3  .   4   message length
     */

    /* According to RFC 5246 Appendix E.1, the version here is typically
     * "{03,00}, the lowest version number supported by the client, [or] the
     * value of ClientHello.client_version", so the only meaningful check here
     * is the major version shouldn't be less than 3 */
    if( buf[0] != SSL_MSG_HANDSHAKE ||
        buf[1] < SSL_MAJOR_VERSION_3 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    n = ( buf[3] << 8 ) | buf[4];

    if( n < 45 || n > SSL_MAX_CONTENT_LEN )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
        ( ret = ssl_fetch_input( ssl, 5 + n ) ) != 0 )
    {
        return( ret );
    }

    buf = ssl->in_msg;
    if( !ssl->renegotiation )
        n = ssl->in_left - 5;
    else
        n = ssl->in_msglen;

    ssl->handshake->update_checksum( ssl, buf, n );

    /*
     * SSL layer:
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     *    38  .  38   session id length
     *    39  . 38+x  session id
     *   39+x . 40+x  ciphersuitelist length
     *   41+x .  ..   ciphersuitelist
     *    ..  .  ..   compression alg.
     *    ..  .  ..   extensions
     */

    /*
     * Check the handshake type and protocol version
     */
    if( buf[0] != SSL_HS_CLIENT_HELLO )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->major_ver = buf[4];
    ssl->minor_ver = buf[5];

    ssl->handshake->max_major_ver = ssl->major_ver;
    ssl->handshake->max_minor_ver = ssl->minor_ver;

    if( ssl->major_ver < ssl->min_major_ver ||
        ssl->minor_ver < ssl->min_minor_ver )
    {
        ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                                     SSL_ALERT_MSG_PROTOCOL_VERSION );

        return( POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
    }

    if( ssl->major_ver > ssl->max_major_ver )
    {
        ssl->major_ver = ssl->max_major_ver;
        ssl->minor_ver = ssl->max_minor_ver;
    }
    else if( ssl->minor_ver > ssl->max_minor_ver )
        ssl->minor_ver = ssl->max_minor_ver;

    __movsb( ssl->handshake->randbytes, buf + 6, 32 );

    /*
     * Check the handshake message length
     */
    if( buf[1] != 0 || n != (uint32_t) 4 + ( ( buf[2] << 8 ) | buf[3] ) )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /*
     * Check the session length
     */
    sess_len = buf[38];

    if( sess_len > 32 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->session_negotiate->length = sess_len;
    __stosb( ssl->session_negotiate->id, 0,
            sizeof( ssl->session_negotiate->id ) );
    __movsb( ssl->session_negotiate->id, buf + 39,
            ssl->session_negotiate->length );

    /*
     * Check the ciphersuitelist length
     */
    ciph_len = ( buf[39 + sess_len] << 8 )
             | ( buf[40 + sess_len]      );

    if( ciph_len < 2 || ( ciph_len % 2 ) != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /*
     * Check the compression algorithms length
     */
    comp_len = buf[41 + sess_len + ciph_len];

    if( comp_len < 1 || comp_len > 16 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /*
     * Check the extension length
     */
    if( n > 42 + sess_len + ciph_len + comp_len )
    {
        ext_len = ( buf[42 + sess_len + ciph_len + comp_len] << 8 )
                | ( buf[43 + sess_len + ciph_len + comp_len]      );

        if( ( ext_len > 0 && ext_len < 4 ) ||
            n != 44 + sess_len + ciph_len + comp_len + ext_len )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }
    }

    ssl->session_negotiate->compression = SSL_COMPRESS_NULL;


    /*
     * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
     */
    for( i = 0, p = buf + 41 + sess_len; i < ciph_len; i += 2, p += 2 )
    {
        if( p[0] == 0 && p[1] == SSL_EMPTY_RENEGOTIATION_INFO )
        {
            if( ssl->renegotiation == SSL_RENEGOTIATION )
            {
                if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                    return( ret );

                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
            }
            ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
            break;
        }
    }

    ext = buf + 44 + sess_len + ciph_len + comp_len;

    while( ext_len )
    {
        uint32_t ext_id   = ( ( ext[0] <<  8 )
                                | ( ext[1]       ) );
        uint32_t ext_size = ( ( ext[2] <<  8 )
                                | ( ext[3]       ) );

        if( ext_size + 4 > ext_len )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }
        switch( ext_id )
        {
#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
        case TLS_EXT_SERVERNAME:
            if( ssl->f_sni == NULL )
                break;

            ret = ssl_parse_servername_ext( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;
#endif /* POLARSSL_SSL_SERVER_NAME_INDICATION */

        case TLS_EXT_RENEGOTIATION_INFO:
            renegotiation_info_seen = 1;

            ret = ssl_parse_renegotiation_info( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;

        case TLS_EXT_SIG_ALG:
            if( ssl->renegotiation == SSL_RENEGOTIATION )
                break;

            ret = ssl_parse_signature_algorithms_ext( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;

        case TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:

            ret = ssl_parse_supported_elliptic_curves( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;

        case TLS_EXT_SUPPORTED_POINT_FORMATS:
            ssl->handshake->cli_exts |= TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;

            ret = ssl_parse_supported_point_formats( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
        case TLS_EXT_MAX_FRAGMENT_LENGTH:
            ret = ssl_parse_max_fragment_length_ext( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
        case TLS_EXT_TRUNCATED_HMAC:
            ret = ssl_parse_truncated_hmac_ext( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

#if defined(POLARSSL_SSL_ALPN)
        case TLS_EXT_ALPN:
            ret = ssl_parse_alpn_ext( ssl, ext + 4, ext_size );
            if( ret != 0 )
                return( ret );
            break;
#endif /* POLARSSL_SSL_ALPN */
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
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

        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /*
     * Search for a matching ciphersuite
     * (At the end because we need information from the EC-based extensions
     * and certificate from the SNI callback triggered by the SNI extension.)
     */
    ciphersuites = ssl->ciphersuite_list[ssl->minor_ver];
    ciphersuite_info = NULL;
    for( i = 0; ciphersuites[i] != 0; i++ )
    {
        for( j = 0, p = buf + 41 + sess_len; j < ciph_len; j += 2, p += 2 )
        {
            if( p[0] != ( ( ciphersuites[i] >> 8 ) & 0xFF ) ||
                p[1] != ( ( ciphersuites[i]      ) & 0xFF ) )
                continue;

            if( ( ret = ssl_ciphersuite_match( ssl, ciphersuites[i],
                                               &ciphersuite_info ) ) != 0 )
                return( ret );

            if( ciphersuite_info != NULL )
                goto have_ciphersuite;
        }
    }

    if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
        return( ret );

    return( POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN );

have_ciphersuite:
    ssl->session_negotiate->ciphersuite = ciphersuites[i];
    ssl->transform_negotiate->ciphersuite_info = ciphersuite_info;
    ssl_optimize_checksum( ssl, ssl->transform_negotiate->ciphersuite_info );

    ssl->in_left = 0;
    ssl->state++;

    return( 0 );
}

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
static void ssl_write_truncated_hmac_ext( ssl_context *ssl,
                                          uint8_t *buf,
                                          size_t *olen )
{
    uint8_t *p = buf;

    if( ssl->session_negotiate->trunc_hmac == SSL_TRUNC_HMAC_DISABLED )
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

void ssl_write_renegotiation_ext( ssl_context *ssl,
                                         uint8_t *buf,
                                         size_t *olen )
{
    uint8_t *p = buf;

    if( ssl->secure_renegotiation != SSL_SECURE_RENEGOTIATION )
    {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_RENEGOTIATION_INFO >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_RENEGOTIATION_INFO      ) & 0xFF );

    *p++ = 0x00;
    *p++ = ( ssl->verify_data_len * 2 + 1 ) & 0xFF;
    *p++ = ssl->verify_data_len * 2 & 0xFF;

    __movsb( p, ssl->peer_verify_data, ssl->verify_data_len );
    p += ssl->verify_data_len;
    __movsb( p, ssl->own_verify_data, ssl->verify_data_len );
    p += ssl->verify_data_len;

    *olen = 5 + ssl->verify_data_len * 2;
}

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext( ssl_context *ssl,
                                               uint8_t *buf,
                                               size_t *olen )
{
    uint8_t *p = buf;

    if( ssl->session_negotiate->mfl_code == SSL_MAX_FRAG_LEN_NONE )
    {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_MAX_FRAGMENT_LENGTH >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_MAX_FRAGMENT_LENGTH      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 1;

    *p++ = ssl->session_negotiate->mfl_code;

    *olen = 5;
}
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

static void ssl_write_supported_point_formats_ext( ssl_context *ssl, uint8_t *buf, size_t *olen )
{
    uint8_t *p = buf;
    ((void) ssl);

    if( ( ssl->handshake->cli_exts &
          TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT ) == 0 )
    {
        *olen = 0;
        return;
    }

    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_POINT_FORMATS >> 8 ) & 0xFF );
    *p++ = (uint8_t)( ( TLS_EXT_SUPPORTED_POINT_FORMATS      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 2;

    *p++ = 1;
    *p++ = POLARSSL_ECP_PF_UNCOMPRESSED;

    *olen = 6;
}

void ssl_write_alpn_ext( ssl_context *ssl, uint8_t *buf, size_t *olen )
{
    if( ssl->alpn_chosen == NULL )
    {
        *olen = 0;
        return;
    }

    /*
     * 0 . 1    ext identifier
     * 2 . 3    ext length
     * 4 . 5    protocol list length
     * 6 . 6    protocol name length
     * 7 . 7+n  protocol name
     */
    buf[0] = (uint8_t)( ( TLS_EXT_ALPN >> 8 ) & 0xFF );
    buf[1] = (uint8_t)( ( TLS_EXT_ALPN      ) & 0xFF );

    *olen = 7 + strlen( ssl->alpn_chosen );

    buf[2] = (uint8_t)( ( ( *olen - 4 ) >> 8 ) & 0xFF );
    buf[3] = (uint8_t)( ( ( *olen - 4 )      ) & 0xFF );

    buf[4] = (uint8_t)( ( ( *olen - 6 ) >> 8 ) & 0xFF );
    buf[5] = (uint8_t)( ( ( *olen - 6 )      ) & 0xFF );

    buf[6] = (uint8_t)( ( ( *olen - 7 )      ) & 0xFF );

    __movsb( buf + 7, ssl->alpn_chosen, *olen - 7 );
}

static int ssl_write_server_hello( ssl_context *ssl )
{
    time_t t;
    int ret;
    size_t olen, ext_len = 0, n;
    uint8_t *buf, *p;

    if( ssl->f_rng == NULL )
    {
        return( POLARSSL_ERR_SSL_NO_RNG );
    }

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;
    p = buf + 4;

    *p++ = (uint8_t) ssl->major_ver;
    *p++ = (uint8_t) ssl->minor_ver;

    t = time( NULL );
    *p++ = (uint8_t)( t >> 24 );
    *p++ = (uint8_t)( t >> 16 );
    *p++ = (uint8_t)( t >>  8 );
    *p++ = (uint8_t)( t       );

    if( ( ret = ssl->f_rng( ssl->p_rng, p, 28 ) ) != 0 )
        return( ret );

    p += 28;

    __movsb( ssl->handshake->randbytes + 32, buf + 6, 32 );

    /*
     * Resume is 0  by default, see ssl_handshake_init().
     * It may be already set to 1 by ssl_parse_session_ticket_ext().
     * If not, try looking up session ID in our cache.
     */
    if( ssl->handshake->resume == 0 &&
        ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
        ssl->session_negotiate->length != 0 &&
        ssl->f_get_cache != NULL &&
        ssl->f_get_cache( ssl->p_get_cache, ssl->session_negotiate ) == 0 )
    {
        ssl->handshake->resume = 1;
    }

    if( ssl->handshake->resume == 0 )
    {
        /*
         * New session, create a new session id,
         * unless we're about to issue a session ticket
         */
        ssl->state++;
        ssl->session_negotiate->start = time( NULL );

        {
            ssl->session_negotiate->length = n = 32;
            if( ( ret = ssl->f_rng( ssl->p_rng, ssl->session_negotiate->id,
                                    n ) ) != 0 )
                return( ret );
        }
    }
    else
    {
        /*
         * Resuming a session
         */
        n = ssl->session_negotiate->length;
        ssl->state = SSL_SERVER_CHANGE_CIPHER_SPEC;

        if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    /*
     *    38  .  38     session id length
     *    39  . 38+n    session id
     *   39+n . 40+n    chosen ciphersuite
     *   41+n . 41+n    chosen compression alg.
     *   42+n . 43+n    extensions length
     *   44+n . 43+n+m  extensions
     */
    *p++ = (uint8_t) ssl->session_negotiate->length;
    __movsb( p, ssl->session_negotiate->id, ssl->session_negotiate->length );
    p += ssl->session_negotiate->length;

    *p++ = (uint8_t)( ssl->session_negotiate->ciphersuite >> 8 );
    *p++ = (uint8_t)( ssl->session_negotiate->ciphersuite      );
    *p++ = (uint8_t)( ssl->session_negotiate->compression      );

    /*
     *  First write extensions, then the total length
     */
    ssl_write_renegotiation_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    ssl_write_max_fragment_length_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
    ssl_write_truncated_hmac_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

    ssl_write_supported_point_formats_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

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
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO;

    ret = ssl_write_record( ssl );

    return( ret );
}

int ssl_write_certificate_request( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    size_t dn_size, total_dn_size; /* excluding length bytes */
    size_t ct_len, sa_len; /* including length bytes */
    uint8_t *buf, *p;
    const x509_crt *crt;

    ssl->state++;

    if( ssl->authmode == SSL_VERIFY_NONE )
    {
        return( 0 );
    }

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
    buf = ssl->out_msg;
    p = buf + 4;

    /*
     * Supported certificate types
     *
     *     ClientCertificateType certificate_types<1..2^8-1>;
     *     enum { (255) } ClientCertificateType;
     */
    ct_len = 0;

    p[1 + ct_len++] = SSL_CERT_TYPE_RSA_SIGN;
    p[0] = (uint8_t) ct_len++;
    p += ct_len;

    sa_len = 0;
    /*
     * Add signature_algorithms for verify (TLS 1.2)
     *
     *     SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
     *
     *     struct {
     *           HashAlgorithm hash;
     *           SignatureAlgorithm signature;
     *     } SignatureAndHashAlgorithm;
     *
     *     enum { (255) } HashAlgorithm;
     *     enum { (255) } SignatureAlgorithm;
     */
    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        /*
         * Only use current running hash algorithm that is already required
         * for requested ciphersuite.
         */
        ssl->handshake->verify_sig_alg = SSL_HASH_SHA256;

        if( ssl->transform_negotiate->ciphersuite_info->mac ==
            POLARSSL_MD_SHA384 )
        {
            ssl->handshake->verify_sig_alg = SSL_HASH_SHA384;
        }

        /*
         * Supported signature algorithms
         */
        p[2 + sa_len++] = ssl->handshake->verify_sig_alg;
        p[2 + sa_len++] = SSL_SIG_RSA;
        p[0] = (uint8_t)( sa_len >> 8 );
        p[1] = (uint8_t)( sa_len      );
        sa_len += 2;
        p += sa_len;
    }

    /*
     * DistinguishedName certificate_authorities<0..2^16-1>;
     * opaque DistinguishedName<1..2^16-1>;
     */
    p += 2;
    crt = ssl->ca_chain;

    total_dn_size = 0;
    while( crt != NULL && crt->version != 0 )
    {
        if( p - buf > 4096 )
            break;

        dn_size = crt->subject_raw.len;
        *p++ = (uint8_t)( dn_size >> 8 );
        *p++ = (uint8_t)( dn_size      );
        __movsb( p, crt->subject_raw.p, dn_size );
        p += dn_size;

        total_dn_size += 2 + dn_size;
        crt = crt->next;
    }

    ssl->out_msglen  = p - buf;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE_REQUEST;
    ssl->out_msg[4 + ct_len + sa_len] = (uint8_t)( total_dn_size  >> 8 );
    ssl->out_msg[5 + ct_len + sa_len] = (uint8_t)( total_dn_size       );

    ret = ssl_write_record( ssl );

    return( ret );
}

static int ssl_write_server_key_exchange( ssl_context *ssl )
{
    int ret;
    size_t n = 0;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    uint8_t *p = ssl->out_msg + 4;
    uint8_t *dig_signed = p;
    size_t dig_signed_len = 0, len;
    ((void) dig_signed);
    ((void) dig_signed_len);

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA)
    {
        /*
         * Ephemeral ECDH parameters:
         *
         * struct {
         *     ECParameters curve_params;
         *     ECPoint      public;
         * } ServerECDHParams;
         */
        const ecp_curve_info **curve = NULL;
        const ecp_group_id *gid;

        /* Match our preference list against the offered curves */
        for( gid = ssl->curve_list; *gid != POLARSSL_ECP_DP_NONE; gid++ )
            for( curve = ssl->handshake->curves; *curve != NULL; curve++ )
                if( (*curve)->grp_id == *gid )
                    goto curve_matching_done;

curve_matching_done:
        if( *curve == NULL )
        {
            return( POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN );
        }

        if( ( ret = ecp_use_known_dp( &ssl->handshake->ecdh_ctx.grp,
                                       (*curve)->grp_id ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = ecdh_make_params( &ssl->handshake->ecdh_ctx, &len,
                                      p, SSL_MAX_CONTENT_LEN - n,
                                      ssl->f_rng, ssl->p_rng ) ) != 0 )
        {
            return( ret );
        }

        dig_signed = p;
        dig_signed_len = len;

        p += len;
        n += len;
    }

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA)
    {
        size_t signature_len = 0;
        uint32_t hashlen = 0;
        uint8_t hash[64];
        md_type_t md_alg = POLARSSL_MD_NONE;

        if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
        {
            md_alg = ssl_md_alg_from_hash( ssl->handshake->sig_alg );

            if( md_alg == POLARSSL_MD_NONE )
            {
                return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
            }
        }
        else {
            md_alg = POLARSSL_MD_NONE;
        }

        /*
         * Compute the hash to be signed
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
            if( ( ret = md_init_ctx( &ctx, md_info_from_type(md_alg) ) ) != 0 )
            {
                return( ret );
            }

            md_starts( &ctx );
            md_update( &ctx, ssl->handshake->randbytes, 64 );
            md_update( &ctx, dig_signed, dig_signed_len );
            md_finish( &ctx, hash );

            if( ( ret = md_free_ctx( &ctx ) ) != 0 )
            {
                return( ret );
            }

        }
        else
        {
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        /*
         * Make the signature
         */
        if( ssl_own_key( ssl ) == NULL )
        {
            return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );
        }

        if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
        {
            *(p++) = ssl->handshake->sig_alg;
            *(p++) = ssl_sig_from_pk( ssl_own_key( ssl ) );

            n += 2;
        }

        if( ( ret = pk_sign( ssl_own_key( ssl ), md_alg, hash, hashlen,
                        p + 2 , &signature_len,
                        ssl->f_rng, ssl->p_rng ) ) != 0 )
        {
            return( ret );
        }

        *(p++) = (uint8_t)( signature_len >> 8 );
        *(p++) = (uint8_t)( signature_len      );
        n += 2;

        p += signature_len;
        n += signature_len;
    }

    ssl->out_msglen  = 4 + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_KEY_EXCHANGE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

static int ssl_write_server_hello_done( ssl_context *ssl )
{
    int ret;

    ssl->out_msglen  = 4;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO_DONE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

static int ssl_parse_client_key_exchange( ssl_context *ssl )
{
    int ret;
    const ssl_ciphersuite_t *ciphersuite_info;

    ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ssl->in_msg[0] != SSL_HS_CLIENT_KEY_EXCHANGE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA || ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_RSA)
    {
        if( ( ret = ecdh_read_public( &ssl->handshake->ecdh_ctx,
                        ssl->in_msg + 4, ssl->in_hslen - 4 ) ) != 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP );
        }

        if( ( ret = ecdh_calc_secret( &ssl->handshake->ecdh_ctx,
                                      &ssl->handshake->pmslen,
                                       ssl->handshake->premaster,
                                       POLARSSL_MPI_MAX_SIZE,
                                       ssl->f_rng, ssl->p_rng ) ) != 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS );
        }
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
    {
        return( ret );
    }

    ssl->state++;

    return( 0 );
}

int ssl_parse_certificate_verify( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t sa_len, sig_len;
    uint8_t hash[48];
    uint8_t *hash_start = hash;
    size_t hashlen;
    pk_type_t pk_alg;
    md_type_t md_alg;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    if( ssl->session_negotiate->peer_cert == NULL )
    {
        ssl->state++;
        return( 0 );
    }

    ssl->handshake->calc_verify( ssl, hash );

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    ssl->state++;

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    if( ssl->in_msg[0] != SSL_HS_CERTIFICATE_VERIFY )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   sig alg (TLS 1.2 only)
     *    4+n .  5+n  signature length (n = sa_len)
     *    6+n . 6+n+m signature (m = sig_len)
     */
    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        sa_len = 2;

        /*
         * Hash
         */
        if( ssl->in_msg[4] != ssl->handshake->verify_sig_alg )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }

        md_alg = ssl_md_alg_from_hash( ssl->handshake->verify_sig_alg );

        /* Info from md_alg will be used instead */
        hashlen = 0;

        /*
         * Signature
         */
        if( ( pk_alg = ssl_pk_alg_from_sig( ssl->in_msg[5] ) )
                        == POLARSSL_PK_NONE )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }

        /*
         * Check the certificate's key type matches the signature alg
         */
        if( ! pk_can_do( &ssl->session_negotiate->peer_cert->pk, pk_alg ) )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
        }
    }
    else
    {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    sig_len = ( ssl->in_msg[4 + sa_len] << 8 ) | ssl->in_msg[5 + sa_len];

    if( sa_len + sig_len + 6 != ssl->in_hslen )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    if( ( ret = pk_verify( &ssl->session_negotiate->peer_cert->pk,
                           md_alg, hash_start, hashlen,
                           ssl->in_msg + 6 + sa_len, sig_len ) ) != 0 )
    {
        return( ret );
    }

    return( ret );
}

/*
 * SSL handshake -- server side -- single step
 */
int ssl_handshake_server_step( ssl_context *ssl )
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
         *  <==   ClientHello
         */
        case SSL_CLIENT_HELLO:
            ret = ssl_parse_client_hello( ssl );
            break;

        /*
         *  ==>   ServerHello
         *        Certificate
         *      ( ServerKeyExchange  )
         *      ( CertificateRequest )
         *        ServerHelloDone
         */
        case SSL_SERVER_HELLO:
            ret = ssl_write_server_hello( ssl );
            break;

        case SSL_SERVER_CERTIFICATE:
            ret = ssl_write_certificate( ssl );
            break;

        case SSL_SERVER_KEY_EXCHANGE:
            ret = ssl_write_server_key_exchange( ssl );
            break;

        case SSL_CERTIFICATE_REQUEST:
            ret = ssl_write_certificate_request( ssl );
            break;

        case SSL_SERVER_HELLO_DONE:
            ret = ssl_write_server_hello_done( ssl );
            break;

        /*
         *  <== ( Certificate/Alert  )
         *        ClientKeyExchange
         *      ( CertificateVerify  )
         *        ChangeCipherSpec
         *        Finished
         */
        case SSL_CLIENT_CERTIFICATE:
            ret = ssl_parse_certificate( ssl );
            break;

        case SSL_CLIENT_KEY_EXCHANGE:
            ret = ssl_parse_client_key_exchange( ssl );
            break;

        case SSL_CERTIFICATE_VERIFY:
            ret = ssl_parse_certificate_verify( ssl );
            break;

        case SSL_CLIENT_CHANGE_CIPHER_SPEC:
            ret = ssl_parse_change_cipher_spec( ssl );
            break;

        case SSL_CLIENT_FINISHED:
            ret = ssl_parse_finished( ssl );
            break;

        /*
         *  ==> ( NewSessionTicket )
         *        ChangeCipherSpec
         *        Finished
         */
        case SSL_SERVER_CHANGE_CIPHER_SPEC:
            ret = ssl_write_change_cipher_spec( ssl );
            break;

        case SSL_SERVER_FINISHED:
            ret = ssl_write_finished( ssl );
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
#endif /* POLARSSL_SSL_SRV_C */
