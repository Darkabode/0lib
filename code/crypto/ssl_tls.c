#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_SSL_TLS_C)

#include "ssl.h"

#if defined(POLARSSL_X509_CRT_PARSE_C) && \
    defined(POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE)
#include "oid.h"
#endif

#include <stdlib.h>

#if defined(_MSC_VER) && !defined _stricmp && !defined(EFIX64) && \
    !defined(EFI32)
#define _stricmp _stricmp
#endif

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static uint32_t mfl_code_to_length[SSL_MAX_FRAG_LEN_INVALID] =
{
    SSL_MAX_CONTENT_LEN,    /* SSL_MAX_FRAG_LEN_NONE */
    512,                    /* SSL_MAX_FRAG_LEN_512  */
    1024,                   /* SSL_MAX_FRAG_LEN_1024 */
    2048,                   /* SSL_MAX_FRAG_LEN_2048 */
    4096,                   /* SSL_MAX_FRAG_LEN_4096 */
};
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

static int ssl_session_copy( ssl_session *dst, const ssl_session *src )
{
    ssl_session_free( dst );
    __movsb( dst, src, sizeof( ssl_session ) );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    if( src->peer_cert != NULL )
    {
        int ret;

        dst->peer_cert = (x509_crt *) memory_alloc( sizeof(x509_crt) );
        if( dst->peer_cert == NULL )
            return( POLARSSL_ERR_SSL_MALLOC_FAILED );

        x509_crt_init( dst->peer_cert );

        if( ( ret = x509_crt_parse_der( dst->peer_cert, src->peer_cert->raw.p,
                                    src->peer_cert->raw.len ) != 0 ) )
        {
            memory_free( dst->peer_cert );
            dst->peer_cert = NULL;
            return( ret );
        }
    }
#endif /* POLARSSL_X509_CRT_PARSE_C */

    return( 0 );
}

/*
 * Key material generation
 */

int tls_prf_sha256( const uint8_t *secret, size_t slen,
                           const char *label,
                           const uint8_t *random, size_t rlen,
                           uint8_t *dstbuf, size_t dlen )
{
    size_t nb;
    size_t i, j, k;
    uint8_t tmp[128];
    uint8_t h_i[32];

    if( sizeof( tmp ) < 32 + strlen( label ) + rlen )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    nb = strlen( label );
    __movsb( tmp + 32, label, nb );
    __movsb( tmp + 32 + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    sha256_hmac( secret, slen, tmp + 32, nb, tmp, 0 );

    for( i = 0; i < dlen; i += 32 )
    {
        sha256_hmac( secret, slen, tmp, 32 + nb, h_i, 0 );
        sha256_hmac( secret, slen, tmp, 32,      tmp, 0 );

        k = ( i + 32 > dlen ) ? dlen % 32 : 32;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    __stosb( tmp, 0, sizeof( tmp ) );
    __stosb( h_i, 0, sizeof( h_i ) );

    return( 0 );
}

int tls_prf_sha384( const uint8_t *secret, size_t slen,
                           const char *label,
                           const uint8_t *random, size_t rlen,
                           uint8_t *dstbuf, size_t dlen )
{
    size_t nb;
    size_t i, j, k;
    uint8_t tmp[128];
    uint8_t h_i[48];

    if( sizeof( tmp ) < 48 + strlen( label ) + rlen )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    nb = strlen( label );
    __movsb( tmp + 48, label, nb );
    __movsb( tmp + 48 + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    sha512_hmac( secret, slen, tmp + 48, nb, tmp, 1 );

    for( i = 0; i < dlen; i += 48 )
    {
        sha512_hmac( secret, slen, tmp, 48 + nb, h_i, 1 );
        sha512_hmac( secret, slen, tmp, 48,      tmp, 1 );

        k = ( i + 48 > dlen ) ? dlen % 48 : 48;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    __stosb( tmp, 0, sizeof( tmp ) );
    __stosb( h_i, 0, sizeof( h_i ) );

    return( 0 );
}

static void ssl_update_checksum_start(ssl_context *, const uint8_t *, size_t);


static void ssl_update_checksum_sha256(ssl_context *, const uint8_t *, size_t);
static void ssl_calc_verify_tls_sha256(ssl_context *,uint8_t *);
static void ssl_calc_finished_tls_sha256(ssl_context *,uint8_t *,int);
static void ssl_update_checksum_sha384(ssl_context *, const uint8_t *, size_t);
static void ssl_calc_verify_tls_sha384(ssl_context *,uint8_t *);
static void ssl_calc_finished_tls_sha384(ssl_context *,uint8_t *,int);

int ssl_derive_keys( ssl_context *ssl )
{
    int ret = 0;
    uint8_t tmp[64];
    uint8_t keyblk[256];
    uint8_t *key1;
    uint8_t *key2;
    uint8_t *mac_enc;
    uint8_t *mac_dec;
    size_t iv_copy_len;
    const cipher_info_t *cipher_info;
    const md_info_t *md_info;

    ssl_session *session = ssl->session_negotiate;
    ssl_transform *transform = ssl->transform_negotiate;
    ssl_handshake_params *handshake = ssl->handshake;

    cipher_info = cipher_info_from_type( transform->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = md_info_from_type( transform->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    /*
     * Set appropriate PRF function and other SSL / TLS / TLS1.2 functions
     */
    if( ssl->minor_ver == SSL_MINOR_VERSION_3 &&
        transform->ciphersuite_info->mac == POLARSSL_MD_SHA384 )
    {
        handshake->tls_prf = tls_prf_sha384;
        handshake->calc_verify = ssl_calc_verify_tls_sha384;
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
    }
    else if( ssl->minor_ver == SSL_MINOR_VERSION_3 ) {
        handshake->tls_prf = tls_prf_sha256;
        handshake->calc_verify = ssl_calc_verify_tls_sha256;
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    /*
     * TLSv1+:
     *   master = PRF( premaster, "master secret", randbytes )[0..47]
     */
    if( handshake->resume == 0 ) {
        handshake->tls_prf( handshake->premaster, handshake->pmslen,
                            "master secret",
                            handshake->randbytes, 64, session->master, 48 );

        __stosb( handshake->premaster, 0, sizeof( handshake->premaster ) );
    }

    /*
     * Swap the client and server random values.
     */
    __movsb( tmp, handshake->randbytes, 64 );
    __movsb( handshake->randbytes, tmp + 32, 32 );
    __movsb( handshake->randbytes + 32, tmp, 32 );
    __stosb( tmp, 0, sizeof( tmp ) );

    /*
     *  TLSv1:
     *    key block = PRF( master, "key expansion", randbytes )
     */
    handshake->tls_prf( session->master, 48, "key expansion",
                        handshake->randbytes, 64, keyblk, 256 );

    __stosb( handshake->randbytes, 0, sizeof( handshake->randbytes ) );

    /*
     * Determine the appropriate key, IV and MAC length.
     */

    /* Initialize HMAC contexts */
    if ((ret = md_init_ctx(&transform->md_ctx_enc, md_info)) != 0 || (ret = md_init_ctx(&transform->md_ctx_dec, md_info)) != 0) {
        return ret;
    }

    /* Get MAC length */
    transform->maclen = md_get_size(md_info);

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
    /*
    * If HMAC is to be truncated, we shall keep the leftmost bytes,
    * (rfc 6066 page 13 or rfc 2104 section 4),
    * so we only need to adjust the length here.
    */
    if (session->trunc_hmac == SSL_TRUNC_HMAC_ENABLED)
        transform->maclen = SSL_TRUNCATED_HMAC_LEN;
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

    /* IV length */
    transform->ivlen = cipher_info->iv_size;

    /* Minimum length */
    /*
    * GenericBlockCipher:
    * first multiple of blocklen greater than maclen
    * + IV except for SSL3 and TLS 1.0
    */
    transform->minlen = transform->maclen + cipher_info->block_size - transform->maclen % cipher_info->block_size;
    if (ssl->minor_ver == SSL_MINOR_VERSION_2 || ssl->minor_ver == SSL_MINOR_VERSION_3) {
        transform->minlen += transform->ivlen;
    }
    else {
        return POLARSSL_ERR_SSL_INTERNAL_ERROR;
    }

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */
    if( ssl->endpoint == SSL_IS_CLIENT )
    {
        key1 = keyblk + transform->maclen * 2;
        key2 = keyblk + transform->maclen * 2 + transform->keylen;

        mac_enc = keyblk;
        mac_dec = keyblk + transform->maclen;

        /*
         * This is not used in TLS v1.1.
         */
        iv_copy_len = ( transform->fixed_ivlen ) ?
                            transform->fixed_ivlen : transform->ivlen;
        __movsb( transform->iv_enc, key2 + transform->keylen,  iv_copy_len );
        __movsb( transform->iv_dec, key2 + transform->keylen + iv_copy_len,
                iv_copy_len );
    }
    else
    {
        key1 = keyblk + transform->maclen * 2 + transform->keylen;
        key2 = keyblk + transform->maclen * 2;

        mac_enc = keyblk + transform->maclen;
        mac_dec = keyblk;

        /*
         * This is not used in TLS v1.1.
         */
        iv_copy_len = ( transform->fixed_ivlen ) ?
                            transform->fixed_ivlen : transform->ivlen;
        __movsb( transform->iv_dec, key1 + transform->keylen,  iv_copy_len );
        __movsb( transform->iv_enc, key1 + transform->keylen + iv_copy_len,
                iv_copy_len );
    }

    if( ssl->minor_ver >= SSL_MINOR_VERSION_1 )
    {
        md_hmac_starts( &transform->md_ctx_enc, mac_enc, transform->maclen );
        md_hmac_starts( &transform->md_ctx_dec, mac_dec, transform->maclen );
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ( ret = cipher_init_ctx( &transform->cipher_ctx_enc,
                                 cipher_info ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = cipher_init_ctx( &transform->cipher_ctx_dec,
                                 cipher_info ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = cipher_setkey( &transform->cipher_ctx_enc, key1, cipher_info->key_length, POLARSSL_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = cipher_setkey( &transform->cipher_ctx_dec, key2,
                               cipher_info->key_length,
                               POLARSSL_DECRYPT ) ) != 0 )
    {
        return( ret );
    }

    if( cipher_info->mode == POLARSSL_MODE_CBC )
    {
        if( ( ret = cipher_set_padding_mode( &transform->cipher_ctx_enc,
                                             POLARSSL_PADDING_NONE ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = cipher_set_padding_mode( &transform->cipher_ctx_dec,
                                             POLARSSL_PADDING_NONE ) ) != 0 )
        {
            return( ret );
        }
    }

    __stosb( keyblk, 0, sizeof( keyblk ) );

    return( 0 );
}

void ssl_calc_verify_tls_sha256( ssl_context *ssl, uint8_t hash[32] )
{
    sha256_context sha256;

    __movsb( &sha256, &ssl->handshake->fin_sha256, sizeof(sha256_context) );
    sha256_finish( &sha256, hash );

    return;
}

void ssl_calc_verify_tls_sha384( ssl_context *ssl, uint8_t hash[48] )
{
    sha512_context sha512;

    __movsb( &sha512, &ssl->handshake->fin_sha512, sizeof(sha512_context) );
    sha512_finish( &sha512, hash );

    return;
}

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( ssl_context *ssl )
{
    size_t i;

    /*
     * Add MAC before encrypt, except for GCM
     */
    if (ssl->minor_ver >= SSL_MINOR_VERSION_1) {
        md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_ctr, 13 );
        md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_msg, ssl->out_msglen );
        md_hmac_finish( &ssl->transform_out->md_ctx_enc, ssl->out_msg + ssl->out_msglen );
        md_hmac_reset( &ssl->transform_out->md_ctx_enc );
    }
    else {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    ssl->out_msglen += ssl->transform_out->maclen;

    /*
     * Encrypt
     */
    if( ssl->transform_out->cipher_ctx_enc.cipher_info->mode == POLARSSL_MODE_CBC ) {
        int ret;
        uint8_t *enc_msg;
        size_t enc_msglen, padlen, olen = 0;

        padlen = ssl->transform_out->ivlen - ( ssl->out_msglen + 1 ) % ssl->transform_out->ivlen;
        if (padlen == ssl->transform_out->ivlen) {
            padlen = 0;
        }

        for (i = 0; i <= padlen; i++) {
            ssl->out_msg[ssl->out_msglen + i] = (uint8_t)padlen;
        }

        ssl->out_msglen += padlen + 1;

        enc_msglen = ssl->out_msglen;
        enc_msg = ssl->out_msg;

        /*
         * Prepend per-record IV for block cipher in TLS v1.1 and up as per
         * Method 1 (6.2.3.2. in RFC4346 and RFC5246)
         */
        if( ssl->minor_ver >= SSL_MINOR_VERSION_2 ) {
            /*
             * Generate IV
             */
            int ret = ssl->f_rng( ssl->p_rng, ssl->transform_out->iv_enc, ssl->transform_out->ivlen );
            if( ret != 0 )
                return( ret );

            __movsb( ssl->out_iv, ssl->transform_out->iv_enc, ssl->transform_out->ivlen );

            /*
             * Fix pointer positions and message length with added IV
             */
            enc_msg = ssl->out_msg;
            enc_msglen = ssl->out_msglen;
            ssl->out_msglen += ssl->transform_out->ivlen;
        }

        if( ( ret = cipher_reset( &ssl->transform_out->cipher_ctx_enc ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = cipher_set_iv( &ssl->transform_out->cipher_ctx_enc,
                                   ssl->transform_out->iv_enc,
                                   ssl->transform_out->ivlen ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = cipher_update( &ssl->transform_out->cipher_ctx_enc,
                                   enc_msg, enc_msglen, enc_msg,
                                   &olen ) ) != 0 )
        {
            return( ret );
        }

        enc_msglen -= olen;

        if( ( ret = cipher_finish( &ssl->transform_out->cipher_ctx_enc,
                                   enc_msg + olen, &olen ) ) != 0 )
        {
            return( ret );
        }

        if( enc_msglen != olen )
        {
            return( POLARSSL_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
    {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    for( i = 8; i > 0; i-- )
        if( ++ssl->out_ctr[i - 1] != 0 )
            break;

    /* The loops goes to its end iff the counter is wrapping */
    if( i == 0 )
    {
        return( POLARSSL_ERR_SSL_COUNTER_WRAPPING );
    }

    return( 0 );
}

#define POLARSSL_SSL_MAX_MAC_SIZE   48

static int ssl_decrypt_buf( ssl_context *ssl )
{
    size_t i;
    size_t padlen = 0, correct = 1;

    if( ssl->in_msglen < ssl->transform_in->minlen )
    {
        return( POLARSSL_ERR_SSL_INVALID_MAC );
    }
    if( ssl->transform_in->cipher_ctx_dec.cipher_info->mode ==
                                                       POLARSSL_MODE_CBC )
    {
        /*
         * Decrypt and check the padding
         */
        int ret;
        uint8_t *dec_msg;
        uint8_t *dec_msg_result;
        size_t dec_msglen;
        size_t minlen = 0;
        size_t olen = 0;

        /*
         * Check immediate ciphertext sanity
         */
        if( ssl->in_msglen % ssl->transform_in->ivlen != 0 )
        {
            return( POLARSSL_ERR_SSL_INVALID_MAC );
        }

        if( ssl->minor_ver >= SSL_MINOR_VERSION_2 )
            minlen += ssl->transform_in->ivlen;

        if( ssl->in_msglen < minlen + ssl->transform_in->ivlen ||
            ssl->in_msglen < minlen + ssl->transform_in->maclen + 1 )
        {
            return( POLARSSL_ERR_SSL_INVALID_MAC );
        }

        dec_msglen = ssl->in_msglen;
        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;

        /*
         * Initialize for prepended IV for block cipher in TLS v1.1 and up
         */
        if( ssl->minor_ver >= SSL_MINOR_VERSION_2 )
        {
            dec_msglen -= ssl->transform_in->ivlen;
            ssl->in_msglen -= ssl->transform_in->ivlen;

            for( i = 0; i < ssl->transform_in->ivlen; i++ )
                ssl->transform_in->iv_dec[i] = ssl->in_iv[i];
        }

        if( ( ret = cipher_reset( &ssl->transform_in->cipher_ctx_dec ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = cipher_set_iv( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen ) ) != 0 )
        {
            return( ret );
        }

        if( ( ret = cipher_update( &ssl->transform_in->cipher_ctx_dec,
                                   dec_msg, dec_msglen, dec_msg_result,
                                   &olen ) ) != 0 )
        {
            return( ret );
        }

        dec_msglen -= olen;
        if( ( ret = cipher_finish( &ssl->transform_in->cipher_ctx_dec,
                                   dec_msg_result + olen, &olen ) ) != 0 )
        {
            return( ret );
        }

        if( dec_msglen != olen )
        {
            return( POLARSSL_ERR_SSL_INTERNAL_ERROR );
        }

        padlen = 1 + ssl->in_msg[ssl->in_msglen - 1];

        if( ssl->in_msglen < ssl->transform_in->maclen + padlen )
        {
            padlen = 0;
            correct = 0;
        }
        if( ssl->minor_ver > SSL_MINOR_VERSION_0 )
        {
            /*
             * TLSv1+: always check the padding up to the first failure
             * and fake check up to 256 bytes of padding
             */
            size_t pad_count = 0, real_count = 1;
            size_t padding_idx = ssl->in_msglen - padlen - 1;

            /*
             * Padding is guaranteed to be incorrect if:
             *   1. padlen >= ssl->in_msglen
             *
             *   2. padding_idx >= SSL_MAX_CONTENT_LEN +
             *                     ssl->transform_in->maclen
             *
             * In both cases we reset padding_idx to a safe value (0) to
             * prevent out-of-buffer reads.
             */
            correct &= ( ssl->in_msglen >= padlen + 1 );
            correct &= ( padding_idx < SSL_MAX_CONTENT_LEN +
                                       ssl->transform_in->maclen );

            padding_idx *= correct;

            for( i = 1; i <= 256; i++ )
            {
                real_count &= ( i <= padlen );
                pad_count += real_count *
                             ( ssl->in_msg[padding_idx + i] == padlen - 1 );
            }

            correct &= ( pad_count == padlen ); /* Only 1 on correct padding */

            padlen &= correct * 0x1FF;
        }
        else
        {
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }
    }
    else
    {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    /*
     * Always compute the MAC (RFC4346, CBCTIME), except for GCM of course
     */
    uint8_t tmp[POLARSSL_SSL_MAX_MAC_SIZE];

    ssl->in_msglen -= ( ssl->transform_in->maclen + padlen );

    ssl->in_hdr[3] = (uint8_t)( ssl->in_msglen >> 8 );
    ssl->in_hdr[4] = (uint8_t)( ssl->in_msglen      );

    __movsb( tmp, ssl->in_msg + ssl->in_msglen, ssl->transform_in->maclen );
    if( ssl->minor_ver > SSL_MINOR_VERSION_0 )
    {
        /*
            * Process MAC and always update for padlen afterwards to make
            * total time independent of padlen
            *
            * extra_run compensates MAC check for padlen
            *
            * Known timing attacks:
            *  - Lucky Thirteen (http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
            *
            * We use ( ( Lx + 8 ) / 64 ) to handle 'negative Lx' values
            * correctly. (We round down instead of up, so -56 is the correct
            * value for our calculations instead of -55)
            */
        size_t j, extra_run = 0;
        extra_run = ( 13 + ssl->in_msglen + padlen + 8 ) / 64 -
                    ( 13 + ssl->in_msglen          + 8 ) / 64;

        extra_run &= correct * 0xFF;

        md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_ctr, 13 );
        md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_msg,
                            ssl->in_msglen );
        md_hmac_finish( &ssl->transform_in->md_ctx_dec,
                            ssl->in_msg + ssl->in_msglen );
        for( j = 0; j < extra_run; j++ )
            md_process( &ssl->transform_in->md_ctx_dec, ssl->in_msg );

        md_hmac_reset( &ssl->transform_in->md_ctx_dec );
    }
    else
    {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( safer_memcmp( tmp, ssl->in_msg + ssl->in_msglen,
                        ssl->transform_in->maclen ) != 0 )
    {
        correct = 0;
    }

    /*
        * Finally check the correct flag
        */
    if( correct == 0 )
        return( POLARSSL_ERR_SSL_INVALID_MAC );

    if( ssl->in_msglen == 0 )
    {
        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if( ssl->nb_zero > 3 )
        {
            return( POLARSSL_ERR_SSL_INVALID_MAC );
        }
    }
    else
        ssl->nb_zero = 0;

    for( i = 8; i > 0; i-- )
        if( ++ssl->in_ctr[i - 1] != 0 )
            break;

    /* The loops goes to its end iff the counter is wrapping */
    if( i == 0 )
    {
        return( POLARSSL_ERR_SSL_COUNTER_WRAPPING );
    }

    return( 0 );
}

/*
 * Fill the input message buffer
 */
int ssl_fetch_input( ssl_context *ssl, size_t nb_want )
{
    int ret;
    size_t len;

    if( nb_want > SSL_BUFFER_LEN - 8 )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    while( ssl->in_left < nb_want )
    {
        len = nb_want - ssl->in_left;
        ret = ssl->f_recv( ssl->p_recv, ssl->in_hdr + ssl->in_left, len );

        if( ret == 0 )
            return( POLARSSL_ERR_SSL_CONN_EOF );

        if( ret < 0 )
            return( ret );

        ssl->in_left += ret;
    }

    return( 0 );
}

/*
 * Flush any data not yet written
 */
int ssl_flush_output( ssl_context *ssl )
{
    int ret;
    uint8_t *buf;

    while( ssl->out_left > 0 )
    {
        buf = ssl->out_hdr + 5 + ssl->out_msglen - ssl->out_left;
        ret = ssl->f_send( ssl->p_send, buf, ssl->out_left );

        if( ret <= 0 )
            return( ret );

        ssl->out_left -= ret;
    }

    return( 0 );
}

/*
 * Record layer functions
 */
int ssl_write_record( ssl_context *ssl )
{
    int ret, done = 0;
    size_t len = ssl->out_msglen;

    if( ssl->out_msgtype == SSL_MSG_HANDSHAKE )
    {
        ssl->out_msg[1] = (uint8_t)( ( len - 4 ) >> 16 );
        ssl->out_msg[2] = (uint8_t)( ( len - 4 ) >>  8 );
        ssl->out_msg[3] = (uint8_t)( ( len - 4 )       );

        if( ssl->out_msg[0] != SSL_HS_HELLO_REQUEST )
            ssl->handshake->update_checksum( ssl, ssl->out_msg, len );
    }

    if( !done )
    {
        ssl->out_hdr[0] = (uint8_t) ssl->out_msgtype;
        ssl->out_hdr[1] = (uint8_t) ssl->major_ver;
        ssl->out_hdr[2] = (uint8_t) ssl->minor_ver;
        ssl->out_hdr[3] = (uint8_t)( len >> 8 );
        ssl->out_hdr[4] = (uint8_t)( len      );

        if( ssl->transform_out != NULL )
        {
            if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
            {
                return( ret );
            }

            len = ssl->out_msglen;
            ssl->out_hdr[3] = (uint8_t)( len >> 8 );
            ssl->out_hdr[4] = (uint8_t)( len      );
        }

        ssl->out_left = 5 + ssl->out_msglen;
    }

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int ssl_read_record( ssl_context *ssl )
{
    int ret, done = 0;

    if( ssl->in_hslen != 0 &&
        ssl->in_hslen < ssl->in_msglen )
    {
        /*
         * Get next Handshake message in the current record
         */
        ssl->in_msglen -= ssl->in_hslen;

        memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                 ssl->in_msglen );

        ssl->in_hslen  = 4;
        ssl->in_hslen += ( ssl->in_msg[2] << 8 ) | ssl->in_msg[3];

        if( ssl->in_msglen < 4 || ssl->in_msg[1] != 0 )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->in_msglen < ssl->in_hslen )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->state != SSL_HANDSHAKE_OVER )
            ssl->handshake->update_checksum( ssl, ssl->in_msg, ssl->in_hslen );

        return( 0 );
    }

    ssl->in_hslen = 0;

    /*
     * Read the record header and validate it
     */
    if( ( ret = ssl_fetch_input( ssl, 5 ) ) != 0 )
    {
        return( ret );
    }

    ssl->in_msgtype =  ssl->in_hdr[0];
    ssl->in_msglen = ( ssl->in_hdr[3] << 8 ) | ssl->in_hdr[4];

    if( ssl->in_hdr[1] != ssl->major_ver )
    {
        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    if( ssl->in_hdr[2] > ssl->max_minor_ver )
    {
        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    /* Sanity check (outer boundaries) */
    if( ssl->in_msglen < 1 || ssl->in_msglen > SSL_BUFFER_LEN - 13 )
    {
        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    /*
     * Make sure the message length is acceptable for the current transform
     * and protocol version.
     */
    if( ssl->transform_in == NULL )
    {
        if( ssl->in_msglen > SSL_MAX_CONTENT_LEN )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }
    else
    {
        if( ssl->in_msglen < ssl->transform_in->minlen )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        /*
         * TLS encrypted messages can have up to 256 bytes of padding
         */
        if( ssl->minor_ver >= SSL_MINOR_VERSION_1 &&
            ssl->in_msglen > ssl->transform_in->minlen +
                             SSL_MAX_CONTENT_LEN + 256 )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }

    /*
     * Read and optionally decrypt the message contents
     */
    if( ( ret = ssl_fetch_input( ssl, 5 + ssl->in_msglen ) ) != 0 )
    {
        return( ret );
    }

    if( !done && ssl->transform_in != NULL )
    {
        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
        {
#if defined(POLARSSL_SSL_ALERT_MESSAGES)
            if( ret == POLARSSL_ERR_SSL_INVALID_MAC )
            {
                ssl_send_alert_message( ssl,
                                        SSL_ALERT_LEVEL_FATAL,
                                        SSL_ALERT_MSG_BAD_RECORD_MAC );
            }
#endif
            return( ret );
        }

        if( ssl->in_msglen > SSL_MAX_CONTENT_LEN )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE &&
        ssl->in_msgtype != SSL_MSG_ALERT &&
        ssl->in_msgtype != SSL_MSG_CHANGE_CIPHER_SPEC &&
        ssl->in_msgtype != SSL_MSG_APPLICATION_DATA )
    {
        if( ( ret = ssl_send_alert_message( ssl,
                        SSL_ALERT_LEVEL_FATAL,
                        SSL_ALERT_MSG_UNEXPECTED_MESSAGE ) ) != 0 )
        {
            return( ret );
        }

        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    if( ssl->in_msgtype == SSL_MSG_HANDSHAKE )
    {
        ssl->in_hslen  = 4;
        ssl->in_hslen += ( ssl->in_msg[2] << 8 ) | ssl->in_msg[3];

        /*
         * Additional checks to validate the handshake header
         */
        if( ssl->in_msglen < 4 || ssl->in_msg[1] != 0 )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->in_msglen < ssl->in_hslen )
        {
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->state != SSL_HANDSHAKE_OVER )
            ssl->handshake->update_checksum( ssl, ssl->in_msg, ssl->in_hslen );
    }

    if( ssl->in_msgtype == SSL_MSG_ALERT )
    {
        /*
         * Ignore non-fatal alerts, except close_notify
         */
        if( ssl->in_msg[0] == SSL_ALERT_LEVEL_FATAL )
        {
            /**
             * Subtract from error code as ssl->in_msg[1] is 7-bit positive
             * error identifier.
             */
            return( POLARSSL_ERR_SSL_FATAL_ALERT_MESSAGE );
        }

        if( ssl->in_msg[0] == SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            return( POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY );
        }
    }

    ssl->in_left = 0;

    return( 0 );
}

int ssl_send_fatal_handshake_failure( ssl_context *ssl )
{
    int ret;

    if( ( ret = ssl_send_alert_message( ssl,
                    SSL_ALERT_LEVEL_FATAL,
                    SSL_ALERT_MSG_HANDSHAKE_FAILURE ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int ssl_send_alert_message( ssl_context *ssl,
                            uint8_t level,
                            uint8_t message )
{
    int ret;

    ssl->out_msgtype = SSL_MSG_ALERT;
    ssl->out_msglen = 2;
    ssl->out_msg[0] = level;
    ssl->out_msg[1] = message;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Handshake functions
 */
int ssl_write_certificate( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const x509_crt *crt;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    if( ssl->endpoint == SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 )
        {
            ssl->state++;
            return( 0 );
        }
    }
    else /* SSL_IS_SERVER */
    {
        if( ssl_own_cert( ssl ) == NULL )
        {
            return( POLARSSL_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    i = 7;
    crt = ssl_own_cert( ssl );

    while( crt != NULL )
    {
        n = crt->raw.len;
        if( n > SSL_MAX_CONTENT_LEN - 3 - i )
        {
            return( POLARSSL_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        ssl->out_msg[i    ] = (uint8_t)( n >> 16 );
        ssl->out_msg[i + 1] = (uint8_t)( n >>  8 );
        ssl->out_msg[i + 2] = (uint8_t)( n       );

        i += 3; __movsb( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;
    }

    ssl->out_msg[4]  = (uint8_t)( ( i - 7 ) >> 16 );
    ssl->out_msg[5]  = (uint8_t)( ( i - 7 ) >>  8 );
    ssl->out_msg[6]  = (uint8_t)( ( i - 7 )       );

    ssl->out_msglen  = i;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( ret );
}

int ssl_parse_certificate( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    if( ssl->endpoint == SSL_IS_SERVER &&
        ( ssl->authmode == SSL_VERIFY_NONE) )
    {
        ssl->session_negotiate->verify_result = BADCERT_SKIP_VERIFY;
        ssl->state++;
        return( 0 );
    }

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    ssl->state++;

    if( ssl->endpoint  == SSL_IS_SERVER &&
        ssl->minor_ver != SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_hslen   == 7                    &&
            ssl->in_msgtype == SSL_MSG_HANDSHAKE    &&
            ssl->in_msg[0]  == SSL_HS_CERTIFICATE   &&
            memcmp( ssl->in_msg + 4, "\0\0\0", 3 ) == 0 )
        {
            ssl->session_negotiate->verify_result = BADCERT_MISSING;
            if( ssl->authmode == SSL_VERIFY_REQUIRED )
                return( POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE );
            else
                return( 0 );
        }
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != SSL_HS_CERTIFICATE || ssl->in_hslen < 10 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /*
     * Same message structure as in ssl_write_certificate()
     */
    n = ( ssl->in_msg[5] << 8 ) | ssl->in_msg[6];

    if( ssl->in_msg[4] != 0 || ssl->in_hslen != 7 + n )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        x509_crt_free( ssl->session_negotiate->peer_cert );
        memory_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert = (x509_crt *) memory_alloc(
                    sizeof( x509_crt ) ) ) == NULL )
    {
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    x509_crt_init( ssl->session_negotiate->peer_cert );

    i = 7;

    while( i < ssl->in_hslen )
    {
        if( ssl->in_msg[i] != 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( (uint32_t) ssl->in_msg[i + 1] << 8 )
            | (uint32_t) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                  ssl->in_msg + i, n );
        if( ret != 0 )
        {
            return( ret );
        }

        i += n;
    }

    /*
     * On client, make sure the server cert doesn't change during renego to
     * avoid "triple handshake" attack: https://secure-resumption.com/
     */
    if( ssl->endpoint == SSL_IS_CLIENT &&
        ssl->renegotiation == SSL_RENEGOTIATION )
    {
        if( ssl->session->peer_cert == NULL )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        if( ssl->session->peer_cert->raw.len !=
            ssl->session_negotiate->peer_cert->raw.len ||
            memcmp( ssl->session->peer_cert->raw.p,
                    ssl->session_negotiate->peer_cert->raw.p,
                    ssl->session->peer_cert->raw.len ) != 0 )
        {
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }
    }

    if( ssl->authmode != SSL_VERIFY_NONE )
    {
        if( ssl->ca_chain == NULL )
        {
            return( POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED );
        }

        /*
         * Main check: verify certificate
         */
        ret = x509_crt_verify( ssl->session_negotiate->peer_cert,
                               ssl->ca_chain, ssl->ca_crl, ssl->peer_cn,
                              &ssl->session_negotiate->verify_result,
                               ssl->f_vrfy, ssl->p_vrfy );

        /*
         * Secondary checks: always done, but change 'ret' only if it was 0
         */

        {
            pk_context *pk = &ssl->session_negotiate->peer_cert->pk;

            /* If certificate uses an EC key, make sure the curve is OK */
            if( pk_can_do( pk, POLARSSL_PK_ECKEY ) &&
                ! ssl_curve_is_acceptable( ssl, pk_ec( *pk )->grp.id ) )
            {
                if( ret == 0 )
                    ret = POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE;
            }
        }

        if( ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                  ciphersuite_info,
                                  ! ssl->endpoint ) != 0 )
        {
            if( ret == 0 )
                ret = POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE;
        }

        if( ssl->authmode != SSL_VERIFY_REQUIRED )
            ret = 0;
    }

    return( ret );
}

int ssl_write_change_cipher_spec( ssl_context *ssl )
{
    int ret;

    ssl->out_msgtype = SSL_MSG_CHANGE_CIPHER_SPEC;
    ssl->out_msglen  = 1;
    ssl->out_msg[0]  = 1;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int ssl_parse_change_cipher_spec( ssl_context *ssl )
{
    int ret;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msglen != 1 || ssl->in_msg[0] != 1 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
    }

    ssl->state++;

    return( 0 );
}

void ssl_optimize_checksum( ssl_context *ssl,
                            const ssl_ciphersuite_t *ciphersuite_info )
{
    ((void) ciphersuite_info);

    if (ciphersuite_info->mac == POLARSSL_MD_SHA384) {
        ssl->handshake->update_checksum = ssl_update_checksum_sha384;
    }
    else {
        ssl->handshake->update_checksum = ssl_update_checksum_sha256;
    }
}

static void ssl_update_checksum_start( ssl_context *ssl,
                                       const uint8_t *buf, size_t len )
{
    sha256_update( &ssl->handshake->fin_sha256, buf, len );
    sha512_update( &ssl->handshake->fin_sha512, buf, len );
}

void ssl_update_checksum_sha256( ssl_context *ssl,
                                        const uint8_t *buf, size_t len )
{
    sha256_update( &ssl->handshake->fin_sha256, buf, len );
}

void ssl_update_checksum_sha384( ssl_context *ssl,
                                        const uint8_t *buf, size_t len )
{
    sha512_update( &ssl->handshake->fin_sha512, buf, len );
}

void ssl_calc_finished_tls_sha256(ssl_context *ssl, uint8_t *buf, int from )
{
    int len = 12;
    const char *sender;
    sha256_context sha256;
    uint8_t padbuf[32];

    ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    __movsb( &sha256, &ssl->handshake->fin_sha256, sizeof(sha256_context) );

    /*
     * TLSv1.2:
     *   hash = PRF( master, finished_label,
     *               Hash( handshake ) )[0.11]
     */

    sender = ( from == SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    sha256_finish( &sha256, padbuf );

    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 32, buf, len );

    __stosb( &sha256, 0, sizeof( sha256_context ) );

    __stosb(  padbuf, 0, sizeof(  padbuf ) );
}

void ssl_calc_finished_tls_sha384(ssl_context *ssl, uint8_t *buf, int from )
{
    int len = 12;
    const char *sender;
    sha512_context sha512;
    uint8_t padbuf[48];

    ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    __movsb( &sha512, &ssl->handshake->fin_sha512, sizeof(sha512_context) );

    /*
     * TLSv1.2:
     *   hash = PRF( master, finished_label,
     *               Hash( handshake ) )[0.11]
     */

    sender = ( from == SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    sha512_finish( &sha512, padbuf );

    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 48, buf, len );

    __stosb( &sha512, 0, sizeof( sha512_context ) );

    __stosb(  padbuf, 0, sizeof(  padbuf ) );
}

void ssl_handshake_wrapup( ssl_context *ssl )
{
    int resume = ssl->handshake->resume;

    /*
     * Free our handshake params
     */
    ssl_handshake_free( ssl->handshake );
    memory_free( ssl->handshake );
    ssl->handshake = NULL;

    if (ssl->renegotiation == SSL_RENEGOTIATION) {
        ssl->renegotiation = SSL_RENEGOTIATION_DONE;
        ssl->renego_records_seen = 0;
    }
    /*
     * Switch in our now active transform context
     */
    if( ssl->transform )
    {
        ssl_transform_free( ssl->transform );
        memory_free( ssl->transform );
    }
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_negotiate = NULL;

    if( ssl->session )
    {
        ssl_session_free( ssl->session );
        memory_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    /*
     * Add cache entry
     */
    if( ssl->f_set_cache != NULL &&
        ssl->session->length != 0 &&
        resume == 0 )
    {
        ssl->f_set_cache(ssl->p_set_cache, ssl->session);
    }

    ssl->state++;
}

int ssl_write_finished( ssl_context *ssl )
{
    int ret, hash_len;

    /*
     * Set the out_msg pointer to the correct location based on IV length
     */
    if( ssl->minor_ver >= SSL_MINOR_VERSION_2 )
    {
        ssl->out_msg = ssl->out_iv + ssl->transform_negotiate->ivlen -
                       ssl->transform_negotiate->fixed_ivlen;
    }
    else
        ssl->out_msg = ssl->out_iv;

    ssl->handshake->calc_finished( ssl, ssl->out_msg + 4, ssl->endpoint );

    // TODO TLS/1.2 Hash length is determined by cipher suite (Page 63)
    hash_len = ( ssl->minor_ver == SSL_MINOR_VERSION_0 ) ? 36 : 12;

    ssl->verify_data_len = hash_len;
    __movsb( ssl->own_verify_data, ssl->out_msg + 4, hash_len );

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_FINISHED;

    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if( ssl->handshake->resume != 0 )
    {
        if( ssl->endpoint == SSL_IS_CLIENT )
            ssl->state = SSL_HANDSHAKE_WRAPUP;
        else
            ssl->state = SSL_CLIENT_CHANGE_CIPHER_SPEC;
    }
    else
        ssl->state++;

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;
    __stosb( ssl->out_ctr, 0, 8 );

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int ssl_parse_finished( ssl_context *ssl )
{
    int ret;
    uint32_t hash_len;
    uint8_t buf[36];

    ssl->handshake->calc_finished( ssl, buf, ssl->endpoint ^ 1 );

    /*
     * Switch to our negotiated transform and session parameters for inbound
     * data.
     */
    ssl->transform_in = ssl->transform_negotiate;
    ssl->session_in = ssl->session_negotiate;
    __stosb( ssl->in_ctr, 0, 8 );

    /*
     * Set the in_msg pointer to the correct location based on IV length
     */
    if( ssl->minor_ver >= SSL_MINOR_VERSION_2 )
    {
        ssl->in_msg = ssl->in_iv + ssl->transform_negotiate->ivlen -
                      ssl->transform_negotiate->fixed_ivlen;
    }
    else
        ssl->in_msg = ssl->in_iv;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    // TODO TLS/1.2 Hash length is determined by cipher suite (Page 63)
    hash_len = ( ssl->minor_ver == SSL_MINOR_VERSION_0 ) ? 36 : 12;

    if( ssl->in_msg[0] != SSL_HS_FINISHED ||
        ssl->in_hslen  != 4 + hash_len )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_FINISHED );
    }

    if( safer_memcmp( ssl->in_msg + 4, buf, hash_len ) != 0 )
    {
        return( POLARSSL_ERR_SSL_BAD_HS_FINISHED );
    }

    ssl->verify_data_len = hash_len;
    __movsb( ssl->peer_verify_data, buf, hash_len );

    if( ssl->handshake->resume != 0 )
    {
        if( ssl->endpoint == SSL_IS_CLIENT )
            ssl->state = SSL_CLIENT_CHANGE_CIPHER_SPEC;

        if( ssl->endpoint == SSL_IS_SERVER )
            ssl->state = SSL_HANDSHAKE_WRAPUP;
    }
    else
        ssl->state++;

    return( 0 );
}

static void ssl_handshake_params_init(ssl_handshake_params *handshake)
{
    __stosb(handshake, 0, sizeof(ssl_handshake_params));

    sha256_init(&handshake->fin_sha256);
    sha256_starts(&handshake->fin_sha256, 0);
    sha512_init(&handshake->fin_sha512);
    sha512_starts(&handshake->fin_sha512, 1);

    handshake->update_checksum = ssl_update_checksum_start;
    handshake->sig_alg = SSL_HASH_SHA1;

    ecdh_init(&handshake->ecdh_ctx);
}

static void ssl_transform_init(ssl_transform *transform)
{
    __stosb(transform, 0, sizeof(ssl_transform));

    cipher_init(&transform->cipher_ctx_enc);
    cipher_init(&transform->cipher_ctx_dec);

    md_init(&transform->md_ctx_enc);
    md_init(&transform->md_ctx_dec);
}

void ssl_session_init(ssl_session *session)
{
    __stosb(session, 0, sizeof(ssl_session));
}

static int ssl_handshake_init(ssl_context *ssl)
{
    /* Clear old handshake information if present */
    if (ssl->transform_negotiate)
        ssl_transform_free(ssl->transform_negotiate);
    if (ssl->session_negotiate)
        ssl_session_free(ssl->session_negotiate);
    if (ssl->handshake)
        ssl_handshake_free(ssl->handshake);

    /*
    * Either the pointers are now NULL or cleared properly and can be freed.
    * Now allocate missing structures.
    */
    if (ssl->transform_negotiate == NULL)
    {
        ssl->transform_negotiate =
            (ssl_transform *)polarssl_malloc(sizeof(ssl_transform));
    }

    if (ssl->session_negotiate == NULL)
    {
        ssl->session_negotiate =
            (ssl_session *)polarssl_malloc(sizeof(ssl_session));
    }

    if (ssl->handshake == NULL)
    {
        ssl->handshake = (ssl_handshake_params *)
            polarssl_malloc(sizeof(ssl_handshake_params));
    }

    /* All pointers should exist and can be directly freed without issue */
    if (ssl->handshake == NULL ||
        ssl->transform_negotiate == NULL ||
        ssl->session_negotiate == NULL)
    {
        polarssl_free(ssl->handshake);
        polarssl_free(ssl->transform_negotiate);
        polarssl_free(ssl->session_negotiate);

        ssl->handshake = NULL;
        ssl->transform_negotiate = NULL;
        ssl->session_negotiate = NULL;

        return(POLARSSL_ERR_SSL_MALLOC_FAILED);
    }

    /* Initialize structures */
    ssl_session_init(ssl->session_negotiate);
    ssl_transform_init(ssl->transform_negotiate);
    ssl_handshake_params_init(ssl->handshake);

#if defined(POLARSSL_X509_CRT_PARSE_C)
    ssl->handshake->key_cert = ssl->key_cert;
#endif

    return(0);
}

/*
 * Initialize an SSL context
 */
int ssl_init( ssl_context *ssl )
{
    int ret;
    int len = SSL_BUFFER_LEN;

    __stosb( ssl, 0, sizeof( ssl_context ) );

    /*
     * Sane defaults
     */
    ssl->min_major_ver = SSL_MIN_MAJOR_VERSION;
    ssl->min_minor_ver = SSL_MIN_MINOR_VERSION;
    ssl->max_major_ver = SSL_MAX_MAJOR_VERSION;
    ssl->max_minor_ver = SSL_MAX_MINOR_VERSION;

    ssl_set_ciphersuites( ssl, ssl_list_ciphersuites() );

    ssl->renego_max_records = SSL_RENEGO_MAX_RECORDS_DEFAULT;
    /*
     * Prepare base structures
     */
    ssl->in_ctr = (uint8_t *) memory_alloc( len );
    ssl->in_hdr = ssl->in_ctr +  8;
    ssl->in_iv  = ssl->in_ctr + 13;
    ssl->in_msg = ssl->in_ctr + 13;

    if( ssl->in_ctr == NULL )
    {
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    ssl->out_ctr = (uint8_t *) memory_alloc( len );
    ssl->out_hdr = ssl->out_ctr +  8;
    ssl->out_iv  = ssl->out_ctr + 13;
    ssl->out_msg = ssl->out_ctr + 13;

    if( ssl->out_ctr == NULL )
    {
        memory_free( ssl->in_ctr );
        ssl->in_ctr = NULL;
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    __stosb( ssl-> in_ctr, 0, SSL_BUFFER_LEN );
    __stosb( ssl->out_ctr, 0, SSL_BUFFER_LEN );

    ssl->curve_list = ecp_grp_id_list( );

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
int ssl_session_reset( ssl_context *ssl )
{
    int ret;

    ssl->state = SSL_HELLO_REQUEST;
    ssl->renegotiation = SSL_INITIAL_HANDSHAKE;
    ssl->secure_renegotiation = SSL_LEGACY_RENEGOTIATION;

    ssl->verify_data_len = 0;
    __stosb( ssl->own_verify_data, 0, 36 );
    __stosb( ssl->peer_verify_data, 0, 36 );

    ssl->in_offt = NULL;

    ssl->in_msg = ssl->in_ctr + 13;
    ssl->in_msgtype = 0;
    ssl->in_msglen = 0;
    ssl->in_left = 0;

    ssl->in_hslen = 0;
    ssl->nb_zero = 0;
    ssl->record_read = 0;

    ssl->out_msg = ssl->out_ctr + 13;
    ssl->out_msgtype = 0;
    ssl->out_msglen = 0;
    ssl->out_left = 0;

    ssl->transform_in = NULL;
    ssl->transform_out = NULL;

    ssl->renego_records_seen = 0;

    __stosb( ssl->out_ctr, 0, SSL_BUFFER_LEN );
    __stosb( ssl->in_ctr, 0, SSL_BUFFER_LEN );

    if( ssl->transform )
    {
        ssl_transform_free( ssl->transform );
        memory_free( ssl->transform );
        ssl->transform = NULL;
    }

    if( ssl->session )
    {
        ssl_session_free( ssl->session );
        memory_free( ssl->session );
        ssl->session = NULL;
    }

#if defined(POLARSSL_SSL_ALPN)
    ssl->alpn_chosen = NULL;
#endif

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    return( 0 );
}


/*
 * SSL set accessors
 */
void ssl_set_endpoint( ssl_context *ssl, int endpoint )
{
    ssl->endpoint   = endpoint;
}

void ssl_set_authmode( ssl_context *ssl, int authmode )
{
    ssl->authmode   = authmode;
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
void ssl_set_verify( ssl_context *ssl,
                     int (*f_vrfy)(void *, x509_crt *, int, int *),
                     void *p_vrfy )
{
    ssl->f_vrfy      = f_vrfy;
    ssl->p_vrfy      = p_vrfy;
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

void ssl_set_rng( ssl_context *ssl,
                  int (*f_rng)(void *, uint8_t *, size_t),
                  void *p_rng )
{
    ssl->f_rng      = f_rng;
    ssl->p_rng      = p_rng;
}

void ssl_set_dbg( ssl_context *ssl,
                  void (*f_dbg)(void *, int, const char *),
                  void  *p_dbg )
{
    ssl->f_dbg      = f_dbg;
    ssl->p_dbg      = p_dbg;
}

void ssl_set_bio( ssl_context *ssl,
            int (*f_recv)(void *, uint8_t *, size_t), void *p_recv,
            int (*f_send)(void *, const uint8_t *, size_t), void *p_send )
{
    ssl->f_recv     = f_recv;
    ssl->f_send     = f_send;
    ssl->p_recv     = p_recv;
    ssl->p_send     = p_send;
}

void ssl_set_session_cache( ssl_context *ssl,
        int (*f_get_cache)(void *, ssl_session *), void *p_get_cache,
        int (*f_set_cache)(void *, const ssl_session *), void *p_set_cache )
{
    ssl->f_get_cache = f_get_cache;
    ssl->p_get_cache = p_get_cache;
    ssl->f_set_cache = f_set_cache;
    ssl->p_set_cache = p_set_cache;
}

int ssl_set_session( ssl_context *ssl, const ssl_session *session )
{
    int ret;

    if( ssl == NULL ||
        session == NULL ||
        ssl->session_negotiate == NULL ||
        ssl->endpoint != SSL_IS_CLIENT )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    if( ( ret = ssl_session_copy( ssl->session_negotiate, session ) ) != 0 )
        return( ret );

    ssl->handshake->resume = 1;

    return( 0 );
}

void ssl_set_ciphersuites( ssl_context *ssl, const int *ciphersuites )
{
    ssl->ciphersuite_list[SSL_MINOR_VERSION_0] = ciphersuites;
    ssl->ciphersuite_list[SSL_MINOR_VERSION_1] = ciphersuites;
    ssl->ciphersuite_list[SSL_MINOR_VERSION_2] = ciphersuites;
    ssl->ciphersuite_list[SSL_MINOR_VERSION_3] = ciphersuites;
}

void ssl_set_ciphersuites_for_version( ssl_context *ssl,
                                       const int *ciphersuites,
                                       int major, int minor )
{
    if( major != SSL_MAJOR_VERSION_3 )
        return;

    if( minor < SSL_MINOR_VERSION_0 || minor > SSL_MINOR_VERSION_3 )
        return;

    ssl->ciphersuite_list[minor] = ciphersuites;
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
/* Add a new (empty) key_cert entry an return a pointer to it */
static ssl_key_cert *ssl_add_key_cert( ssl_context *ssl )
{
    ssl_key_cert *key_cert, *last;

    key_cert = (ssl_key_cert *) memory_alloc( sizeof(ssl_key_cert) );
    if( key_cert == NULL )
        return( NULL );

    __stosb( key_cert, 0, sizeof( ssl_key_cert ) );

    /* Append the new key_cert to the (possibly empty) current list */
    if( ssl->key_cert == NULL )
    {
        ssl->key_cert = key_cert;
        if( ssl->handshake != NULL )
            ssl->handshake->key_cert = key_cert;
    }
    else
    {
        last = ssl->key_cert;
        while( last->next != NULL )
            last = last->next;
        last->next = key_cert;
    }

    return key_cert;
}

void ssl_set_ca_chain( ssl_context *ssl, x509_crt *ca_chain,
                       x509_crl *ca_crl, const char *peer_cn )
{
    ssl->ca_chain   = ca_chain;
    ssl->ca_crl     = ca_crl;
    ssl->peer_cn    = peer_cn;
}

int ssl_set_own_cert( ssl_context *ssl, x509_crt *own_cert,
                       pk_context *pk_key )
{
    ssl_key_cert *key_cert = ssl_add_key_cert( ssl );

    if( key_cert == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    key_cert->cert = own_cert;
    key_cert->key  = pk_key;

    return( 0 );
}

int ssl_set_own_cert_rsa( ssl_context *ssl, x509_crt *own_cert,
                           rsa_context_t *rsa_key )
{
    int ret;
    ssl_key_cert *key_cert = ssl_add_key_cert( ssl );

    if( key_cert == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    key_cert->key = (pk_context *) memory_alloc( sizeof(pk_context) );
    if( key_cert->key == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    pk_init( key_cert->key );

    ret = pk_init_ctx( key_cert->key, pk_info_from_type( POLARSSL_PK_RSA ) );
    if( ret != 0 )
        return( ret );

    if( ( ret = rsa_copy( pk_rsa( *key_cert->key ), rsa_key ) ) != 0 )
        return( ret );

    key_cert->cert = own_cert;
    key_cert->key_own_alloc = 1;

    return( 0 );
}

int ssl_set_own_cert_alt( ssl_context *ssl, x509_crt *own_cert,
                          void *rsa_key,
                          rsa_decrypt_func rsa_decrypt,
                          rsa_sign_func rsa_sign,
                          rsa_key_len_func rsa_key_len )
{
    int ret;
    ssl_key_cert *key_cert = ssl_add_key_cert( ssl );

    if( key_cert == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    key_cert->key = (pk_context *) memory_alloc( sizeof(pk_context) );
    if( key_cert->key == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    pk_init( key_cert->key );

    if( ( ret = pk_init_ctx_rsa_alt( key_cert->key, rsa_key,
                                 rsa_decrypt, rsa_sign, rsa_key_len ) ) != 0 )
        return( ret );

    key_cert->cert = own_cert;
    key_cert->key_own_alloc = 1;

    return( 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

/*
 * Set the allowed elliptic curves
 */
void ssl_set_curves( ssl_context *ssl, const ecp_group_id *curve_list )
{
  ssl->curve_list = curve_list;
}

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
int ssl_set_hostname( ssl_context *ssl, const char *hostname )
{
    if( hostname == NULL )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    ssl->hostname_len = strlen( hostname );

    if( ssl->hostname_len + 1 == 0 )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    ssl->hostname = (uint8_t *) memory_alloc( ssl->hostname_len + 1 );

    if( ssl->hostname == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    __movsb( ssl->hostname, (const uint8_t *) hostname,
            ssl->hostname_len );

    ssl->hostname[ssl->hostname_len] = '\0';

    return( 0 );
}

void ssl_set_sni( ssl_context *ssl,
                  int (*f_sni)(void *, ssl_context *,
                                const uint8_t *, size_t),
                  void *p_sni )
{
    ssl->f_sni = f_sni;
    ssl->p_sni = p_sni;
}
#endif /* POLARSSL_SSL_SERVER_NAME_INDICATION */

#if defined(POLARSSL_SSL_ALPN)
int ssl_set_alpn_protocols( ssl_context *ssl, const char **protos )
{
    size_t cur_len, tot_len;
    const char **p;

    /*
     * "Empty strings MUST NOT be included and byte strings MUST NOT be
     * truncated". Check lengths now rather than later.
     */
    tot_len = 0;
    for( p = protos; *p != NULL; p++ )
    {
        cur_len = strlen( *p );
        tot_len += cur_len;

        if( cur_len == 0 || cur_len > 255 || tot_len > 65535 )
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    ssl->alpn_list = protos;

    return( 0 );
}

const char *ssl_get_alpn_protocol( const ssl_context *ssl )
{
    return ssl->alpn_chosen;
}
#endif /* POLARSSL_SSL_ALPN */

void ssl_set_max_version( ssl_context *ssl, int major, int minor )
{
    if( major >= SSL_MIN_MAJOR_VERSION && major <= SSL_MAX_MAJOR_VERSION &&
        minor >= SSL_MIN_MINOR_VERSION && minor <= SSL_MAX_MINOR_VERSION )
    {
        ssl->max_major_ver = major;
        ssl->max_minor_ver = minor;
    }
}

void ssl_set_min_version( ssl_context *ssl, int major, int minor )
{
    if( major >= SSL_MIN_MAJOR_VERSION && major <= SSL_MAX_MAJOR_VERSION &&
        minor >= SSL_MIN_MINOR_VERSION && minor <= SSL_MAX_MINOR_VERSION )
    {
        ssl->min_major_ver = major;
        ssl->min_minor_ver = minor;
    }
}

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
int ssl_set_max_frag_len( ssl_context *ssl, uint8_t mfl_code )
{
    if( mfl_code >= SSL_MAX_FRAG_LEN_INVALID ||
        mfl_code_to_length[mfl_code] > SSL_MAX_CONTENT_LEN )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    ssl->mfl_code = mfl_code;

    return( 0 );
}
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
int ssl_set_truncated_hmac( ssl_context *ssl, int truncate )
{
    if( ssl->endpoint != SSL_IS_CLIENT )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    ssl->trunc_hmac = truncate;

    return( 0 );
}
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

void ssl_set_renegotiation( ssl_context *ssl, int renegotiation )
{
    ssl->disable_renegotiation = renegotiation;
}

void ssl_legacy_renegotiation( ssl_context *ssl, int allow_legacy )
{
    ssl->allow_legacy_renegotiation = allow_legacy;
}

void ssl_set_renegotiation_enforced(ssl_context *ssl, int max_records)
{
    ssl->renego_max_records = max_records;
}

/*
 * SSL get accessors
 */
size_t ssl_get_bytes_avail( const ssl_context *ssl )
{
    return( ssl->in_offt == NULL ? 0 : ssl->in_msglen );
}

int ssl_get_verify_result( const ssl_context *ssl )
{
    return( ssl->session->verify_result );
}

const char *ssl_get_ciphersuite( const ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return NULL;

    return ssl_get_ciphersuite_name( ssl->session->ciphersuite );
}

const char *ssl_get_version( const ssl_context *ssl )
{
    switch( ssl->minor_ver )
    {
        case SSL_MINOR_VERSION_0:
            return( "SSLv3.0" );

        case SSL_MINOR_VERSION_1:
            return( "TLSv1.0" );

        case SSL_MINOR_VERSION_2:
            return( "TLSv1.1" );

        case SSL_MINOR_VERSION_3:
            return( "TLSv1.2" );

        default:
            break;
    }
    return( "unknown" );
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
const x509_crt *ssl_get_peer_cert( const ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return NULL;

    return ssl->session->peer_cert;
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

int ssl_get_session( const ssl_context *ssl, ssl_session *dst )
{
    if( ssl == NULL ||
        dst == NULL ||
        ssl->session == NULL ||
        ssl->endpoint != SSL_IS_CLIENT )
    {
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ssl_session_copy( dst, ssl->session ) );
}

/*
 * Perform a single step of the SSL handshake
 */
int ssl_handshake_step( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

#if defined(POLARSSL_SSL_CLI_C)
    if( ssl->endpoint == SSL_IS_CLIENT )
        ret = ssl_handshake_client_step( ssl );
#endif

#if defined(POLARSSL_SSL_SRV_C)
    if( ssl->endpoint == SSL_IS_SERVER )
        ret = ssl_handshake_server_step( ssl );
#endif

    return( ret );
}

/*
 * Perform the SSL handshake
 */
int ssl_handshake( ssl_context *ssl )
{
    int ret = 0;

    while( ssl->state != SSL_HANDSHAKE_OVER )
    {
        ret = ssl_handshake_step( ssl );

        if( ret != 0 )
            break;
    }

    return( ret );
}

#if defined(POLARSSL_SSL_SRV_C)
/*
 * Write HelloRequest to request renegotiation on server
 */
static int ssl_write_hello_request( ssl_context *ssl )
{
    int ret;

    ssl->out_msglen  = 4;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_HELLO_REQUEST;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        return( ret );
    }

    ssl->renegotiation = SSL_RENEGOTIATION_PENDING;

    return( 0 );
}
#endif /* POLARSSL_SSL_SRV_C */

/*
 * Actually renegotiate current connection, triggered by either:
 * - calling ssl_renegotiate() on client,
 * - receiving a HelloRequest on client during ssl_read(),
 * - receiving any handshake message on server during ssl_read() after the
 *   initial handshake is completed
 * If the handshake doesn't complete due to waiting for I/O, it will continue
 * during the next calls to ssl_renegotiate() or ssl_read() respectively.
 */
static int ssl_start_renegotiation( ssl_context *ssl )
{
    int ret;

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    ssl->state = SSL_HELLO_REQUEST;
    ssl->renegotiation = SSL_RENEGOTIATION;

    if( ( ret = ssl_handshake( ssl ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Renegotiate current connection on client,
 * or request renegotiation on server
 */
int ssl_renegotiate( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

#if defined(POLARSSL_SSL_SRV_C)
    /* On server, just send the request */
    if( ssl->endpoint == SSL_IS_SERVER )
    {
        if( ssl->state != SSL_HANDSHAKE_OVER )
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

        return( ssl_write_hello_request( ssl ) );
    }
#endif /* POLARSSL_SSL_SRV_C */

#if defined(POLARSSL_SSL_CLI_C)
    /*
     * On client, either start the renegotiation process or,
     * if already in progress, continue the handshake
     */
    if( ssl->renegotiation != SSL_RENEGOTIATION )
    {
        if( ssl->state != SSL_HANDSHAKE_OVER )
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

        if( ( ret = ssl_start_renegotiation( ssl ) ) != 0 )
        {
            return( ret );
        }
    }
    else
    {
        if( ( ret = ssl_handshake( ssl ) ) != 0 )
        {
            return( ret );
        }
    }
#endif /* POLARSSL_SSL_CLI_C */

    return( ret );
}

/*
 * Receive application data decrypted from the SSL layer
 */
int ssl_read( ssl_context *ssl, uint8_t *buf, size_t len )
{
    int ret;
    size_t n;

    if( ssl->state != SSL_HANDSHAKE_OVER )
    {
        if( ( ret = ssl_handshake( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    if( ssl->in_offt == NULL )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            if( ret == POLARSSL_ERR_SSL_CONN_EOF )
                return( 0 );

            return( ret );
        }

        if( ssl->in_msglen  == 0 && ssl->in_msgtype == SSL_MSG_APPLICATION_DATA ) {
            /*
             * OpenSSL sends empty messages to randomize the IV
             */
            if( ( ret = ssl_read_record( ssl ) ) != 0 ) {
                if( ret == POLARSSL_ERR_SSL_CONN_EOF )
                    return( 0 );

                return( ret );
            }
        }

        if( ssl->in_msgtype == SSL_MSG_HANDSHAKE ) {
            if( ssl->endpoint == SSL_IS_CLIENT &&
                ( ssl->in_msg[0] != SSL_HS_HELLO_REQUEST ||
                  ssl->in_hslen != 4 ) )
            {
                return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
            }

            if( ssl->disable_renegotiation == SSL_RENEGOTIATION_DISABLED ||
                ( ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
                  ssl->allow_legacy_renegotiation ==
                                                SSL_LEGACY_NO_RENEGOTIATION ) )
            {
                if( ssl->minor_ver >= SSL_MINOR_VERSION_1 ) {
                    if( ( ret = ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_WARNING, SSL_ALERT_MSG_NO_RENEGOTIATION ) ) != 0 ) {
                        return( ret );
                    }
                }
                else {
                    return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
                }
            }
            else {
                if( ( ret = ssl_start_renegotiation( ssl ) ) != 0 ) {
                    return ret;
                }

                return( POLARSSL_ERR_NET_WANT_READ );
            }
        }
        else if( ssl->renegotiation == SSL_RENEGOTIATION_PENDING ) {
            ssl->renego_records_seen++;

            if (ssl->renego_max_records >= 0 && ssl->renego_records_seen > ssl->renego_max_records) {
                return POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE;
            }
        }
        else if( ssl->in_msgtype != SSL_MSG_APPLICATION_DATA ) {
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->in_offt = ssl->in_msg;
    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    __movsb( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
        /* all bytes consumed  */
        ssl->in_offt = NULL;
    else
        /* more data available */
        ssl->in_offt += n;

    return( (int) n );
}

/*
 * Send application data to be encrypted by the SSL layer
 */
int ssl_write( ssl_context *ssl, const uint8_t *buf, size_t len )
{
    int ret;
    size_t n;
    uint32_t max_len = SSL_MAX_CONTENT_LEN;

    if( ssl->state != SSL_HANDSHAKE_OVER )
    {
        if( ( ret = ssl_handshake( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    /*
     * Assume mfl_code is correct since it was checked when set
     */
    max_len = mfl_code_to_length[ssl->mfl_code];

    /*
     * Check if a smaller max length was negotiated
     */
    if( ssl->session_out != NULL &&
        mfl_code_to_length[ssl->session_out->mfl_code] < max_len )
    {
        max_len = mfl_code_to_length[ssl->session_out->mfl_code];
    }
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

    n = ( len < max_len) ? len : max_len;

    if( ssl->out_left != 0 )
    {
        if( ( ret = ssl_flush_output( ssl ) ) != 0 )
        {
            return( ret );
        }
    }
    else
    {
        ssl->out_msglen  = n;
        ssl->out_msgtype = SSL_MSG_APPLICATION_DATA;
        __movsb( ssl->out_msg, buf, n );

        if( ( ret = ssl_write_record( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    return( (int) n );
}

/*
 * Notify the peer that the connection is being closed
 */
int ssl_close_notify( ssl_context *ssl )
{
    int ret;

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
    {
        return( ret );
    }

    if( ssl->state == SSL_HANDSHAKE_OVER )
    {
        if( ( ret = ssl_send_alert_message( ssl,
                        SSL_ALERT_LEVEL_WARNING,
                        SSL_ALERT_MSG_CLOSE_NOTIFY ) ) != 0 )
        {
            return( ret );
        }
    }

    return( ret );
}

void ssl_transform_free( ssl_transform *transform )
{
    cipher_free_ctx( &transform->cipher_ctx_enc );
    cipher_free_ctx( &transform->cipher_ctx_dec );

    md_free_ctx( &transform->md_ctx_enc );
    md_free_ctx( &transform->md_ctx_dec );

    __stosb( transform, 0, sizeof( ssl_transform ) );
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
static void ssl_key_cert_free( ssl_key_cert *key_cert )
{
    ssl_key_cert *cur = key_cert, *next;

    while( cur != NULL )
    {
        next = cur->next;

        if( cur->key_own_alloc )
        {
            pk_free( cur->key );
            memory_free( cur->key );
        }
        memory_free( cur );

        cur = next;
    }
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

void ssl_handshake_free( ssl_handshake_params *handshake )
{
    ecdh_free( &handshake->ecdh_ctx );

    /* explicit void pointer cast for buggy MS compiler */
    memory_free( (void *) handshake->curves );

#if defined(POLARSSL_X509_CRT_PARSE_C) && \
    defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
    /*
     * Free only the linked list wrapper, not the keys themselves
     * since the belong to the SNI callback
     */
    if( handshake->sni_key_cert != NULL )
    {
        ssl_key_cert *cur = handshake->sni_key_cert, *next;

        while( cur != NULL )
        {
            next = cur->next;
            memory_free( cur );
            cur = next;
        }
    }
#endif /* POLARSSL_X509_CRT_PARSE_C && POLARSSL_SSL_SERVER_NAME_INDICATION */

    __stosb( handshake, 0, sizeof( ssl_handshake_params ) );
}

void ssl_session_free( ssl_session *session )
{
#if defined(POLARSSL_X509_CRT_PARSE_C)
    if( session->peer_cert != NULL )
    {
        x509_crt_free( session->peer_cert );
        memory_free( session->peer_cert );
    }
#endif

    __stosb( session, 0, sizeof( ssl_session ) );
}

/*
 * Free an SSL context
 */
void ssl_free( ssl_context *ssl )
{

    if( ssl->out_ctr != NULL )
    {
        __stosb( ssl->out_ctr, 0, SSL_BUFFER_LEN );
        memory_free( ssl->out_ctr );
    }

    if( ssl->in_ctr != NULL )
    {
        __stosb( ssl->in_ctr, 0, SSL_BUFFER_LEN );
        memory_free( ssl->in_ctr );
    }

    if( ssl->transform )
    {
        ssl_transform_free( ssl->transform );
        memory_free( ssl->transform );
    }

    if( ssl->handshake )
    {
        ssl_handshake_free( ssl->handshake );
        ssl_transform_free( ssl->transform_negotiate );
        ssl_session_free( ssl->session_negotiate );

        memory_free( ssl->handshake );
        memory_free( ssl->transform_negotiate );
        memory_free( ssl->session_negotiate );
    }

    if( ssl->session )
    {
        ssl_session_free( ssl->session );
        memory_free( ssl->session );
    }

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
    if ( ssl->hostname != NULL )
    {
        __stosb( ssl->hostname, 0, ssl->hostname_len );
        memory_free( ssl->hostname );
        ssl->hostname_len = 0;
    }
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C)
    ssl_key_cert_free( ssl->key_cert );
#endif

    /* Actually clear after last debug message */
    __stosb( ssl, 0, sizeof( ssl_context ) );
}

#if defined(POLARSSL_PK_C)
/*
 * Convert between POLARSSL_PK_XXX and SSL_SIG_XXX
 */
uint8_t ssl_sig_from_pk( pk_context *pk )
{
    if( pk_can_do( pk, POLARSSL_PK_RSA ) )
        return( SSL_SIG_RSA );
    return( SSL_SIG_ANON );
}

pk_type_t ssl_pk_alg_from_sig( uint8_t sig )
{
    switch( sig )
    {
        case SSL_SIG_RSA:
            return( POLARSSL_PK_RSA );
        default:
            return( POLARSSL_PK_NONE );
    }
}
#endif /* POLARSSL_PK_C */

/*
 * Convert between SSL_HASH_XXX and POLARSSL_MD_XXX
 */
md_type_t ssl_md_alg_from_hash( uint8_t hash )
{
    switch( hash )
    {
#if defined(POLARSSL_SHA256_C)
        case SSL_HASH_SHA224:
            return( POLARSSL_MD_SHA224 );
        case SSL_HASH_SHA256:
            return( POLARSSL_MD_SHA256 );
#endif
#if defined(POLARSSL_SHA512_C)
        case SSL_HASH_SHA384:
            return( POLARSSL_MD_SHA384 );
        case SSL_HASH_SHA512:
            return( POLARSSL_MD_SHA512 );
#endif
        default:
            return( POLARSSL_MD_NONE );
    }
}

/*
 * Check is a curve proposed by the peer is in our list.
 * Return 1 if we're willing to use it, 0 otherwise.
 */
int ssl_curve_is_acceptable( const ssl_context *ssl, ecp_group_id grp_id )
{
    const ecp_group_id *gid;

    for( gid = ssl->curve_list; *gid != POLARSSL_ECP_DP_NONE; gid++ )
        if( *gid == grp_id )
            return( 1 );

    return( 0 );
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
int ssl_check_cert_usage( const x509_crt *cert,
                          const ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint )
{
#if defined(POLARSSL_X509_CHECK_KEY_USAGE)
    int usage = 0;
#endif
#if defined(POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE)
    const char *ext_oid;
    size_t ext_len;
#endif

#if !defined(POLARSSL_X509_CHECK_KEY_USAGE) &&          \
    !defined(POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE)
    ((void) cert);
    ((void) cert_endpoint);
#endif

#if defined(POLARSSL_X509_CHECK_KEY_USAGE)
    if( cert_endpoint == SSL_IS_SERVER )
    {
        /* Server part of the key exchange */
        switch( ciphersuite->key_exchange )
        {
            case POLARSSL_KEY_EXCHANGE_ECDHE_RSA:
                usage = KU_DIGITAL_SIGNATURE;
                break;

            case POLARSSL_KEY_EXCHANGE_ECDH_RSA:
                usage = KU_KEY_AGREEMENT;
                break;
        }
    }
    else
    {
        /* Client auth: we only implement rsa_sign and ecdsa_sign for now */
        usage = KU_DIGITAL_SIGNATURE;
    }

    if( x509_crt_check_key_usage( cert, usage ) != 0 )
        return( -1 );
#else
    ((void) ciphersuite);
#endif /* POLARSSL_X509_CHECK_KEY_USAGE */

#if defined(POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE)
    if( cert_endpoint == SSL_IS_SERVER )
    {
        ext_oid = OID_SERVER_AUTH;
        ext_len = OID_SIZE( OID_SERVER_AUTH );
    }
    else
    {
        ext_oid = OID_CLIENT_AUTH;
        ext_len = OID_SIZE( OID_CLIENT_AUTH );
    }

    if( x509_crt_check_extended_key_usage( cert, ext_oid, ext_len ) != 0 )
        return( -1 );
#endif /* POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE */

    return( 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

#endif /* POLARSSL_SSL_TLS_C */
