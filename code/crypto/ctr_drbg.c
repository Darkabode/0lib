#include "..\zmodule.h"
#include "config.h"
#include "ctr_drbg.h"

/*
 * Non-public function wrapped by ctr_crbg_init(). Necessary to allow NIST
 * tests to succeed (which require known length fixed entropy)
 */
int ctr_drbg_init_entropy_len(ctr_drbg_context_t *ctx, int (*f_entropy)(void *, uint8_t *, size_t), void *p_entropy, const uint8_t* custom, size_t len, size_t entropy_len )
{
    int ret;
    uint8_t key[CTR_DRBG_KEYSIZE];

    __stosb(ctx, 0, sizeof(ctr_drbg_context_t));
    __stosb(key, 0, CTR_DRBG_KEYSIZE);

    ctx->f_entropy = f_entropy;
    ctx->p_entropy = p_entropy;

    ctx->entropy_len = entropy_len;
    ctx->reseed_interval = CTR_DRBG_RESEED_INTERVAL;

    /*
     * Initialize with an empty key
     */
    aes_setkey_enc( &ctx->aes_ctx, key);

    if ((ret = ctr_drbg_reseed(ctx, custom, len)) != 0) {
        return ret;
    }

    return 0;
}

int ctr_drbg_init( ctr_drbg_context_t *ctx, int (*f_entropy)(void *, uint8_t *, size_t), void *p_entropy, const uint8_t *custom, size_t len )
{
    return ctr_drbg_init_entropy_len( ctx, f_entropy, p_entropy, custom, len, CTR_DRBG_ENTROPY_LEN );
}

void ctr_drbg_set_prediction_resistance( ctr_drbg_context_t *ctx, int resistance )
{
    ctx->prediction_resistance = resistance;
}

void ctr_drbg_set_entropy_len( ctr_drbg_context_t *ctx, size_t len )
{
    ctx->entropy_len = len;
}

void ctr_drbg_set_reseed_interval( ctr_drbg_context_t *ctx, int interval )
{
    ctx->reseed_interval = interval;
}

int block_cipher_df( uint8_t *output, const uint8_t *data, size_t data_len )
{
    uint8_t buf[CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16];
    uint8_t tmp[CTR_DRBG_SEEDLEN];
    uint8_t key[CTR_DRBG_KEYSIZE];
    uint8_t chain[CTR_DRBG_BLOCKSIZE];
    uint8_t *p, *iv;
    aes_context_t aes_ctx;

    int i, j;
    size_t buf_len, use_len;

    __stosb( buf, 0, CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16 );

    /*
     * Construct IV (16 bytes) and S in buffer
     * IV = Counter (in 32-bits) padded to 16 with zeroes
     * S = Length input string (in 32-bits) || Length of output (in 32-bits) ||
     *     data || 0x80
     *     (Total is padded to a multiple of 16-bytes with zeroes)
     */
    p = buf + CTR_DRBG_BLOCKSIZE;
    *p++ = ( data_len >> 24 ) & 0xff;
    *p++ = ( data_len >> 16 ) & 0xff;
    *p++ = ( data_len >> 8  ) & 0xff;
    *p++ = ( data_len       ) & 0xff;
    p += 3;
    *p++ = CTR_DRBG_SEEDLEN;
    __movsb( p, data, data_len );
    p[data_len] = 0x80;

    buf_len = CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for( i = 0; i < CTR_DRBG_KEYSIZE; i++ )
        key[i] = i;

    aes_setkey_enc( &aes_ctx, key);

    /*
     * Reduce data to POLARSSL_CTR_DRBG_SEEDLEN bytes of data
     */
    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE ) {
        p = buf;
        __stosb( chain, 0, CTR_DRBG_BLOCKSIZE );
        use_len = buf_len;

        while( use_len > 0 ) {
            for (i = 0; i < CTR_DRBG_BLOCKSIZE; i++) {
                chain[i] ^= p[i];
            }
            p += CTR_DRBG_BLOCKSIZE;
            use_len -= ( use_len >= CTR_DRBG_BLOCKSIZE ) ? CTR_DRBG_BLOCKSIZE : use_len;

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, chain, chain );
        }

        __movsb( tmp + j, chain, CTR_DRBG_BLOCKSIZE );

        /*
         * Update IV
         */
        ++buf[3];
    }

    /*
     * Do final encryption with reduced data
     */
    aes_setkey_enc( &aes_ctx, tmp);
    iv = tmp + CTR_DRBG_KEYSIZE;
    p = output;

    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE ) {
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, iv, iv );
        __movsb( p, iv, CTR_DRBG_BLOCKSIZE );
        p += CTR_DRBG_BLOCKSIZE;
    }

    return 0;
}

int ctr_drbg_update_internal( ctr_drbg_context_t *ctx, const uint8_t data[CTR_DRBG_SEEDLEN] )
{
    uint8_t tmp[CTR_DRBG_SEEDLEN];
    uint8_t *p = tmp;
    int i, j;

    __stosb( tmp, 0, CTR_DRBG_SEEDLEN );

    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE ) {
        /*
         * Increase counter
         */
        for( i = CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        /*
         * Crypt counter block
         */
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, p );

        p += CTR_DRBG_BLOCKSIZE;
    }

    for (i = 0; i < CTR_DRBG_SEEDLEN; ++i) {
        tmp[i] ^= data[i];
    }

    /*
     * Update key and counter
     */
    aes_setkey_enc( &ctx->aes_ctx, tmp);
    __movsb( ctx->counter, tmp + CTR_DRBG_KEYSIZE, CTR_DRBG_BLOCKSIZE );

    return 0;
}

void ctr_drbg_update( ctr_drbg_context_t *ctx, const uint8_t *additional, size_t add_len )
{
    uint8_t add_input[CTR_DRBG_SEEDLEN];

    if (add_len > 0) {
        block_cipher_df( add_input, additional, add_len );
        ctr_drbg_update_internal( ctx, add_input );
    }
}

int ctr_drbg_reseed( ctr_drbg_context_t *ctx, const uint8_t *additional, size_t len )
{
    uint8_t seed[CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;

    if( ctx->entropy_len + len > CTR_DRBG_MAX_SEED_INPUT )
        return( POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG );

    __stosb( seed, 0, CTR_DRBG_MAX_SEED_INPUT );

    /*
     * Gather entropy_len bytes of entropy to seed state
     */
    if (0 != ctx->f_entropy(ctx->p_entropy, seed, ctx->entropy_len)) {
        return( POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED );
    }

    seedlen += ctx->entropy_len;

    /*
     * Add additional data
     */
    if (additional && len) {
        __movsb( seed + seedlen, additional, len );
        seedlen += len;
    }

    /*
     * Reduce to 384 bits
     */
    block_cipher_df( seed, seed, seedlen );

    /*
     * Update state
     */
    ctr_drbg_update_internal( ctx, seed );
    ctx->reseed_counter = 1;

    return 0;
}

int ctr_drbg_random_with_add(void *p_rng, uint8_t *output, size_t output_len, const uint8_t *additional, size_t add_len)
{
    int ret = 0;
    ctr_drbg_context_t *ctx = (ctr_drbg_context_t *) p_rng;
    uint8_t add_input[CTR_DRBG_SEEDLEN];
    uint8_t *p = output;
    uint8_t tmp[CTR_DRBG_BLOCKSIZE];
    int i;
    size_t use_len;

    if (output_len > CTR_DRBG_MAX_REQUEST) {
        return(POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG);
    }

    if (add_len > CTR_DRBG_MAX_INPUT) {
        return(POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG);
    }

    __stosb( add_input, 0, CTR_DRBG_SEEDLEN );

    if( ctx->reseed_counter > ctx->reseed_interval || ctx->prediction_resistance ) {
        if ((ret = ctr_drbg_reseed(ctx, additional, add_len)) != 0) {
            return(ret);
        }

        add_len = 0;
    }

    if (add_len > 0) {
        block_cipher_df( add_input, additional, add_len );
        ctr_drbg_update_internal( ctx, add_input );
    }

    while (output_len > 0) {
        /*
         * Increase counter
         */
        for (i = CTR_DRBG_BLOCKSIZE; i > 0; --i) {
            if (++ctx->counter[i - 1] != 0) {
                break;
            }
        }

        /*
         * Crypt counter block
         */
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, tmp );

        use_len = (output_len > CTR_DRBG_BLOCKSIZE ) ? CTR_DRBG_BLOCKSIZE : output_len;
        /*
         * Copy random block to destination
         */
        __movsb( p, tmp, use_len );
        p += use_len;
        output_len -= use_len;
    }

    ctr_drbg_update_internal( ctx, add_input );

    ctx->reseed_counter++;

    return 0;
}

int ctr_drbg_random( void *p_rng, uint8_t *output, size_t output_len )
{
    return ctr_drbg_random_with_add( p_rng, output, output_len, NULL, 0 );
}
