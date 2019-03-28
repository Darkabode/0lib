#ifndef POLARSSL_SHA512_H
#define POLARSSL_SHA512_H

  #define UL64(x) x##ui64
  typedef unsigned __int64 uint64_t;

#define POLARSSL_ERR_SHA512_FILE_IO_ERROR              -0x007A  /**< Read/write error in file. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA-512 context structure
 */
typedef struct
{
    uint64_t total[2];          /*!< number of bytes processed  */
    uint64_t state[8];          /*!< intermediate digest state  */
    uint8_t buffer[128];  /*!< data block being processed */

    uint8_t ipad[128];    /*!< HMAC: inner padding        */
    uint8_t opad[128];    /*!< HMAC: outer padding        */
    int is384;                  /*!< 0 => SHA-512, else SHA-384 */
}
sha512_context;

/**
 * \brief          SHA-512 context setup
 *
 * \param ctx      context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha512_starts( sha512_context *ctx, int is384 );

/**
 * \brief          SHA-512 process buffer
 *
 * \param ctx      SHA-512 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha512_update( sha512_context *ctx, const uint8_t *input, size_t ilen );

/**
 * \brief          SHA-512 final digest
 *
 * \param ctx      SHA-512 context
 * \param output   SHA-384/512 checksum result
 */
void sha512_finish( sha512_context *ctx, uint8_t output[64] );

/**
 * \brief          Output = SHA-512( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha512( const uint8_t *input, size_t ilen, uint8_t output[64], int is384 );

/**
 * \brief          SHA-512 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sha512_hmac_starts( sha512_context *ctx, const uint8_t *key, size_t keylen, int is384 );

/**
 * \brief          SHA-512 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sha512_hmac_update( sha512_context *ctx, const uint8_t *input, size_t ilen );

/**
 * \brief          SHA-512 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SHA-384/512 HMAC checksum result
 */
void sha512_hmac_finish( sha512_context *ctx, uint8_t output[64] );

/**
 * \brief          SHA-512 HMAC context reset
 *
 * \param ctx      HMAC context to be reset
 */
void sha512_hmac_reset( sha512_context *ctx );

/**
 * \brief          Output = HMAC-SHA-512( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA-384/512 result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void sha512_hmac( const uint8_t *key, size_t keylen,
                const uint8_t *input, size_t ilen,
                uint8_t output[64], int is384 );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int sha512_self_test( int verbose );

/* Internal use */
void sha512_process( sha512_context *ctx, const uint8_t data[128] );

#ifdef __cplusplus
}
#endif

#endif /* sha512.h */
