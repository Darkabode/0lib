#ifndef POLARSSL_CIPHER_H
#define POLARSSL_CIPHER_H

#include "config.h"
#include <stdlib.h>

#define POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE            -0x6080  /**< The selected feature is not available. */
#define POLARSSL_ERR_CIPHER_BAD_INPUT_DATA                 -0x6100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_CIPHER_ALLOC_FAILED                   -0x6180  /**< Failed to allocate memory. */
#define POLARSSL_ERR_CIPHER_INVALID_PADDING                -0x6200  /**< Input data contains invalid padding and is rejected. */
#define POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED            -0x6280  /**< Decryption of block requires a full block. */
#define POLARSSL_ERR_CIPHER_AUTH_FAILED                    -0x6300  /**< Authentication failed (for AEAD modes). */

#define POLARSSL_CIPHER_VARIABLE_IV_LEN     0x01    /**< Cipher accepts IVs of variable length */
#define POLARSSL_CIPHER_VARIABLE_KEY_LEN    0x02    /**< Cipher accepts keys of variable length */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_CIPHER_ID_NONE = 0,
    POLARSSL_CIPHER_ID_NULL,
    POLARSSL_CIPHER_ID_AES,
} cipher_id_t;

typedef enum {
    POLARSSL_CIPHER_NONE = 0,
    POLARSSL_CIPHER_NULL,
    POLARSSL_CIPHER_AES_256_ECB,
    POLARSSL_CIPHER_AES_256_CBC,
} cipher_type_t;

typedef enum {
    POLARSSL_MODE_NONE = 0,
    POLARSSL_MODE_ECB,
    POLARSSL_MODE_CBC,
} cipher_mode_t;

typedef enum {
    POLARSSL_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default)        */
    POLARSSL_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding         */
    POLARSSL_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding             */
    POLARSSL_PADDING_ZEROS,         /**< zero padding (not reversible!) */
    POLARSSL_PADDING_NONE,          /**< never pad (full blocks only)   */
} cipher_padding_t;

typedef enum {
    POLARSSL_OPERATION_NONE = -1,
    POLARSSL_DECRYPT = 0,
    POLARSSL_ENCRYPT,
} operation_t;

enum {
    /** Undefined key length */
    POLARSSL_KEY_LENGTH_NONE = 0,
};

/** Maximum length of any IV, in bytes */
#define POLARSSL_MAX_IV_LENGTH      16
/** Maximum block size of any cipher, in bytes */
#define POLARSSL_MAX_BLOCK_LENGTH   16

/**
 * Base cipher information. The non-mode specific functions and values.
 */
typedef struct {

    /** Base Cipher type (e.g. POLARSSL_CIPHER_ID_AES) */
    cipher_id_t cipher;

    /** Encrypt using ECB */
    int (*ecb_func)( void *ctx, operation_t mode, const uint8_t *input, uint8_t *output );

    /** Encrypt using CBC */
    int (*cbc_func)( void *ctx, operation_t mode, size_t length, uint8_t *iv, const uint8_t *input, uint8_t *output );

    /** Set key for encryption purposes */
    int (*setkey_enc_func)( void *ctx, const uint8_t *key);

    /** Set key for decryption purposes */
    int (*setkey_dec_func)( void *ctx, const uint8_t *key);

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

} cipher_base_t;

/**
 * Cipher information. Allows cipher functions to be called in a generic way.
 */
typedef struct {
    /** Full cipher identifier (e.g. POLARSSL_CIPHER_AES_256_CBC) */
    cipher_type_t type;

    /** Cipher mode (e.g. POLARSSL_MODE_CBC) */
    cipher_mode_t mode;

    /** Cipher key length, in bits (default length for variable sized ciphers)
     *  (Includes parity bits for ciphers like DES) */
    uint32_t key_length;

    /** Name of the cipher */
    const char * name;

    /** IV/NONCE size, in bytes.
     *  For cipher that accept many sizes: recommended size */
    uint32_t iv_size;

    /** block size, in bytes */
    uint32_t block_size;

    /** Base cipher information and functions */
    const cipher_base_t *base;

} cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct {
    /** Information about the associated cipher */
    const cipher_info_t *cipher_info;

    /** Key length to use */
    int key_length;

    /** Operation that the context's key has been initialised for */
    operation_t operation;

    /** Padding functions to use, if relevant for cipher mode */
    void (*add_padding)( uint8_t *output, size_t olen, size_t data_len );
    int (*get_padding)( uint8_t *input, size_t ilen, size_t *data_len );

    /** Buffer for data that hasn't been encrypted yet */
    uint8_t unprocessed_data[POLARSSL_MAX_BLOCK_LENGTH];

    /** Number of bytes that still need processing */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode */
    uint8_t iv[POLARSSL_MAX_IV_LENGTH];

    /** IV size in bytes (for ciphers with variable-length IVs) */
    size_t iv_size;

    /** Cipher-specific context */
    void *cipher_ctx;
} cipher_context_t;

/**
 * \brief Returns the list of ciphers supported by the generic cipher module.
 *
 * \return              a statically allocated array of ciphers, the last entry
 *                      is 0.
 */
const int *cipher_list( void );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_name, or NULL if not found.
 */
const cipher_info_t *cipher_info_from_string( const char *cipher_name );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_type, or NULL if not found.
 */
const cipher_info_t *cipher_info_from_type( const cipher_type_t cipher_type );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher id, key size and mode.
 *
 * \param cipher_id     Id of the cipher to search for
 *                      (e.g. POLARSSL_CIPHER_ID_AES)
 * \param key_length    Length of the key in bits
 * \param mode          Cipher mode (e.g. POLARSSL_MODE_CBC)
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_type, or NULL if not found.
 */
const cipher_info_t *cipher_info_from_values( const cipher_id_t cipher_id,
                                              int key_length,
                                              const cipher_mode_t mode );

/**
 * \brief               Initialises and fills the cipher context structure with
 *                      the appropriate values.
 *
 * \param ctx           context to initialise. May not be NULL.
 * \param cipher_info   cipher to use.
 *
 * \return              0 on success,
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA on parameter failure,
 *                      POLARSSL_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context failed.
 */
int cipher_init_ctx( cipher_context_t *ctx, const cipher_info_t *cipher_info );

/**
 * \brief               Free the cipher-specific context of ctx. Freeing ctx
 *                      itself remains the responsibility of the caller.
 *
 * \param ctx           Free the cipher-specific context
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails.
 */
int cipher_free_ctx( cipher_context_t *ctx );

/**
 * \brief               Returns the block size of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              size of the cipher's blocks, or 0 if ctx has not been
 *                      initialised.
 */
static uint32_t cipher_get_block_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->block_size;
}

/**
 * \brief               Returns the mode of operation for the cipher.
 *                      (e.g. POLARSSL_MODE_CBC)
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              mode of operation, or POLARSSL_MODE_NONE if ctx
 *                      has not been initialised.
 */
static cipher_mode_t cipher_get_cipher_mode( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_MODE_NONE;

    return ctx->cipher_info->mode;
}

/**
 * \brief               Returns the size of the cipher's IV/NONCE in bytes.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              If IV has not been set yet: (recommended) IV size
 *                      (0 for ciphers not using IV/NONCE).
 *                      If IV has already been set: actual size.
 */
static int cipher_get_iv_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    if( ctx->iv_size != 0 )
        return (int) ctx->iv_size;

    return ctx->cipher_info->iv_size;
}

/**
 * \brief               Returns the type of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              type of the cipher, or POLARSSL_CIPHER_NONE if ctx has
 *                      not been initialised.
 */
static cipher_type_t cipher_get_type( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_CIPHER_NONE;

    return ctx->cipher_info->type;
}

/**
 * \brief               Returns the name of the given cipher, as a string.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              name of the cipher, or NULL if ctx was not initialised.
 */
static const char *cipher_get_name( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->name;
}

/**
 * \brief               Returns the key length of the cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              cipher's key length, in bits, or
 *                      POLARSSL_KEY_LENGTH_NONE if ctx has not been
 *                      initialised.
 */
static int cipher_get_key_size ( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_KEY_LENGTH_NONE;

    return ctx->cipher_info->key_length;
}

/**
 * \brief               Returns the operation of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              operation (POLARSSL_ENCRYPT or POLARSSL_DECRYPT),
 *                      or POLARSSL_OPERATION_NONE if ctx has not been
 *                      initialised.
 */
static operation_t cipher_get_operation( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return POLARSSL_OPERATION_NONE;

    return ctx->operation;
}

/**
 * \brief               Set the key to use with the given context.
 *
 * \param ctx           generic cipher context. May not be NULL. Must have been
 *                      initialised using cipher_context_from_type or
 *                      cipher_context_from_string.
 * \param key           The key to use.
 * \param key_length    key length to use, in bits.
 * \param operation     Operation that the key will be used for, either
 *                      POLARSSL_ENCRYPT or POLARSSL_DECRYPT.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails or a cipher specific
 *                      error code.
 */
int cipher_setkey( cipher_context_t *ctx, const uint8_t *key,
                   int key_length, const operation_t operation );

/**
 * \brief               Set padding mode, for cipher modes that use padding.
 *                      (Default: PKCS7 padding.)
 *
 * \param ctx           generic cipher context
 * \param mode          padding mode
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE
 *                      if selected padding mode is not supported, or
 *                      POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if the cipher mode
 *                      does not support padding.
 */
int cipher_set_padding_mode( cipher_context_t *ctx, cipher_padding_t mode );

/**
 * \brief               Set the initialization vector (IV) or nonce
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use (or NONCE_COUNTER for CTR-mode ciphers)
 * \param iv_len        IV length for ciphers with variable-size IV;
 *                      discarded by ciphers with fixed-size IV.
 *
 * \returns             O on success, or POLARSSL_ERR_CIPHER_BAD_INPUT_DATA
 *
 * \note                Some ciphers don't use IVs nor NONCE. For these
 *                      ciphers, this function has no effect.
 */
int cipher_set_iv( cipher_context_t *ctx,
                   const uint8_t *iv, size_t iv_len );

/**
 * \brief               Finish preparation of the given context
 *
 * \param ctx           generic cipher context
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int cipher_reset( cipher_context_t *ctx );

/**
 * \brief               Generic cipher update function. Encrypts/decrypts
 *                      using the given cipher context. Writes as many block
 *                      size'd blocks of data as possible to output. Any data
 *                      that cannot be written immediately will either be added
 *                      to the next block, or flushed when cipher_final is
 *                      called.
 *                      Exception: for POLARSSL_MODE_ECB, expects single block
 *                                 in size (e.g. 16 bytes for AES)
 *
 * \param ctx           generic cipher context
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data. Should be able to hold at
 *                      least ilen + block_size. Cannot be the same buffer as
 *                      input!
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      POLARSSL_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher or a cipher specific
 *                      error code.
 *
 * \note                If the underlying cipher is GCM, all calls to this
 *                      function, except the last one before cipher_finish(),
 *                      must have ilen a multiple of the block size.
 */
int cipher_update( cipher_context_t *ctx, const uint8_t *input,
                   size_t ilen, uint8_t *output, size_t *olen );

/**
 * \brief               Generic cipher finalisation function. If data still
 *                      needs to be flushed from an incomplete block, data
 *                      contained within it will be padded with the size of
 *                      the last block, and written to the output buffer.
 *
 * \param ctx           Generic cipher context
 * \param output        buffer to write data to. Needs block_size available.
 * \param olen          length of the data written to the output buffer.
 *
 * \returns             0 on success, POLARSSL_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED if decryption
 *                      expected a full block but was not provided one,
 *                      POLARSSL_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting or a cipher specific error code.
 */
int cipher_finish( cipher_context_t *ctx,
                   uint8_t *output, size_t *olen );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int cipher_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_CIPHER_H */
