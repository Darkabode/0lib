#ifndef POLARSSL_CTR_DRBG_H
#define POLARSSL_CTR_DRBG_H

#include "aes.h"

#define POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  /**< The entropy source failed. */
#define POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036  /**< Too many random requested in single call. */
#define POLARSSL_ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038  /**< Input too large (Entropy + additional). */
#define POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A  /**< Read/write error in file. */

#define CTR_DRBG_BLOCKSIZE          16      /**< Block size used by the cipher                  */
#define CTR_DRBG_KEYSIZE            32      /**< Key size used by the cipher                    */
#define CTR_DRBG_KEYBITS            ( CTR_DRBG_KEYSIZE * 8 )
#define CTR_DRBG_SEEDLEN            ( CTR_DRBG_KEYSIZE + CTR_DRBG_BLOCKSIZE )
                                            /**< The seed length (counter + AES key)            */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#define CTR_DRBG_ENTROPY_LEN        48      /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
#define CTR_DRBG_RESEED_INTERVAL    10000   /**< Interval before reseed is performed by default */
#define CTR_DRBG_MAX_INPUT          256     /**< Maximum number of additional input bytes */
#define CTR_DRBG_MAX_REQUEST        1024    /**< Maximum number of requested bytes per call */
#define CTR_DRBG_MAX_SEED_INPUT     384     /**< Maximum size of (re)seed buffer */

/* \} name SECTION: Module settings */

#define CTR_DRBG_PR_OFF             0       /**< No prediction resistance       */
#define CTR_DRBG_PR_ON              1       /**< Prediction resistance enabled  */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint8_t counter[16];  /*!<  counter (V)       */
    int reseed_counter;         /*!<  reseed counter    */
    int prediction_resistance;  /*!<  enable prediction resistance (Automatic
                                      reseed before every random generation)  */
    size_t entropy_len;         /*!<  amount of entropy grabbed on each
                                      (re)seed          */
    int reseed_interval;        /*!<  reseed interval   */

    aes_context_t aes_ctx;        /*!<  AES context       */

    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, uint8_t *, size_t);

    void *p_entropy;            /*!<  context for the entropy function */
} ctr_drbg_context_t;

/**
 * \brief               CTR_DRBG initialization
 *
 * Note: Personalization data can be provided in addition to the more generic
 *       entropy source to make this instantiation as unique as possible.
 *
 * \param ctx           CTR_DRBG context to be initialized
 * \param f_entropy     Entropy callback (p_entropy, buffer to fill, buffer
 *                      length)
 * \param p_entropy     Entropy context
 * \param custom        Personalization data (Device specific identifiers)
 *                      (Can be NULL)
 * \param len           Length of personalization data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
int ctr_drbg_init( ctr_drbg_context_t *ctx,
                   int (*f_entropy)(void *, uint8_t *, size_t),
                   void *p_entropy,
                   const uint8_t *custom,
                   size_t len );

/**
 * \brief               Enable / disable prediction resistance (Default: Off)
 *
 * Note: If enabled, entropy is used for ctx->entropy_len before each call!
 *       Only use this if you have ample supply of good entropy!
 *
 * \param ctx           CTR_DRBG context
 * \param resistance    CTR_DRBG_PR_ON or CTR_DRBG_PR_OFF
 */
void ctr_drbg_set_prediction_resistance( ctr_drbg_context_t *ctx,
                                         int resistance );

/**
 * \brief               Set the amount of entropy grabbed on each (re)seed
 *                      (Default: CTR_DRBG_ENTROPY_LEN)
 *
 * \param ctx           CTR_DRBG context
 * \param len           Amount of entropy to grab
 */
void ctr_drbg_set_entropy_len( ctr_drbg_context_t *ctx,
                               size_t len );

/**
 * \brief               Set the reseed interval
 *                      (Default: CTR_DRBG_RESEED_INTERVAL)
 *
 * \param ctx           CTR_DRBG context
 * \param interval      Reseed interval
 */
void ctr_drbg_set_reseed_interval( ctr_drbg_context_t *ctx,
                                   int interval );

/**
 * \brief               CTR_DRBG reseeding (extracts data from entropy source)
 *
 * \param ctx           CTR_DRBG context
 * \param additional    Additional data to add to state (Can be NULL)
 * \param len           Length of additional data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
int ctr_drbg_reseed( ctr_drbg_context_t *ctx,
                     const uint8_t *additional, size_t len );

/**
 * \brief               CTR_DRBG update state
 *
 * \param ctx           CTR_DRBG context
 * \param additional    Additional data to update state with
 * \param add_len       Length of additional data
 */
void ctr_drbg_update( ctr_drbg_context_t *ctx,
                      const uint8_t *additional, size_t add_len );

/**
 * \brief               CTR_DRBG generate random with additional update input
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         CTR_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 * \param additional    Additional data to update with (Can be NULL)
 * \param add_len       Length of additional data
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG
 */
int ctr_drbg_random_with_add( void *p_rng,
                              uint8_t *output, size_t output_len,
                              const uint8_t *additional, size_t add_len );

/**
 * \brief               CTR_DRBG generate random
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         CTR_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      POLARSSL_ERR_CTR_DRBG_REQUEST_TOO_BIG
 */
int ctr_drbg_random( void *p_rng, uint8_t *output, size_t output_len );


/* Internal functions (do not call directly) */
int ctr_drbg_init_entropy_len( ctr_drbg_context_t *, int (*)(void *, uint8_t *, size_t), void *, const uint8_t *, size_t, size_t );

#ifdef __cplusplus
}
#endif

#endif /* ctr_drbg.h */
