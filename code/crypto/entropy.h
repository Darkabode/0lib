#ifndef POLARSSL_ENTROPY_H
#define POLARSSL_ENTROPY_H

#include "config.h"
#include "sha512.h"

#define POLARSSL_ERR_ENTROPY_SOURCE_FAILED                 -0x003C  /**< Critical entropy source failure. */
#define POLARSSL_ERR_ENTROPY_MAX_SOURCES                   -0x003E  /**< No more sources can be added. */
#define POLARSSL_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  /**< No sources have been added to poll. */
#define POLARSSL_ERR_ENTROPY_FILE_IO_ERROR                 -0x0058  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#define ENTROPY_MAX_SOURCES     20      /**< Maximum number of sources supported */
#define ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */

/* \} name SECTION: Module settings */

#define ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */

#define ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define ENTROPY_SOURCE_MANUAL   ENTROPY_MAX_SOURCES

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return          0 if no critical failures occurred,
 *                  POLARSSL_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*f_source_ptr)(void *data, uint8_t *output, size_t len, size_t *olen);

/**
 * \brief           Entropy source state
 */
typedef struct
{
    f_source_ptr    f_source;   /**< The entropy source callback */
    void *          p_source;   /**< The callback data pointer */
    size_t          size;       /**< Amount received */
    size_t          threshold;  /**< Minimum level required before release */
} source_state_t;

/**
 * \brief           Entropy context structure
 */
typedef struct
{
    sha512_context  accumulator;
    int             source_count;
    source_state_t    source[ENTROPY_MAX_SOURCES];
} entropy_context_t;

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
void entropy_init( entropy_context_t *ctx );

/**
 * \brief           Free the data in the context
 *
 * \param ctx       Entropy context to memory_free
 */
void entropy_free( entropy_context_t *ctx );

/**
 * \brief           Adds an entropy source to poll
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with entropy_func() )
 *
 * \return          0 if successful or POLARSSL_ERR_ENTROPY_MAX_SOURCES
 */
int entropy_add_source( entropy_context_t *ctx, f_source_ptr f_source, void *p_source, size_t threshold );

/**
 * \brief           Trigger an extra gather poll for the accumulator
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 *
 * \return          0 if successful, or POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
int entropy_gather( entropy_context_t *ctx );

/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: ENTROPY_BLOCK_SIZE)
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Length of buffer
 *
 * \return          0 if successful, or POLARSSL_ERR_ENTROPY_SOURCE_FAILED
 */
int entropy_func( void *data, uint8_t *output, size_t len );

/**
 * \brief           Add data to the accumulator manually
 *                  (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param ctx       Entropy context
 * \param data      Data to add
 * \param len       Length of data
 *
 * \return          0 if successful
 */
int entropy_update_manual( entropy_context_t *ctx, const uint8_t *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* entropy.h */
