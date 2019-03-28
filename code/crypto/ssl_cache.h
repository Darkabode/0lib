#ifndef POLARSSL_SSL_CACHE_H
#define POLARSSL_SSL_CACHE_H

#include "ssl.h"

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(SSL_CACHE_DEFAULT_TIMEOUT)
#define SSL_CACHE_DEFAULT_TIMEOUT       86400   /*!< 1 day  */
#endif

#if !defined(SSL_CACHE_DEFAULT_MAX_ENTRIES)
#define SSL_CACHE_DEFAULT_MAX_ENTRIES      50   /*!< Maximum entries in cache */
#endif

/* \} name SECTION: Module settings */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ssl_cache_context ssl_cache_context;
typedef struct _ssl_cache_entry ssl_cache_entry;

/**
 * \brief   This structure is used for storing cache entries
 */
struct _ssl_cache_entry
{
    time_t timestamp;           /*!< entry timestamp    */
    ssl_session session;        /*!< entry session      */
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_buf peer_cert;         /*!< entry peer_cert    */
#endif
    ssl_cache_entry *next;      /*!< chain pointer      */
};

/**
 * \brief Cache context
 */
struct _ssl_cache_context
{
    ssl_cache_entry *chain;     /*!< start of the chain     */
    int timeout;                /*!< cache entry timeout    */
    int max_entries;            /*!< maximum entries        */
};

/**
 * \brief          Initialize an SSL cache context
 *
 * \param cache    SSL cache context
 */
void ssl_cache_init( ssl_cache_context *cache );

/**
 * \brief          Cache get callback implementation
 *                 (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param data     SSL cache context
 * \param session  session to retrieve entry for
 */
int ssl_cache_get( void *data, ssl_session *session );

/**
 * \brief          Cache set callback implementation
 *                 (Thread-safe if POLARSSL_THREADING_C is enabled)
 *
 * \param data     SSL cache context
 * \param session  session to store entry for
 */
int ssl_cache_set( void *data, const ssl_session *session );

/**
 * \brief          Set the cache timeout
 *                 (Default: SSL_CACHE_DEFAULT_TIMEOUT (1 day))
 *
 *                 A timeout of 0 indicates no timeout.
 *
 * \param cache    SSL cache context
 * \param timeout  cache entry timeout in seconds
 */
void ssl_cache_set_timeout( ssl_cache_context *cache, int timeout );

/**
 * \brief          Set the cache timeout
 *                 (Default: SSL_CACHE_DEFAULT_MAX_ENTRIES (50))
 *
 * \param cache    SSL cache context
 * \param max      cache entry maximum
 */
void ssl_cache_set_max_entries( ssl_cache_context *cache, int max );

/**
 * \brief          Free referenced items in a cache context and clear memory
 *
 * \param cache    SSL cache context
 */
void ssl_cache_free( ssl_cache_context *cache );

#ifdef __cplusplus
}
#endif

#endif /* ssl_cache.h */
