#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_SSL_CACHE_C)

#include "ssl_cache.h"

#include <stdlib.h>

void ssl_cache_init( ssl_cache_context *cache )
{
    __stosb( cache, 0, sizeof( ssl_cache_context ) );

    cache->timeout = SSL_CACHE_DEFAULT_TIMEOUT;
    cache->max_entries = SSL_CACHE_DEFAULT_MAX_ENTRIES;
}

int ssl_cache_get( void *data, ssl_session *session )
{
    int ret = 1;
    time_t t = time( NULL );
    ssl_cache_context *cache = (ssl_cache_context *) data;
    ssl_cache_entry *cur, *entry;

    cur = cache->chain;
    entry = NULL;

    while( cur != NULL )
    {
        entry = cur;
        cur = cur->next;

        if( cache->timeout != 0 &&
            (int) ( t - entry->timestamp ) > cache->timeout )
            continue;

        if( session->ciphersuite != entry->session.ciphersuite ||
            session->compression != entry->session.compression ||
            session->length != entry->session.length )
            continue;

        if( memcmp( session->id, entry->session.id,
                    entry->session.length ) != 0 )
            continue;

        __movsb( session->master, entry->session.master, 48 );

        session->verify_result = entry->session.verify_result;

#if defined(POLARSSL_X509_CRT_PARSE_C)
        /*
         * Restore peer certificate (without rest of the original chain)
         */
        if( entry->peer_cert.p != NULL )
        {
            session->peer_cert =
                (x509_crt *) memory_alloc( sizeof(x509_crt) );

            if( session->peer_cert == NULL )
            {
                ret = 1;
                goto exit;
            }

            x509_crt_init( session->peer_cert );
            if( x509_crt_parse( session->peer_cert, entry->peer_cert.p,
                                entry->peer_cert.len ) != 0 )
            {
                memory_free( session->peer_cert );
                session->peer_cert = NULL;
                ret = 1;
                goto exit;
            }
        }
#endif /* POLARSSL_X509_CRT_PARSE_C */

        ret = 0;
        goto exit;
    }

exit:
    return( ret );
}

int ssl_cache_set( void *data, const ssl_session *session )
{
    int ret = 1;
    time_t t = time( NULL ), oldest = 0;
    ssl_cache_entry *old = NULL;
    ssl_cache_context *cache = (ssl_cache_context *) data;
    ssl_cache_entry *cur, *prv;
    int count = 0;

    cur = cache->chain;
    prv = NULL;

    while( cur != NULL )
    {
        count++;

        if( cache->timeout != 0 &&
            (int) ( t - cur->timestamp ) > cache->timeout )
        {
            cur->timestamp = t;
            break; /* expired, reuse this slot, update timestamp */
        }

        if( memcmp( session->id, cur->session.id, cur->session.length ) == 0 )
            break; /* client reconnected, keep timestamp for session id */

        if( oldest == 0 || cur->timestamp < oldest )
        {
            oldest = cur->timestamp;
            old = cur;
        }

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        /*
         * Reuse oldest entry if max_entries reached
         */
        if( count >= cache->max_entries )
        {
            if( old == NULL )
            {
                ret = 1;
                goto exit;
            }

            cur = old;
        }
        else
        {
            /*
             * max_entries not reached, create new entry
             */
            cur = (ssl_cache_entry *)
                        memory_alloc( sizeof(ssl_cache_entry) );
            if( cur == NULL )
            {
                ret = 1;
                goto exit;
            }

            __stosb( cur, 0, sizeof(ssl_cache_entry) );

            if( prv == NULL )
                cache->chain = cur;
            else
                prv->next = cur;
        }

        cur->timestamp = t;
    }

    __movsb( &cur->session, session, sizeof( ssl_session ) );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * If we're reusing an entry, memory_free its certificate first
     */
    if( cur->peer_cert.p != NULL )
    {
        memory_free( cur->peer_cert.p );
        __stosb( &cur->peer_cert, 0, sizeof(x509_buf) );
    }

    /*
     * Store peer certificate
     */
    if( session->peer_cert != NULL )
    {
        cur->peer_cert.p = (uint8_t *)
                                memory_alloc( session->peer_cert->raw.len );
        if( cur->peer_cert.p == NULL )
        {
            ret = 1;
            goto exit;
        }

        __movsb( cur->peer_cert.p, session->peer_cert->raw.p,
                session->peer_cert->raw.len );
        cur->peer_cert.len = session->peer_cert->raw.len;

        cur->session.peer_cert = NULL;
    }
#endif /* POLARSSL_X509_CRT_PARSE_C */

    ret = 0;

exit:
    return( ret );
}

void ssl_cache_set_timeout( ssl_cache_context *cache, int timeout )
{
    if( timeout < 0 ) timeout = 0;

    cache->timeout = timeout;
}

void ssl_cache_set_max_entries( ssl_cache_context *cache, int max )
{
    if( max < 0 ) max = 0;

    cache->max_entries = max;
}

void ssl_cache_free( ssl_cache_context *cache )
{
    ssl_cache_entry *cur, *prv;

    cur = cache->chain;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        ssl_session_free( &prv->session );

#if defined(POLARSSL_X509_CRT_PARSE_C)
        if( prv->peer_cert.p != NULL )
            memory_free( prv->peer_cert.p );
#endif /* POLARSSL_X509_CRT_PARSE_C */

        memory_free( prv );
    }
}

#endif /* POLARSSL_SSL_CACHE_C */
