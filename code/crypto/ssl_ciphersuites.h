#ifndef POLARSSL_SSL_CIPHERSUITES_H
#define POLARSSL_SSL_CIPHERSUITES_H

#include "pk.h"
#include "cipher.h"
#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supported ciphersuites (Official IANA names)
 */

#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    0xC028 /**< TLS 1.2 */


typedef enum {
    POLARSSL_KEY_EXCHANGE_ECDHE_RSA = 1,
    POLARSSL_KEY_EXCHANGE_ECDH_RSA,
} key_exchange_type_t;

typedef struct _ssl_ciphersuite_t ssl_ciphersuite_t;

#define POLARSSL_CIPHERSUITE_WEAK   0x01    /**< Weak ciphersuite flag      */

/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct _ssl_ciphersuite_t
{
    int id;
    const char * name;

    cipher_type_t cipher;
    md_type_t mac;
    key_exchange_type_t key_exchange;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;

    uint8_t flags;
};

const int *ssl_list_ciphersuites( void );

const ssl_ciphersuite_t *ssl_ciphersuite_from_string( const char *ciphersuite_name );
const ssl_ciphersuite_t *ssl_ciphersuite_from_id( int ciphersuite_id );

#if defined(POLARSSL_PK_C)
pk_type_t ssl_get_ciphersuite_sig_pk_alg( const ssl_ciphersuite_t *info );
#endif

int ssl_ciphersuite_uses_ec( const ssl_ciphersuite_t *info );
int ssl_ciphersuite_uses_psk( const ssl_ciphersuite_t *info );

#ifdef __cplusplus
}
#endif

#endif /* ssl_ciphersuites.h */
