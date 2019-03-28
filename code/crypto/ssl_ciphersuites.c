#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_SSL_TLS_C)

#include "ssl_ciphersuites.h"
#include "ssl.h"

#include <stdlib.h>

/*
 * Ordered from most preferred to least preferred in terms of security.
 *
 * Current rule (except rc4, weak and null which come last):
 * 1. By key exchange:
 *    Forward-secure non-PSK > forward-secure PSK > other non-PSK > other PSK
 * 2. By key length and cipher:
 *    AES-256 > Camellia-256 > AES-128 > Camellia-128 > 3DES
 * 3. By cipher mode when relevant GCM > CBC
 * 4. By hash function used
 * 5. By key exchange/auth again: EC > non-EC
 */
static const int ciphersuite_preference[] =
{
    /* All AES-256 ephemeral suites */
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
 
    0
};

static const ssl_ciphersuite_t ciphersuite_definitions[] =
{
    { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
      POLARSSL_CIPHER_AES_256_CBC, POLARSSL_MD_SHA384, POLARSSL_KEY_EXCHANGE_ECDHE_RSA,
      SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3,
      SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3,
      0 },
    { 0, "", 0, 0, 0, 0, 0, 0, 0, 0 }
};


#define MAX_CIPHERSUITES    sizeof( ciphersuite_definitions     ) /         \
                            sizeof( ciphersuite_definitions[0]  )
static int supported_ciphersuites[MAX_CIPHERSUITES];
static int supported_init = 0;

const int *ssl_list_ciphersuites(void)
{
    /*
    * On initial call filter out all ciphersuites not supported by current
    * build based on presence in the ciphersuite_definitions.
    */
    if (supported_init == 0)
    {
        const int *p;
        int *q;

        for (p = ciphersuite_preference, q = supported_ciphersuites;
            *p != 0 && q < supported_ciphersuites + MAX_CIPHERSUITES - 1;
            p++)
        {
            if (ssl_ciphersuite_from_id(*p) != NULL)
                *(q++) = *p;
        }
        *q = 0;

        supported_init = 1;
    }

    return(supported_ciphersuites);
};

const ssl_ciphersuite_t *ssl_ciphersuite_from_string(
    const char *ciphersuite_name)
{
    const ssl_ciphersuite_t *cur = ciphersuite_definitions;

    if (NULL == ciphersuite_name)
        return(NULL);

    while (cur->id != 0)
    {
        if (0 == strcasecmp(cur->name, ciphersuite_name))
            return(cur);

        cur++;
    }

    return(NULL);
}

const ssl_ciphersuite_t *ssl_ciphersuite_from_id(int ciphersuite)
{
    const ssl_ciphersuite_t *cur = ciphersuite_definitions;

    while (cur->id != 0)
    {
        if (cur->id == ciphersuite)
            return(cur);

        cur++;
    }

    return(NULL);
}

const char *ssl_get_ciphersuite_name(const int ciphersuite_id)
{
    const ssl_ciphersuite_t *cur;

    cur = ssl_ciphersuite_from_id(ciphersuite_id);

    if (cur == NULL)
        return("unknown");

    return(cur->name);
}

int ssl_get_ciphersuite_id(const char *ciphersuite_name)
{
    const ssl_ciphersuite_t *cur;

    cur = ssl_ciphersuite_from_string(ciphersuite_name);

    if (cur == NULL)
        return(0);

    return(cur->id);
}
#if defined(POLARSSL_PK_C)
pk_type_t ssl_get_ciphersuite_sig_pk_alg( const ssl_ciphersuite_t *info )
{
    switch( info->key_exchange )
    {
        case POLARSSL_KEY_EXCHANGE_ECDHE_RSA:
            return( POLARSSL_PK_RSA );

        case POLARSSL_KEY_EXCHANGE_ECDH_RSA:
            return( POLARSSL_PK_ECKEY );

        default:
            return( POLARSSL_PK_NONE );
    }
}
#endif /* POLARSSL_PK_C */

int ssl_ciphersuite_uses_ec( const ssl_ciphersuite_t *info )
{
    switch( info->key_exchange )
    {
        case POLARSSL_KEY_EXCHANGE_ECDHE_RSA:
        case POLARSSL_KEY_EXCHANGE_ECDH_RSA:
            return( 1 );

        default:
            return( 0 );
    }
}

#endif /* POLARSSL_SSL_TLS_C */
