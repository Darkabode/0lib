#include "..\zmodule.h"
#include "config.h"
#include "entropy.h"
#include "entropy_poll.h"

#include "timing.h"

int platform_entropy_poll( void *data, uint8_t *output, size_t len, size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if (fn_CryptAcquireContextW( &provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE) {
        return POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
    }

    if (fn_CryptGenRandom(provider, (DWORD)len, output) == FALSE) {
        return POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
    }

    fn_CryptReleaseContext( provider, 0 );
    *olen = len;

    return 0;
}

int hardclock_poll(void *data, uint8_t *output, size_t len, size_t *olen )
{
    ulong_t timer = hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(ulong_t) )
        return( 0 );

    __movsb( output, &timer, sizeof(ulong_t) );
    *olen = sizeof(ulong_t);

    return( 0 );
}
