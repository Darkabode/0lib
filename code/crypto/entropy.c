#include "..\zmodule.h"
#include "config.h"

#include "entropy.h"
#include "entropy_poll.h"


#define ENTROPY_MAX_LOOP    256     /**< Maximum amount to loop before error */

void entropy_init( entropy_context_t *ctx )
{
    __stosb( ctx, 0, sizeof(entropy_context_t) );

    sha512_starts( &ctx->accumulator, 0 );

    entropy_add_source( ctx, platform_entropy_poll, NULL, ENTROPY_MIN_PLATFORM );
    entropy_add_source( ctx, hardclock_poll, NULL, ENTROPY_MIN_HARDCLOCK );
}

void entropy_free( entropy_context_t *ctx )
{
    ((void) ctx);
}

int entropy_add_source( entropy_context_t *ctx, f_source_ptr f_source, void *p_source, size_t threshold )
{
    int index, ret = 0;

    index = ctx->source_count;
    if( index >= ENTROPY_MAX_SOURCES )
    {
        ret = POLARSSL_ERR_ENTROPY_MAX_SOURCES;
        goto exit;
    }

    ctx->source[index].f_source = f_source;
    ctx->source[index].p_source = p_source;
    ctx->source[index].threshold = threshold;

    ctx->source_count++;

exit:
    return( ret );
}

/*
 * Entropy accumulator update
 */
static int entropy_update( entropy_context_t *ctx, uint8_t source_id, const uint8_t *data, size_t len )
{
    uint8_t header[2];
    uint8_t tmp[ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const uint8_t *p = data;

    if (use_len > ENTROPY_BLOCK_SIZE) {
        sha512( data, len, tmp, 0 );
        p = tmp;
        use_len = ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

    sha512_update( &ctx->accumulator, header, 2 );
    sha512_update( &ctx->accumulator, p, use_len );

    return 0;
}

int entropy_update_manual( entropy_context_t *ctx, const uint8_t *data, size_t len )
{
    int ret;

    ret = entropy_update( ctx, ENTROPY_SOURCE_MANUAL, data, len );

    return ( ret );
}

/*
 * Run through the different sources to add entropy to our accumulator
 */
static int entropy_gather_internal( entropy_context_t *ctx )
{
    int ret, i;
    uint8_t buf[ENTROPY_MAX_GATHER];
    size_t olen;

    if( ctx->source_count == 0 )
        return( POLARSSL_ERR_ENTROPY_NO_SOURCES_DEFINED );

    /*
     * Run through our entropy sources
     */
    for( i = 0; i < ctx->source_count; i++ )
    {
        olen = 0;
        if ( ( ret = ctx->source[i].f_source( ctx->source[i].p_source,
                        buf, ENTROPY_MAX_GATHER, &olen ) ) != 0 )
        {
            return( ret );
        }

        /*
         * Add if we actually gathered something
         */
        if( olen > 0 )
        {
            entropy_update( ctx, (uint8_t) i, buf, olen );
            ctx->source[i].size += olen;
        }
    }

    return( 0 );
}

/*
 * Thread-safe wrapper for entropy_gather_internal()
 */
int entropy_gather( entropy_context_t *ctx )
{
    int ret;

    ret = entropy_gather_internal( ctx );

    return( ret );
}

int entropy_func( void *data, uint8_t *output, size_t len )
{
    int ret, count = 0, i, reached;
    entropy_context_t *ctx = (entropy_context_t *) data;
    uint8_t buf[ENTROPY_BLOCK_SIZE];

    if( len > ENTROPY_BLOCK_SIZE )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    /*
     * Always gather extra entropy before a call
     */
    do
    {
        if( count++ > ENTROPY_MAX_LOOP )
        {
            ret = POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if( ( ret = entropy_gather_internal( ctx ) ) != 0 )
            goto exit;

        reached = 0;

        for( i = 0; i < ctx->source_count; i++ )
            if( ctx->source[i].size >= ctx->source[i].threshold )
                reached++;
    }
    while( reached != ctx->source_count );

    __stosb( buf, 0, ENTROPY_BLOCK_SIZE );

    sha512_finish( &ctx->accumulator, buf );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    __stosb( &ctx->accumulator, 0, sizeof( sha512_context ) );
    sha512_starts( &ctx->accumulator, 0 );
    sha512_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );

    /*
     * Perform second SHA-512 on entropy
     */
    sha512( buf, ENTROPY_BLOCK_SIZE, buf, 0 );

    for( i = 0; i < ctx->source_count; i++ )
        ctx->source[i].size = 0;

    __movsb( output, buf, len );

    ret = 0;

exit:
    return ret;
}
