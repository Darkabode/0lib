#include "..\zmodule.h"
#include "config.h"
#include "ecdh.h"

/*
 * Generate public key: simple wrapper around ecp_gen_keypair
 */
int ecdh_gen_public( ecp_group *grp, mpi_t *d, ecp_point *Q,
                     int (*f_rng)(void *, uint8_t *, size_t),
                     void *p_rng )
{
    return ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int ecdh_compute_shared( ecp_group *grp, mpi_t *z,
                         const ecp_point *Q, const mpi_t *d,
                         int (*f_rng)(void *, uint8_t *, size_t),
                         void *p_rng )
{
    int ret;
    ecp_point P;

    ecp_point_init( &P );

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MPI_CHK( ecp_check_pubkey( grp, Q ) );

    MPI_CHK( ecp_mul( grp, &P, d, Q, f_rng, p_rng ) );

    if( ecp_is_zero( &P ) )
    {
        ret = POLARSSL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MPI_CHK( mpi_copy( z, &P.X ) );

cleanup:
    ecp_point_free( &P );

    return( ret );
}

/*
 * Initialize context
 */
void ecdh_init( ecdh_context *ctx )
{
    __stosb( ctx, 0, sizeof( ecdh_context ) );
}

/*
 * Free context
 */
void ecdh_free( ecdh_context *ctx )
{
    if( ctx == NULL )
        return;

    ecp_group_free( &ctx->grp );
    mpi_free      ( &ctx->d   );
    ecp_point_free( &ctx->Q   );
    ecp_point_free( &ctx->Qp  );
    mpi_free      ( &ctx->z   );
    ecp_point_free( &ctx->Vi  );
    ecp_point_free( &ctx->Vf  );
    mpi_free      ( &ctx->_d  );
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int ecdh_make_params( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng )
{
    int ret;
    size_t grp_len, pt_len;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    if( ( ret = ecp_tls_write_group( &ctx->grp, &grp_len, buf, blen ) )
                != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                     &pt_len, buf, blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return 0;
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int ecdh_read_params( ecdh_context *ctx,
                      const uint8_t **buf, const uint8_t *end )
{
    int ret;

    if( ( ret = ecp_tls_read_group( &ctx->grp, buf, end - *buf ) ) != 0 )
        return( ret );

    if( ( ret = ecp_tls_read_point( &ctx->grp, &ctx->Qp, buf, end - *buf ) )
                != 0 )
        return( ret );

    return 0;
}

/*
 * Get parameters from a keypair
 */
int ecdh_get_params( ecdh_context *ctx, const ecp_keypair *key,
                     ecdh_side side )
{
    int ret;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    /* If it's not our key, just import the public part as Qp */
    if( side == POLARSSL_ECDH_THEIRS )
        return( ecp_copy( &ctx->Qp, &key->Q ) );

    /* Our key: import public (as Q) and private parts */
    if( side != POLARSSL_ECDH_OURS )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecp_copy( &ctx->Q, &key->Q ) ) != 0 ||
        ( ret = mpi_copy( &ctx->d, &key->d ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Setup and export the client public value
 */
int ecdh_make_public( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    return ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                olen, buf, blen );
}

/*
 * Parse and import the client's public value
 */
int ecdh_read_public( ecdh_context *ctx,
                      const uint8_t *buf, size_t blen )
{
    int ret;
    const uint8_t *p = buf;

    if( ctx == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecp_tls_read_point( &ctx->grp, &ctx->Qp, &p, blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Derive and export the shared secret
 */
int ecdh_calc_secret( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
                                     f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( mpi_size( &ctx->z ) > blen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    return mpi_write_binary( &ctx->z, buf, *olen );
}
