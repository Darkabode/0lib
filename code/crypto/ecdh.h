#ifndef POLARSSL_ECDH_H
#define POLARSSL_ECDH_H

#include "ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * When importing from an EC key, select if it is our key or the peer's key
 */
typedef enum
{
    POLARSSL_ECDH_OURS,
    POLARSSL_ECDH_THEIRS,
} ecdh_side;

/**
 * \brief           ECDH context structure
 */
typedef struct
{
    ecp_group grp;      /*!<  ellipitic curve used                          */
    mpi_t d;              /*!<  our secret value (private key)                */
    ecp_point Q;        /*!<  our public value (public key)                 */
    ecp_point Qp;       /*!<  peer's public value (public key)              */
    mpi_t z;              /*!<  shared secret                                 */
    int point_format;   /*!<  format for point export in TLS messages       */
    ecp_point Vi;       /*!<  blinding value (for later)                    */
    ecp_point Vf;       /*!<  un-blinding value (for later)                 */
    mpi_t _d;             /*!<  previous d (for later)                        */
}
ecdh_context;

/**
 * \brief           Generate a public key
 *
 * \param grp       ECP group
 * \param d         Destination MPI (secret exponent)
 * \param Q         Destination point (public key)
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a POLARSSL_ERR_ECP_XXX or POLARSSL_MPI_XXX error code
 */
int ecdh_gen_public( ecp_group *grp, mpi_t *d, ecp_point *Q,
                     int (*f_rng)(void *, uint8_t *, size_t),
                     void *p_rng );

/**
 * \brief           Compute shared secret
 *
 * \param grp       ECP group
 * \param z         Destination MPI (shared secret)
 * \param Q         Public key from other party
 * \param d         Our secret exponent
 * \param f_rng     RNG function (see notes)
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a POLARSSL_ERR_ECP_XXX or POLARSSL_MPI_XXX error code
 *
 * \note            If f_rng is not NULL, it is used to implement
 *                  countermeasures against potential elaborate timing
 *                  attacks, see \c ecp_mul() for details.
 */
int ecdh_compute_shared( ecp_group *grp, mpi_t *z,
                         const ecp_point *Q, const mpi_t *d,
                         int (*f_rng)(void *, uint8_t *, size_t),
                         void *p_rng );

/**
 * \brief           Initialize context
 *
 * \param ctx       Context to initialize
 */
void ecdh_init( ecdh_context *ctx );

/**
 * \brief           Free context
 *
 * \param ctx       Context to memory_free
 */
void ecdh_free( ecdh_context *ctx );

/**
 * \brief           Setup and write the ServerKeyExhange parameters
 *
 * \param ctx       ECDH context
 * \param olen      number of chars written
 * \param buf       destination buffer
 * \param blen      length of buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            This function assumes that ctx->grp has already been
 *                  properly set (for example using ecp_use_known_dp).
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_make_params( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng );

/**
 * \brief           Parse the ServerKeyExhange parameters
 *
 * \param ctx       ECDH context
 * \param buf       pointer to start of input buffer
 * \param end       one past end of buffer
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_read_params( ecdh_context *ctx,
                      const uint8_t **buf, const uint8_t *end );

/**
 * \brief           Setup an ECDH context from an EC key
 *
 * \param ctx       ECDH constext to set
 * \param key       EC key to use
 * \param side      Is it our key (1) or the peer's key (0) ?
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_get_params( ecdh_context *ctx, const ecp_keypair *key,
                     ecdh_side side );

/**
 * \brief           Setup and export the client's public value
 *
 * \param ctx       ECDH context
 * \param olen      number of bytes actually written
 * \param buf       destination buffer
 * \param blen      size of destination buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_make_public( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng );

/**
 * \brief           Parse and import the client's public value
 *
 * \param ctx       ECDH context
 * \param buf       start of input buffer
 * \param blen      length of input buffer
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_read_public( ecdh_context *ctx,
                      const uint8_t *buf, size_t blen );

/**
 * \brief           Derive and export the shared secret
 *
 * \param ctx       ECDH context
 * \param olen      number of bytes written
 * \param buf       destination buffer
 * \param blen      buffer length
 * \param f_rng     RNG function, see notes for \c ecdh_compute_shared()
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful, or an POLARSSL_ERR_ECP_XXX error code
 */
int ecdh_calc_secret( ecdh_context *ctx, size_t *olen,
                      uint8_t *buf, size_t blen,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int ecdh_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* ecdh.h */
