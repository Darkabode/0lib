#include "..\zmodule.h"
#include "config.h"

#include "rsa.h"
#include "oid.h"

#include <stdlib.h>

/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context_t *ctx, int hash_id )
{
    __stosb( ctx, 0, sizeof( rsa_context_t ) );
    ctx->hash_id = hash_id;
}

/*
 * Generate an RSA keypair
 */
int rsa_gen_key(rsa_context_t *ctx, int (*f_rng)(void *, uint8_t *, size_t), void *p_rng, uint32_t nbits, int exponent)
{
    int ret;
    mpi_t P1, Q1, H, G;

    if (f_rng == NULL || nbits < 128 || exponent < 3) {
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);
    }

    mpi_init( &P1 );
    mpi_init( &Q1 );
    mpi_init( &H );
    mpi_init( &G );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    } while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:
    mpi_free( &P1 );
    mpi_free( &Q1 );
    mpi_free( &H );
    mpi_free( &G );

    if (ret != 0) {
        rsa_free(ctx);
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED + ret );
    }

    return 0;
}

/*
 * Check a public RSA key
 */
int rsa_check_pubkey(const rsa_context_t* ctx)
{
    if (!ctx->N.p || !ctx->E.p) {
        return(POLARSSL_ERR_RSA_KEY_CHECK_FAILED);
    }

    if ((ctx->N.p[0] & 1) == 0 || (ctx->E.p[0] & 1) == 0) {
        return(POLARSSL_ERR_RSA_KEY_CHECK_FAILED);
    }

    if (mpi_msb(&ctx->N) < 128 || mpi_msb(&ctx->N) > POLARSSL_MPI_MAX_BITS) {
        return(POLARSSL_ERR_RSA_KEY_CHECK_FAILED);
    }

    if (mpi_msb(&ctx->E) < 2 || mpi_cmp_mpi(&ctx->E, &ctx->N) >= 0) {
        return(POLARSSL_ERR_RSA_KEY_CHECK_FAILED);
    }

    return 0;
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( const rsa_context_t *ctx )
{
    int ret;
    mpi_t PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    mpi_init( &PQ ); mpi_init( &DE ); mpi_init( &P1 ); mpi_init( &Q1 );
    mpi_init( &H  ); mpi_init( &I  ); mpi_init( &G  ); mpi_init( &G2 );
    mpi_init( &L1 ); mpi_init( &L2 ); mpi_init( &DP ); mpi_init( &DQ );
    mpi_init( &QP );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    MPI_CHK( mpi_mod_mpi( &DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &QP, &ctx->Q, &ctx->P ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) != 0 ||
        mpi_cmp_mpi( &DP, &ctx->DP ) != 0 ||
        mpi_cmp_mpi( &DQ, &ctx->DQ ) != 0 ||
        mpi_cmp_mpi( &QP, &ctx->QP ) != 0 ||
        mpi_cmp_int( &L2, 0 ) != 0 ||
        mpi_cmp_int( &I, 1 ) != 0 ||
        mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = POLARSSL_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    mpi_free( &PQ ); mpi_free( &DE ); mpi_free( &P1 ); mpi_free( &Q1 );
    mpi_free( &H  ); mpi_free( &I  ); mpi_free( &G  ); mpi_free( &G2 );
    mpi_free( &L1 ); mpi_free( &L2 ); mpi_free( &DP ); mpi_free( &DQ );
    mpi_free( &QP );

    if( ret == POLARSSL_ERR_RSA_KEY_CHECK_FAILED )
        return( ret );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED + ret );

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context_t *ctx,
                const uint8_t *input,
                uint8_t *output )
{
    int ret;
    size_t olen;
    mpi_t T;

    mpi_init( &T );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology—CRYPTO’96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
int rsa_prepare_blinding( rsa_context_t *ctx, mpi_t *Vi, mpi_t *Vf, int (*f_rng)(void *, uint8_t *, size_t), void *p_rng )
{
    int ret, count = 0;

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
        MPI_CHK( mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MPI_CHK( mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MPI_CHK( mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MPI_CHK( mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto done;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
            return( POLARSSL_ERR_RSA_RNG_FAILED );

        MPI_CHK( mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );
        MPI_CHK( mpi_gcd( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    } while( mpi_cmp_int( &ctx->Vi, 1 ) != 0 );

    /* Blinding value: Vi =  Vf^(-e) mod N */
    MPI_CHK( mpi_inv_mod( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    MPI_CHK( mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );

done:
    if( Vi != &ctx->Vi )
    {
        MPI_CHK( mpi_copy( Vi, &ctx->Vi ) );
        MPI_CHK( mpi_copy( Vf, &ctx->Vf ) );
    }

cleanup:
    return( ret );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context_t *ctx,
                 int (*f_rng)(void *, uint8_t *, size_t),
                 void *p_rng,
                 const uint8_t *input,
                 uint8_t *output )
{
    int ret;
    size_t olen;
    mpi_t T, T1, T2;
    mpi_t *Vi, *Vf;

    /*
     * When using the Chinese Remainder Theorem, we use blinding values.
     * Without threading, we just read them directly from the context,
     * otherwise we make a local copy in order to reduce locking contention.
     */
    Vi = &ctx->Vi;
    Vf = &ctx->Vf;

    mpi_init( &T ); mpi_init( &T1 ); mpi_init( &T2 );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );
    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    if( f_rng != NULL )
    {
        /*
         * Blinding
         * T = T * Vi mod N
         */
        MPI_CHK( rsa_prepare_blinding( ctx, Vi, Vf, f_rng, p_rng ) );
        MPI_CHK( mpi_mul_mpi( &T, &T, Vi ) );
        MPI_CHK( mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * T = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );

    if( f_rng != NULL )
    {
        /*
         * Unblind
         * T = T * Vf mod N
         */
        MPI_CHK( mpi_mul_mpi( &T, &T, Vf ) );
        MPI_CHK( mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:
    mpi_free( &T ); mpi_free( &T1 ); mpi_free( &T2 );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context_t *ctx, int (*f_rng)(void *, uint8_t *, size_t), void *p_rng, int mode, size_t ilen, const uint8_t *input, uint8_t *output )
{
    size_t nb_pad, olen;
    int ret;
    uint8_t *p = output;

    olen = ctx->len;

    if (olen < ilen + 11)
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    if (mode == RSA_PUBLIC)
    {
        *p++ = RSA_CRYPT;

        while (nb_pad-- > 0)
        {
            int rng_dl = 100;

            do {
                ret = f_rng(p_rng, p, 1);
            } while (*p == 0 && --rng_dl && ret == 0);

            // Check if RNG failed to generate data
            //
            if (rng_dl == 0 || ret != 0)
                return POLARSSL_ERR_RSA_RNG_FAILED + ret;

            p++;
        }
    }
    else
    {
        *p++ = RSA_SIGN;

        while (nb_pad-- > 0)
            *p++ = 0xFF;
    }

    *p++ = 0;
    __movsb(p, input, ilen);

    return((mode == RSA_PUBLIC) ? rsa_public(ctx, output, output) : rsa_private(ctx, f_rng, p_rng, output, output));
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context_t *ctx,
                       int (*f_rng)(void *, uint8_t *, size_t),
                       void *p_rng,
                       int mode, size_t *olen,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t output_max_len)
{
    int ret;
    size_t ilen, pad_count = 0, i;
    uint8_t *p, bad, pad_done = 0;
    uint8_t buf[POLARSSL_MPI_MAX_SIZE];

    ilen = ctx->len;

    if (ilen < 16 || ilen > sizeof(buf))
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

    ret = (mode == RSA_PUBLIC)
        ? rsa_public(ctx, input, buf)
        : rsa_private(ctx, f_rng, p_rng, input, buf);

    if (ret != 0)
        return(ret);

    p = buf;
    bad = 0;

    /*
    * Check and get padding len in "constant-time"
    */
    bad |= *p++; /* First byte must be 0 */

    /* This test does not depend on secret data */
    if (mode == RSA_PRIVATE)
    {
        bad |= *p++ ^ RSA_CRYPT;

        /* Get padding len, but always read till end of buffer
        * (minus one, for the 00 byte) */
        for (i = 0; i < ilen - 3; i++)
        {
            pad_done |= (p[i] == 0);
            pad_count += (pad_done == 0);
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }
    else
    {
        bad |= *p++ ^ RSA_SIGN;

        /* Get padding len, but always read till end of buffer
        * (minus one, for the 00 byte) */
        for (i = 0; i < ilen - 3; i++)
        {
            pad_done |= (p[i] != 0xFF);
            pad_count += (pad_done == 0);
        }

        p += pad_count;
        bad |= *p++; /* Must be zero */
    }

    if (bad)
        return(POLARSSL_ERR_RSA_INVALID_PADDING);

    if (ilen - (p - buf) > output_max_len)
        return(POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE);

    *olen = ilen - (p - buf);
    __movsb(output, p, *olen);

    return(0);
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context_t *ctx, int (*f_rng)(void *, uint8_t *, size_t), void *p_rng, int mode, md_type_t md_alg, uint32_t hashlen, const uint8_t *hash, uint8_t *sig )
{
    size_t nb_pad, olen, oid_size = 0;
    uint8_t *p = sig;
    const char *oid;

    olen = ctx->len;
    nb_pad = olen - 3;

    if (md_alg != POLARSSL_MD_NONE)
    {
        const md_info_t *md_info = md_info_from_type(md_alg);
        if (md_info == NULL)
            return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

        if (oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0)
            return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

        nb_pad -= 10 + oid_size;

        hashlen = md_get_size(md_info);
    }

    nb_pad -= hashlen;

    if ((nb_pad < 8) || (nb_pad > olen))
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

    *p++ = 0;
    *p++ = RSA_SIGN;
    __stosb(p, 0xFF, nb_pad);
    p += nb_pad;
    *p++ = 0;

    if (md_alg == POLARSSL_MD_NONE)
    {
        __movsb(p, hash, hashlen);
    }
    else
    {
        /*
        * DigestInfo ::= SEQUENCE {
        *   digestAlgorithm DigestAlgorithmIdentifier,
        *   digest Digest }
        *
        * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
        *
        * Digest ::= OCTET STRING
        */
        *p++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
        *p++ = (uint8_t)(0x08 + oid_size + hashlen);
        *p++ = ASN1_SEQUENCE | ASN1_CONSTRUCTED;
        *p++ = (uint8_t)(0x04 + oid_size);
        *p++ = ASN1_OID;
        *p++ = oid_size & 0xFF;
        __movsb(p, oid, oid_size);
        p += oid_size;
        *p++ = ASN1_NULL;
        *p++ = 0x00;
        *p++ = ASN1_OCTET_STRING;
        *p++ = hashlen;
        __movsb(p, hash, hashlen);
    }

    return((mode == RSA_PUBLIC) ? rsa_public(ctx, sig, sig) : rsa_private(ctx, f_rng, p_rng, sig, sig));
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context_t *ctx,
                      int (*f_rng)(void *, uint8_t *, size_t),
                      void *p_rng,
                      int mode,
                      md_type_t md_alg,
                      uint32_t hashlen,
                      const uint8_t *hash,
                      const uint8_t *sig )
{
    int ret;
    size_t len, siglen, asn1_len;
    uint8_t *p, *end;
    uint8_t buf[POLARSSL_MPI_MAX_SIZE];
    md_type_t msg_md_alg;
    const md_info_t *md_info;
    asn1_buf oid;

    siglen = ctx->len;

    if (siglen < 16 || siglen > sizeof(buf))
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);

    ret = (mode == RSA_PUBLIC)
        ? rsa_public(ctx, sig, buf)
        : rsa_private(ctx, f_rng, p_rng, sig, buf);

    if (ret != 0)
        return(ret);

    p = buf;

    if (*p++ != 0 || *p++ != RSA_SIGN)
        return(POLARSSL_ERR_RSA_INVALID_PADDING);

    while (*p != 0)
    {
        if (p >= buf + siglen - 1 || *p != 0xFF)
            return(POLARSSL_ERR_RSA_INVALID_PADDING);
        p++;
    }
    p++;

    len = siglen - (p - buf);

    if (len == hashlen && md_alg == POLARSSL_MD_NONE)
    {
        if (memcmp(p, hash, hashlen) == 0)
            return(0);
        else
            return(POLARSSL_ERR_RSA_VERIFY_FAILED);
    }

    md_info = md_info_from_type(md_alg);
    if (md_info == NULL)
        return(POLARSSL_ERR_RSA_BAD_INPUT_DATA);
    hashlen = md_get_size(md_info);

    end = p + len;

    // Parse the ASN.1 structure inside the PKCS#1 v1.5 structure
    //
    if ((ret = asn1_get_tag(&p, end, &asn1_len,
        ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if (asn1_len + 2 != len)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if ((ret = asn1_get_tag(&p, end, &asn1_len,
        ASN1_CONSTRUCTED | ASN1_SEQUENCE)) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if (asn1_len + 6 + hashlen != len)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if ((ret = asn1_get_tag(&p, end, &oid.len, ASN1_OID)) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    oid.p = p;
    p += oid.len;

    if (oid_get_md_alg(&oid, &msg_md_alg) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if (md_alg != msg_md_alg)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    /*
    * assume the algorithm parameters must be NULL
    */
    if ((ret = asn1_get_tag(&p, end, &asn1_len, ASN1_NULL)) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if ((ret = asn1_get_tag(&p, end, &asn1_len, ASN1_OCTET_STRING)) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if (asn1_len != hashlen)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    if (memcmp(p, hash, hashlen) != 0)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    p += hashlen;

    if (p != end)
        return(POLARSSL_ERR_RSA_VERIFY_FAILED);

    return(0);
}

/*
 * Copy the components of an RSA key
 */
int rsa_copy( rsa_context_t *dst, const rsa_context_t *src )
{
    int ret;

    dst->ver = src->ver;
    dst->len = src->len;

    MPI_CHK( mpi_copy( &dst->N, &src->N ) );
    MPI_CHK( mpi_copy( &dst->E, &src->E ) );

    MPI_CHK( mpi_copy( &dst->D, &src->D ) );
    MPI_CHK( mpi_copy( &dst->P, &src->P ) );
    MPI_CHK( mpi_copy( &dst->Q, &src->Q ) );
    MPI_CHK( mpi_copy( &dst->DP, &src->DP ) );
    MPI_CHK( mpi_copy( &dst->DQ, &src->DQ ) );
    MPI_CHK( mpi_copy( &dst->QP, &src->QP ) );

    MPI_CHK( mpi_copy( &dst->RN, &src->RN ) );
    MPI_CHK( mpi_copy( &dst->RP, &src->RP ) );
    MPI_CHK( mpi_copy( &dst->RQ, &src->RQ ) );

    MPI_CHK( mpi_copy( &dst->Vi, &src->Vi ) );
    MPI_CHK( mpi_copy( &dst->Vf, &src->Vf ) );

    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        rsa_free( dst );

    return( ret );
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context_t *ctx )
{
    mpi_free( &ctx->Vi ); mpi_free( &ctx->Vf );
    mpi_free( &ctx->RQ ); mpi_free( &ctx->RP ); mpi_free( &ctx->RN );
    mpi_free( &ctx->QP ); mpi_free( &ctx->DQ ); mpi_free( &ctx->DP );
    mpi_free( &ctx->Q  ); mpi_free( &ctx->P  ); mpi_free( &ctx->D );
    mpi_free( &ctx->E  ); mpi_free( &ctx->N  );
}
