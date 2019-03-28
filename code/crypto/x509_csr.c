#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_X509_CSR_PARSE_C)

#include "x509_csr.h"
#include "oid.h"
#if defined(POLARSSL_PEM_PARSE_C)
#include "pem.h"
#endif

#include <stdlib.h>


/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( uint8_t **p,
                             const uint8_t *end,
                             int *ver )
{
    int ret;

    if( ( ret = asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( POLARSSL_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Parse a CSR
 */
int x509_csr_parse_der( x509_csr *csr, const uint8_t *buf, size_t buflen )
{
    int ret;
    size_t len;
    uint8_t *p, *end;

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

    x509_csr_init( csr );

    /*
    * first copy the raw DER data
    */
    p = (uint8_t*)memory_alloc(len = buflen);
    __movsb(p, buf, buflen);

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    csr->version++;

    if( csr->version != 1 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_UNKNOWN_VERSION );
    }

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }
    // TODO Parse Attributes / extension requests

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = x509_get_alg_null( &p, end, &csr->sig_oid ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = x509_get_sig_alg( &csr->sig_oid, &csr->sig_md,
                                  &csr->sig_pk ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
* Parse a CSR, allowing for PEM or raw DER encoding
*/
int x509_csr_parse(x509_csr *csr, const uint8_t *buf, size_t buflen)
{
    int ret;
#if defined(POLARSSL_PEM_PARSE_C)
    size_t use_len;
    pem_context pem;
#endif

    /*
    * Check for valid input
    */
    if (csr == NULL || buf == NULL)
        return(POLARSSL_ERR_X509_BAD_INPUT_DATA);

#if defined(POLARSSL_PEM_PARSE_C)
    pem_init(&pem);
    ret = pem_read_buffer(&pem,
        "-----BEGIN CERTIFICATE REQUEST-----",
        "-----END CERTIFICATE REQUEST-----",
        buf, NULL, 0, &use_len);

    if (ret == 0)
    {
        /*
        * Was PEM encoded, parse the result
        */
        if ((ret = x509_csr_parse_der(csr, pem.buf, pem.buflen)) != 0)
            return(ret);

        pem_free(&pem);
        return(0);
    }
    else if (ret != POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
    {
        pem_free(&pem);
        return(ret);
    }
    else
#endif /* POLARSSL_PEM_PARSE_C */
        return(x509_csr_parse_der(csr, buf, buflen));
}

/*
 * Load a CSR into the structure
 */
int x509_csr_parse_file( x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    uint8_t *buf;

    if ( ( ret = x509_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = x509_csr_parse( csr, buf, n );

    __stosb( buf, 0, n + 1 );
    memory_free( buf );

    return( ret );
}

#define POLARSSL_ERR_DEBUG_BUF_TOO_SMALL    -2

#define SAFE_SNPRINTF()                         \
{                                               \
    if( ret == -1 )                             \
        return( -1 );                           \
                                                \
    if ( (uint32_t) ret > n ) {             \
        p[n - 1] = '\0';                        \
        return POLARSSL_ERR_DEBUG_BUF_TOO_SMALL;\
    }                                           \
                                                \
    n -= (uint32_t) ret;                    \
    p += (uint32_t) ret;                    \
}

#define BEFORE_COLON    14
#define BC              "14"
/*
 * Return an informational string about the CSR.
 */
int x509_csr_info( char *buf, size_t size, const char *prefix,
                   const x509_csr *csr )
{
    int ret;
    size_t n;
    char *p;
    const char *desc;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = fn__snprintf(p, n, "%sCSR version   : %d", prefix, csr->version );
    SAFE_SNPRINTF();

    ret = fn__snprintf(p, n, "\n%ssubject name  : ", prefix);
    SAFE_SNPRINTF();
    ret = x509_dn_gets( p, n, &csr->subject );
    SAFE_SNPRINTF();

    ret = fn__snprintf(p, n, "\n%ssigned using  : ", prefix);
    SAFE_SNPRINTF();

    ret = oid_get_sig_alg_desc( &csr->sig_oid, &desc );
    if (ret != 0) {
        ret = fn__snprintf(p, n, "???");
    }
    else {
        ret = fn__snprintf(p, n, "%s", desc);
    }
    SAFE_SNPRINTF();

    if ((ret = x509_key_size_helper(key_size_str, BEFORE_COLON, pk_get_name(&csr->pk))) != 0) {
        return ret;
    }

    ret = fn__snprintf(p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str, (int) pk_get_size( &csr->pk ) );
    SAFE_SNPRINTF();

    return (int) ( size - n );
}

/*
 * Initialize a CSR
 */
void x509_csr_init( x509_csr *csr )
{
    __stosb( csr, 0, sizeof(x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void x509_csr_free( x509_csr *csr )
{
    x509_name *name_cur;
    x509_name *name_prv;

    if( csr == NULL )
        return;

    pk_free( &csr->pk );

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        __stosb( name_prv, 0, sizeof( x509_name ) );
        memory_free( name_prv );
    }

    if( csr->raw.p != NULL )
    {
        __stosb( csr->raw.p, 0, csr->raw.len );
        memory_free( csr->raw.p );
    }

    __stosb( csr, 0, sizeof( x509_csr ) );
}

#endif /* POLARSSL_X509_CSR_PARSE_C */
