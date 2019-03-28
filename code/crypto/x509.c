#include "..\zmodule.h"
#include "config.h"

#include "x509.h"
#include "asn1.h"
#include "oid.h"
#if defined(POLARSSL_PEM_PARSE_C)
#include "pem.h"
#endif
#include <stdlib.h>

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
int x509_get_serial( uint8_t **p, const uint8_t *end,
                     x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_INVALID_SERIAL +
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != ( ASN1_CONTEXT_SPECIFIC | ASN1_PRIMITIVE | 2 ) &&
        **p !=   ASN1_INTEGER )
        return( POLARSSL_ERR_X509_INVALID_SERIAL +
                POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_SERIAL + ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

/* Get an algorithm identifier without parameters (eg for signatures)
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int x509_get_alg_null( uint8_t **p, const uint8_t *end,
                       x509_buf *alg )
{
    int ret;

    if( ( ret = asn1_get_alg_null( p, end, alg ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_attr_type_value( uint8_t **p,
                                     const uint8_t *end,
                                     x509_name *cur )
{
    int ret;
    size_t len;
    x509_buf *oid;
    x509_buf *val;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_NAME + ret );

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_INVALID_NAME +
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &oid->len, ASN1_OID ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_NAME + ret );

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_INVALID_NAME +
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != ASN1_BMP_STRING && **p != ASN1_UTF8_STRING      &&
        **p != ASN1_T61_STRING && **p != ASN1_PRINTABLE_STRING &&
        **p != ASN1_IA5_STRING && **p != ASN1_UNIVERSAL_STRING )
        return( POLARSSL_ERR_X509_INVALID_NAME +
                POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &val->len ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_NAME + ret );

    val->p = *p;
    *p += val->len;

    cur->next = NULL;

    return( 0 );
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
int x509_get_name( uint8_t **p, const uint8_t *end,
                   x509_name *cur )
{
    int ret;
    size_t len;
    const uint8_t *end2;
    x509_name *use;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SET ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_NAME + ret );

    end2 = end;
    end  = *p + len;
    use = cur;

    do
    {
        if( ( ret = x509_get_attr_type_value( p, end, use ) ) != 0 )
            return( ret );

        if( *p != end )
        {
            use->next = (x509_name *) memory_alloc(
                    sizeof( x509_name ) );

            if( use->next == NULL )
                return( POLARSSL_ERR_X509_MALLOC_FAILED );

            __stosb( use->next, 0, sizeof( x509_name ) );

            use = use->next;
        }
    }
    while( *p != end );

    /*
     * recurse until end of SEQUENCE is reached
     */
    if( *p == end2 )
        return( 0 );

    cur->next = (x509_name *) memory_alloc(
         sizeof( x509_name ) );

    if( cur->next == NULL )
        return( POLARSSL_ERR_X509_MALLOC_FAILED );

    __stosb( cur->next, 0, sizeof( x509_name ) );

    return( x509_get_name( p, end2, cur->next ) );
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
int x509_get_time( uint8_t **p, const uint8_t *end,
                   x509_time *time )
{
    int ret;
    size_t len;
    char date[64];
    uint8_t tag;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_INVALID_DATE +
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if ( tag == ASN1_UTC_TIME )
    {
        (*p)++;
        ret = asn1_get_len( p, end, &len );

        if( ret != 0 )
            return( POLARSSL_ERR_X509_INVALID_DATE + ret );

        __stosb( date,  0, sizeof( date ) );
        __movsb( date, *p, ( len < sizeof( date ) - 1 ) ?
                len : sizeof( date ) - 1 );

        if( sscanf( date, "%2d%2d%2d%2d%2d%2dZ",
                    &time->year, &time->mon, &time->day,
                    &time->hour, &time->min, &time->sec ) < 5 )
            return( POLARSSL_ERR_X509_INVALID_DATE );

        time->year +=  100 * ( time->year < 50 );
        time->year += 1900;

        *p += len;

        return( 0 );
    }
    else if ( tag == ASN1_GENERALIZED_TIME )
    {
        (*p)++;
        ret = asn1_get_len( p, end, &len );

        if( ret != 0 )
            return( POLARSSL_ERR_X509_INVALID_DATE + ret );

        __stosb( date,  0, sizeof( date ) );
        __movsb( date, *p, ( len < sizeof( date ) - 1 ) ?
                len : sizeof( date ) - 1 );

        if( sscanf( date, "%4d%2d%2d%2d%2d%2dZ",
                    &time->year, &time->mon, &time->day,
                    &time->hour, &time->min, &time->sec ) < 5 )
            return( POLARSSL_ERR_X509_INVALID_DATE );

        *p += len;

        return( 0 );
    }
    else
        return( POLARSSL_ERR_X509_INVALID_DATE +
                POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
}

int x509_get_sig( uint8_t **p, const uint8_t *end, x509_buf *sig )
{
    int ret;
    size_t len;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_INVALID_SIGNATURE +
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    sig->tag = **p;

    if( ( ret = asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_SIGNATURE + ret );

    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

int x509_get_sig_alg( const x509_buf *sig_oid, md_type_t *md_alg,
                      pk_type_t *pk_alg )
{
    int ret = oid_get_sig_alg( sig_oid, md_alg, pk_alg );

    if( ret != 0 )
        return( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG + ret );

    return( 0 );
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!
 */
int x509_get_ext( uint8_t **p, const uint8_t *end,
                  x509_buf *ext, int tag )
{
    int ret;
    size_t len;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &ext->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | tag ) ) != 0 )
        return( ret );

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( end != *p + len )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * Load all data from a file into a given buffer.
 */
int x509_load_file( const char *path, uint8_t **buf, size_t *n )
{
    FILE *f;
    long size;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( POLARSSL_ERR_X509_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( POLARSSL_ERR_X509_FILE_IO_ERROR );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = (uint8_t *) memory_alloc( *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( POLARSSL_ERR_X509_MALLOC_FAILED );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );
        memory_free( *buf );
        return( POLARSSL_ERR_X509_FILE_IO_ERROR );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    return( 0 );
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

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int x509_dn_gets( char *buf, size_t size, const x509_name *dn )
{
    int ret;
    size_t i, n;
    uint8_t c;
    const x509_name *name;
    const char *short_name = NULL;
    char s[128], *p;

    __stosb( s, 0, sizeof( s ) );

    name = dn;
    p = buf;
    n = size;

    while( name != NULL )
    {
        if( !name->oid.p )
        {
            name = name->next;
            continue;
        }

        if( name != dn )
        {
            ret = fn__snprintf( p, n, ", " );
            SAFE_SNPRINTF();
        }

        ret = oid_get_attr_short_name( &name->oid, &short_name );

        if( ret == 0 )
            ret = fn__snprintf(p, n, "%s=", short_name);
        else
            ret = fn__snprintf(p, n, "\?\?=");
        SAFE_SNPRINTF();

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        ret = fn__snprintf(p, n, "%s", s);
        SAFE_SNPRINTF();
        name = name->next;
    }

    return( (int) ( size - n ) );
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int x509_serial_gets( char *buf, size_t size, const x509_buf *serial )
{
    int ret;
    size_t i, n, nr;
    char *p;

    p = buf;
    n = size;

    nr = ( serial->len <= 32 )
        ? serial->len  : 28;

    for( i = 0; i < nr; i++ )
    {
        if( i == 0 && nr > 1 && serial->p[i] == 0x0 )
            continue;

        ret = fn__snprintf(p, n, "%02X%s", serial->p[i], ( i < nr - 1 ) ? ":" : "" );
        SAFE_SNPRINTF();
    }

    if( nr != serial->len )
    {
        ret = fn__snprintf(p, n, "....");
        SAFE_SNPRINTF();
    }

    return( (int) ( size - n ) );
}

/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
int x509_key_size_helper( char *buf, size_t size, const char *name )
{
    char *p = buf;
    size_t n = size;
    int ret;

    if( strlen( name ) + sizeof( " key size" ) > size )
        return POLARSSL_ERR_DEBUG_BUF_TOO_SMALL;

    ret = fn__snprintf(p, n, "%s key size", name);
    SAFE_SNPRINTF();

    return( 0 );
}

/*
 * Return an informational string describing the given OID
 */
const char *x509_oid_get_description( x509_buf *oid )
{
    const char *desc = NULL;
    int ret;

    ret = oid_get_extended_key_usage( oid, &desc );

    if( ret != 0 )
        return( NULL );

    return( desc );
}

/* Return the x.y.z.... style numeric string for the given OID */
int x509_oid_get_numeric_string( char *buf, size_t size, x509_buf *oid )
{
    return oid_get_numeric_string( buf, size, oid );
}

/*
 * Return 0 if the x509_time is still valid, or 1 otherwise.
 */
static void x509_get_current_time( x509_time *now )
{
    SYSTEMTIME st;

    GetSystemTime(&st);

    now->year = st.wYear;
    now->mon = st.wMonth;
    now->day = st.wDay;
    now->hour = st.wHour;
    now->min = st.wMinute;
    now->sec = st.wSecond;
}

/*
 * Return 0 if before <= after, 1 otherwise
 */
static int x509_check_time( const x509_time *before, const x509_time *after )
{
    if( before->year  > after->year )
        return( 1 );

    if( before->year == after->year &&
        before->mon   > after->mon )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day   > after->day )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour  > after->hour )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min   > after->min  )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min  == after->min  &&
        before->sec   > after->sec  )
        return( 1 );

    return( 0 );
}

int x509_time_expired( const x509_time *to )
{
    x509_time now;

    x509_get_current_time( &now );

    return( x509_check_time( &now, to ) );
}

int x509_time_future( const x509_time *from )
{
    x509_time now;

    x509_get_current_time( &now );

    return( x509_check_time( from, &now ) );
}
