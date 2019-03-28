#include "..\zmodule.h"
#include "config.h"

#if defined(POLARSSL_ASN1_WRITE_C)

#include "asn1write.h"

int asn1_write_len( uint8_t **p, uint8_t *start, size_t len )
{
    if( len < 0x80 )
    {
        if( *p - start < 1 )
            return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (uint8_t) len;
        return( 1 );
    }

    if( len <= 0xFF )
    {
        if( *p - start < 2 )
            return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (uint8_t) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( *p - start < 3 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    // We assume we never have lengths larger than 65535 bytes
    //
    *--(*p) = len % 256;
    *--(*p) = ( len / 256 ) % 256;
    *--(*p) = 0x82;

    return( 3 );
}

int asn1_write_tag( uint8_t **p, uint8_t *start, uint8_t tag )
{
    if( *p - start < 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = tag;

    return( 1 );
}

int asn1_write_raw_buffer( uint8_t **p, uint8_t *start,
                           const uint8_t *buf, size_t size )
{
    size_t len = 0;

    if( *p - start < (int) size )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    __movsb( *p, buf, len );

    return( (int) len );
}

int asn1_write_mpi( uint8_t **p, uint8_t *start, mpi_t *X )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    //
    len = mpi_size( X );

    if( *p - start < (int) len )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    (*p) -= len;
    MPI_CHK( mpi_write_binary( X, *p, len ) );

    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if ( X->s ==1 && **p & 0x80 )
    {
        if( *p - start < 1 )
            return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_INTEGER ) );

    ret = (int) len;

cleanup:
    return( ret );
}

int asn1_write_null( uint8_t **p, uint8_t *start )
{
    int ret;
    size_t len = 0;

    // Write NULL
    //
    ASN1_CHK_ADD( len, asn1_write_len( p, start, 0) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_NULL ) );

    return( (int) len );
}

int asn1_write_oid( uint8_t **p, uint8_t *start,
                    const char *oid, size_t oid_len )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_raw_buffer( p, start,
                                  (const uint8_t *) oid, oid_len ) );
    ASN1_CHK_ADD( len , asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len , asn1_write_tag( p, start, ASN1_OID ) );

    return( (int) len );
}

int asn1_write_algorithm_identifier( uint8_t **p, uint8_t *start,
                                     const char *oid, size_t oid_len,
                                     size_t par_len )
{
    int ret;
    size_t len = 0;

    if( par_len == 0 )
        ASN1_CHK_ADD( len, asn1_write_null( p, start ) );
    else
        len += par_len;

    ASN1_CHK_ADD( len, asn1_write_oid( p, start, oid, oid_len ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start,
                                       ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    return( (int) len );
}

int asn1_write_bool( uint8_t **p, uint8_t *start, int boolean )
{
    int ret;
    size_t len = 0;

    if( *p - start < 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = (boolean) ? 1 : 0;
    len++;

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_BOOLEAN ) );

    return( (int) len );
}

int asn1_write_int( uint8_t **p, uint8_t *start, int val )
{
    int ret;
    size_t len = 0;

    // TODO negative values and values larger than 128
    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if( *p - start < 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    len += 1;
    *--(*p) = val;

    if ( val > 0 && **p & 0x80 )
    {
        if( *p - start < 1 )
            return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_INTEGER ) );

    return( (int) len );
}

int asn1_write_printable_string( uint8_t **p, uint8_t *start,
                                 const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_raw_buffer( p, start,
                  (const uint8_t *) text, text_len ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_PRINTABLE_STRING ) );

    return( (int) len );
}

int asn1_write_ia5_string( uint8_t **p, uint8_t *start,
                           const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_raw_buffer( p, start,
                  (const uint8_t *) text, text_len ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_IA5_STRING ) );

    return( (int) len );
}

int asn1_write_bitstring( uint8_t **p, uint8_t *start,
                          const uint8_t *buf, size_t bits )
{
    int ret;
    size_t len = 0, size;

    size = ( bits / 8 ) + ( ( bits % 8 ) ? 1 : 0 );

    // Calculate byte length
    //
    if( *p - start < (int) size + 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    len = size + 1;
    (*p) -= size;
    __movsb( *p, buf, size );

    // Write unused bits
    //
    *--(*p) = (uint8_t) (size * 8 - bits);

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_BIT_STRING ) );

    return( (int) len );
}

int asn1_write_octet_string( uint8_t **p, uint8_t *start,
                             const uint8_t *buf, size_t size )
{
    int ret;
    size_t len = 0;

    ASN1_CHK_ADD( len, asn1_write_raw_buffer( p, start, buf, size ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_OCTET_STRING ) );

    return( (int) len );
}

asn1_named_data *asn1_store_named_data( asn1_named_data **head,
                                        const char *oid, size_t oid_len,
                                        const uint8_t *val,
                                        size_t val_len )
{
    asn1_named_data *cur;

    if( ( cur = asn1_find_named_data( *head, oid, oid_len ) ) == NULL )
    {
        // Add new entry if not present yet based on OID
        //
        if( ( cur = memory_alloc( sizeof(asn1_named_data) ) ) == NULL )
            return( NULL );

        __stosb( cur, 0, sizeof(asn1_named_data) );

        cur->oid.len = oid_len;
        cur->oid.p = memory_alloc( oid_len );
        if( cur->oid.p == NULL )
        {
            memory_free( cur );
            return( NULL );
        }

        cur->val.len = val_len;
        cur->val.p = memory_alloc( val_len );
        if( cur->val.p == NULL )
        {
            memory_free( cur->oid.p );
            memory_free( cur );
            return( NULL );
        }

        __movsb( cur->oid.p, oid, oid_len );

        cur->next = *head;
        *head = cur;
    }
    else if( cur->val.len < val_len )
    {
        // Enlarge existing value buffer if needed
        //
        memory_free( cur->val.p );
        cur->val.p = NULL;

        cur->val.len = val_len;
        cur->val.p = memory_alloc( val_len );
        if( cur->val.p == NULL )
        {
            memory_free( cur->oid.p );
            memory_free( cur );
            return( NULL );
        }
    }

    if( val != NULL )
        __movsb( cur->val.p, val, val_len );

    return( cur );
}
#endif /* POLARSSL_ASN1_WRITE_C */
