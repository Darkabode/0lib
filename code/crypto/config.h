#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/**
 * \def POLARSSL_XXX_ALT
 *
 * Uncomment a macro to let PolarSSL use your alternate core implementation of
 * a symmetric or hash algorithm (e.g. platform specific assembly optimized
 * implementations). Keep in mind that the function prototypes should remain
 * the same.
 *
 * Example: In case you uncomment POLARSSL_AES_ALT, PolarSSL will no longer
 * provide the "struct aes_context_t" definition and omit the base function
 * declarations and implementations. "aes_alt.h" will be included from
 * "aes.h" to include the new function definitions.
 *
 * Uncomment a macro to enable alternate implementation for core algorithm
 * functions
 */
//#define POLARSSL_AES_ALT
//#define POLARSSL_SHA256_ALT
//#define POLARSSL_SHA512_ALT

/**
 * \def POLARSSL_CIPHER_PADDING_XXX
 *
 * Uncomment or comment macros to add support for specific padding modes
 * in the cipher layer with cipher modes that support padding (e.g. CBC)
 *
 * If you disable all padding modes, only full blocks can be used with CBC.
 *
 * Enable padding modes in the cipher layer.
 */
#define POLARSSL_CIPHER_PADDING_PKCS7
#define POLARSSL_CIPHER_PADDING_ONE_AND_ZEROS
#define POLARSSL_CIPHER_PADDING_ZEROS_AND_LEN
#define POLARSSL_CIPHER_PADDING_ZEROS

/**
 * \def POLARSSL_ECP_XXXX_ENABLED
 *
 * Enables specific curves within the Elliptic Curve module.
 * By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
#define POLARSSL_ECP_DP_SECP192R1_ENABLED
#define POLARSSL_ECP_DP_SECP224R1_ENABLED
#define POLARSSL_ECP_DP_SECP256R1_ENABLED
#define POLARSSL_ECP_DP_SECP384R1_ENABLED
#define POLARSSL_ECP_DP_SECP521R1_ENABLED
#define POLARSSL_ECP_DP_SECP192K1_ENABLED
#define POLARSSL_ECP_DP_SECP224K1_ENABLED
#define POLARSSL_ECP_DP_SECP256K1_ENABLED
#define POLARSSL_ECP_DP_BP256R1_ENABLED
#define POLARSSL_ECP_DP_BP384R1_ENABLED
#define POLARSSL_ECP_DP_BP512R1_ENABLED
//#define POLARSSL_ECP_DP_M221_ENABLED  // Not implemented yet!
#define POLARSSL_ECP_DP_M255_ENABLED
//#define POLARSSL_ECP_DP_M383_ENABLED  // Not implemented yet!
//#define POLARSSL_ECP_DP_M511_ENABLED  // Not implemented yet!

/**
 * \def POLARSSL_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
#define POLARSSL_ECP_NIST_OPTIM

/**
 * \def POLARSSL_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
#define POLARSSL_PK_PARSE_EC_EXTENDED

/**
 * \def POLARSSL_SSL_ALL_ALERT_MESSAGES
 *
 * Enable sending of alert messages in case of encountered errors as per RFC.
 * If you choose not to send the alert messages, PolarSSL can still communicate
 * with other servers, only debugging of failures is harder.
 *
 * The advantage of not sending alert messages, is that no information is given
 * about reasons for failures thus preventing adversaries of gaining intel.
 *
 * Enable sending of all alert messages
 */
#define POLARSSL_SSL_ALERT_MESSAGES

/**
 * \def POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO
 *
 * Enable support for receiving and parsing SSLv2 Client Hello messages for the
 * SSL Server module (POLARSSL_SSL_SRV_C).
 *
 * Comment this macro to disable support for SSLv2 Client Hello messages.
 */
#define POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO

/**
 * \def POLARSSL_SSL_MAX_FRAGMENT_LENGTH
 *
 * Enable support for RFC 6066 max_fragment_length extension in SSL.
 *
 * Comment this macro to disable support for the max_fragment_length extension
 */
#define POLARSSL_SSL_MAX_FRAGMENT_LENGTH

/**
 * \def POLARSSL_SSL_ALPN
 *
 * Enable support for Application Layer Protocol Negotiation.
 * draft-ietf-tls-applayerprotoneg-05
 *
 * Comment this macro to disable support for ALPN.
 */
#define POLARSSL_SSL_ALPN

/**
 * \def POLARSSL_SSL_SERVER_NAME_INDICATION
 *
 * Enable support for RFC 6066 server name indication (SNI) in SSL.
 *
 * Comment this macro to disable support for server name indication in SSL
 */
#define POLARSSL_SSL_SERVER_NAME_INDICATION

/**
 * \def POLARSSL_SSL_TRUNCATED_HMAC
 *
 * Enable support for RFC 6066 truncated HMAC in SSL.
 *
 * Comment this macro to disable support for truncated HMAC in SSL
 */
#define POLARSSL_SSL_TRUNCATED_HMAC

/**
 * \def POLARSSL_X509_CHECK_KEY_USAGE
 *
 * Enable verification of the keyUsage extension (CA and leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused
 * (intermediate) CA and leaf certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip keyUsage checking for both CA and leaf certificates.
 */
#define POLARSSL_X509_CHECK_KEY_USAGE

/**
 * \def POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE
 *
 * Enable verification of the extendedKeyUsage extension (leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip extendedKeyUsage checking for certificates.
 */
#define POLARSSL_X509_CHECK_EXTENDED_KEY_USAGE

/* \} name SECTION: PolarSSL feature support */

/**
 * \name SECTION: PolarSSL modules
 *
 * This section enables or disables entire modules in PolarSSL
 * \{
 */

/**
 * \def POLARSSL_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/x509.c
 *          library/dhm.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/pkparse.c
 */
#define POLARSSL_ASN1_PARSE_C

/**
 * \def POLARSSL_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *          library/pkwrite.c
 *          library/x509_create.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 */
#define POLARSSL_ASN1_WRITE_C

/**
 * \def POLARSSL_CERTS_C
 *
 * Enable the test certificates.
 *
 * Module:  library/certs.c
 * Caller:
 *
 * Requires: POLARSSL_PEM_PARSE_C
 *
 * This module is used for testing (ssl_client/server).
 */
//#define POLARSSL_CERTS_C

/**
 * \def POLARSSL_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 * Caller:
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define POLARSSL_MD_C

/**
 * \def POLARSSL_NET_C
 *
 * Enable the TCP/IP networking routines.
 *
 * Module:  library/net.c
 *
 * This module provides TCP/IP networking routines.
 */
#define POLARSSL_NET_C

/**
 * \def POLARSSL_OID_C
 *
 * Enable the OID database.
 *
 * Module:  library/oid.c
 * Caller:  library/asn1write.c
 *          library/pkcs5.c
 *          library/pkparse.c
 *          library/pkwrite.c
 *          library/rsa.c
 *          library/x509.c
 *          library/x509_create.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules translates between OIDs and internal values.
 */
#define POLARSSL_OID_C

/**
 * \def POLARSSL_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define POLARSSL_PEM_PARSE_C

/**
 * \def POLARSSL_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  library/pem.c
 * Caller:  library/pkwrite.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules adds support for encoding / writing PEM files.
 */
#define POLARSSL_PEM_WRITE_C

/**
 * \def POLARSSL_PK_C
 *
 * Enable the generic public (asymetric) key layer.
 *
 * Module:  library/pk.c
 * Caller:  library/ssl_tls.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *
 *
 * Uncomment to enable generic public key wrappers.
 */
#define POLARSSL_PK_C

/**
 * \def POLARSSL_PK_PARSE_C
 *
 * Enable the generic public (asymetric) key parser.
 *
 * Module:  library/pkparse.c
 * Caller:  library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: POLARSSL_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define POLARSSL_PK_PARSE_C

/**
 * \def POLARSSL_PK_WRITE_C
 *
 * Enable the generic public (asymetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Requires: POLARSSL_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define POLARSSL_PK_WRITE_C

/**
 * \def POLARSSL_SHA256_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 * (Used to be POLARSSL_SHA2_C)
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * This module adds support for SHA-224 and SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define POLARSSL_SHA256_C

/**
 * \def POLARSSL_SHA512_C
 *
 * Enable the SHA-384 and SHA-512 cryptographic hash algorithms.
 * (Used to be POLARSSL_SHA4_C)
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * This module adds support for SHA-384 and SHA-512.
 */
#define POLARSSL_SHA512_C

/**
 * \def POLARSSL_SSL_CACHE_C
 *
 * Enable simple SSL cache implementation.
 *
 * Module:  library/ssl_cache.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_CACHE_C
 */
#define POLARSSL_SSL_CACHE_C

/**
 * \def POLARSSL_SSL_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl_cli.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS client support.
 */
#define POLARSSL_SSL_CLI_C

/**
 * \def POLARSSL_SSL_SRV_C
 *
 * Enable the SSL/TLS server code.
 *
 * Module:  library/ssl_srv.c
 * Caller:
 *
 * Requires: POLARSSL_SSL_TLS_C
 *
 * This module is required for SSL/TLS server support.
 */
#define POLARSSL_SSL_SRV_C

/**
 * \def POLARSSL_SSL_TLS_C
 *
 * Enable the generic SSL/TLS code.
 *
 * Module:  library/ssl_tls.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *
 * Requires: at least one of the POLARSSL_SSL_PROTO_* defines
 *
 * This module is required for SSL/TLS.
 */
#define POLARSSL_SSL_TLS_C

/**
 * \def POLARSSL_X509_USE_C
 *
 * Enable X.509 core for using certificates.
 *
 * Module:  library/x509.c
 * Caller:  library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: POLARSSL_ASN1_PARSE_C, POLARSSL_OID_C,
 *           POLARSSL_PK_PARSE_C
 *
 * This module is required for the X.509 parsing modules.
 */
#define POLARSSL_X509_USE_C

/**
 * \def POLARSSL_X509_CRT_PARSE_C
 *
 * Enable X.509 certificate parsing.
 *
 * Module:  library/x509_crt.c
 * Caller:  library/ssl_cli.c
 *          library/ssl_srv.c
 *          library/ssl_tls.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is required for X.509 certificate parsing.
 */
#define POLARSSL_X509_CRT_PARSE_C

/**
 * \def POLARSSL_X509_CRL_PARSE_C
 *
 * Enable X.509 CRL parsing.
 *
 * Module:  library/x509_crl.c
 * Caller:  library/x509_crt.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is required for X.509 CRL parsing.
 */
#define POLARSSL_X509_CRL_PARSE_C

/**
 * \def POLARSSL_X509_CSR_PARSE_C
 *
 * Enable X.509 Certificate Signing Request (CSR) parsing.
 *
 * Module:  library/x509_csr.c
 * Caller:  library/x509_crt_write.c
 *
 * Requires: POLARSSL_X509_USE_C
 *
 * This module is used for reading X.509 certificate request.
 */
#define POLARSSL_X509_CSR_PARSE_C

/**
 * \def POLARSSL_X509_CREATE_C
 *
 * Enable X.509 core for creating certificates.
 *
 * Module:  library/x509_create.c
 *
 * Requires: POLARSSL_OID_C, POLARSSL_PK_WRITE_C
 *
 * This module is the basis for creating X.509 certificates and CSRs.
 */
#define POLARSSL_X509_CREATE_C

/**
 * \def POLARSSL_X509_CRT_WRITE_C
 *
 * Enable creating X.509 certificates.
 *
 * Module:  library/x509_crt_write.c
 *
 * Requires: POLARSSL_CREATE_C
 *
 * This module is required for X.509 certificate creation.
 */
#define POLARSSL_X509_CRT_WRITE_C

/**
 * \def POLARSSL_X509_CSR_WRITE_C
 *
 * Enable creating X.509 Certificate Signing Requests (CSR).
 *
 * Module:  library/x509_csr_write.c
 *
 * Requires: POLARSSL_CREATE_C
 *
 * This module is required for X.509 certificate request writing.
 */
#define POLARSSL_X509_CSR_WRITE_C


/* \} name SECTION: PolarSSL modules */

/**
 * \name SECTION: Module configuration options
 *
 * This section allows for the setting of module specific sizes and
 * configuration options. The default values are already present in the
 * relevant header files and should suffice for the regular use cases.
 *
 * Our advice is to enable options and change their values here
 * only if you have a good reason and know the consequences.
 *
 * Please check the respective header file for documentation on these
 * parameters (to prevent duplicate documentation).
 * \{
 */

/* MPI / BIGNUM options */
//#define POLARSSL_MPI_WINDOW_SIZE            6 /**< Maximum windows size used. */
//#define POLARSSL_MPI_MAX_SIZE             512 /**< Maximum number of bytes for usable MPIs. */

/* CTR_DRBG options */
//#define CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */
//#define CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
//#define CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
//#define CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */

/* HMAC_DRBG options */
//#define POLARSSL_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */
//#define POLARSSL_HMAC_DRBG_MAX_INPUT           256 /**< Maximum number of additional input bytes */
//#define POLARSSL_HMAC_DRBG_MAX_REQUEST        1024 /**< Maximum number of requested bytes per call */
//#define POLARSSL_HMAC_DRBG_MAX_SEED_INPUT      384 /**< Maximum size of (re)seed buffer */

/* ECP options */
//#define POLARSSL_ECP_MAX_BITS             521 /**< Maximum bit size of groups */
//#define POLARSSL_ECP_WINDOW_SIZE            6 /**< Maximum window size used */
//#define POLARSSL_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */

/* Entropy options */
//#define ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
//#define ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */

/* Memory buffer allocator options */
//#define MEMORY_ALIGN_MULTIPLE               4 /**< Align on multiples of this value */

/* Platform options */
//#define POLARSSL_PLATFORM_STD_MEM_HDR <stdlib.h> /**< Header to include if POLARSSL_PLATFORM_NO_STD_FUNCTIONS is defined. Don't define if no header is needed. */
//#define POLARSSL_PLATFORM_STD_MALLOC   memory_alloc /**< Default allocator to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_FREE       memory_free /**< Default memory_free to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_PRINTF   printf /**< Default printf to use, can be undefined */
//#define POLARSSL_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use, can be undefined */

/* SSL Cache options */
//#define SSL_CACHE_DEFAULT_TIMEOUT       86400 /**< 1 day  */
//#define SSL_CACHE_DEFAULT_MAX_ENTRIES      50 /**< Maximum entries in cache */

/* SSL options */
//#define SSL_MAX_CONTENT_LEN             16384 /**< Size of the input / output buffer */
//#define SSL_DEFAULT_TICKET_LIFETIME     86400 /**< Lifetime of session tickets (if enabled) */

/* Debug options */
//#define POLARSSL_DEBUG_DFL_MODE POLARSSL_DEBUG_LOG_FULL /**< Default log: Full or Raw */

/* \} name SECTION: Module configuration options */

#include "check_config.h"

#endif /* POLARSSL_CONFIG_H */
