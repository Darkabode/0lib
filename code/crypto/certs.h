#ifndef POLARSSL_CERTS_H
#define POLARSSL_CERTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Concatenation of all available CA certificates */
extern const char test_ca_list[];

/*
 * Convenience for users who just want a certificate:
 * RSA by default, or ECDSA if RSA i not available
 */
extern const char *test_ca_crt;
extern const char *test_ca_key;
extern const char *test_ca_pwd;
extern const char *test_srv_crt;
extern const char *test_srv_key;
extern const char *test_cli_crt;
extern const char *test_cli_key;


extern const char test_ca_crt_rsa[];
extern const char test_ca_key_rsa[];
extern const char test_ca_pwd_rsa[];
extern const char test_srv_crt_rsa[];
extern const char test_srv_key_rsa[];
extern const char test_cli_crt_rsa[];
extern const char test_cli_key_rsa[];

#ifdef __cplusplus
}
#endif

#endif /* certs.h */
