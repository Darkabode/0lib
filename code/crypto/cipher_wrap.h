#ifndef POLARSSL_CIPHER_WRAP_H
#define POLARSSL_CIPHER_WRAP_H

#include "config.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    cipher_type_t type;
    const cipher_info_t *info;
} cipher_definition_t;

extern const cipher_definition_t cipher_definitions[];

extern int supported_ciphers[];

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_CIPHER_WRAP_H */
