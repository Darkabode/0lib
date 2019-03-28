#ifndef POLARSSL_MD_WRAP_H
#define POLARSSL_MD_WRAP_H

#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POLARSSL_SHA256_C)
extern const md_info_t sha224_info;
extern const md_info_t sha256_info;
#endif
#if defined(POLARSSL_SHA512_C)
extern const md_info_t sha384_info;
extern const md_info_t sha512_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_MD_WRAP_H */
