#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "req-inl.h"

int async__getaddrinfo_translate_error(int sys_err)
{
    switch (sys_err) {
        case 0:                       return 0;
        case WSATRY_AGAIN:            return ASYNC_EAI_AGAIN;
        case WSAEINVAL:               return ASYNC_EAI_BADFLAGS;
        case WSANO_RECOVERY:          return ASYNC_EAI_FAIL;
        case WSAEAFNOSUPPORT:         return ASYNC_EAI_FAMILY;
        case WSA_NOT_ENOUGH_MEMORY:   return ASYNC_EAI_MEMORY;
        case WSAHOST_NOT_FOUND:       return ASYNC_EAI_NONAME;
        case WSATYPE_NOT_FOUND:       return ASYNC_EAI_SERVICE;
        case WSAESOCKTNOSUPPORT:      return ASYNC_EAI_SOCKTYPE;
        default:                      return async_translate_sys_error(sys_err);
    }
    return 0;
}

/* adjust size value to be multiple of 4. Use to keep pointer aligned */
/* Do we need different versions of this for different architectures? */
#define ALIGNED_SIZE(X)     ((((X) + 3) >> 2) << 2)


void async__getaddrinfo_work(struct async__work* w)
{
    async_getaddrinfo_t* req;
    int err;

    req = container_of(w, async_getaddrinfo_t, work_req);
    err = fn_GetAddrInfoW(req->node, req->service, req->hints, &req->res);
    req->retcode = async__getaddrinfo_translate_error(err);
}


/*
 * Called from async_run when complete. Call user specified callback
 * then memory_free returned addrinfo
 * Returned addrinfo strings are converted from UTF-16 to UTF-8.
 *
 * To minimize allocation we calculate total size required,
 * and copy all structs and referenced strings into the one block.
 * Each size calculation is adjusted to avoid unaligned pointers.
 */
static void async__getaddrinfo_done(struct async__work* w, int status)
{
    async_getaddrinfo_t* req;
    int addrinfo_len = 0;
    int name_len = 0;
    size_t addrinfo_struct_len = ALIGNED_SIZE(sizeof(struct addrinfo));
    struct addrinfoW* addrinfow_ptr;
    struct addrinfo* addrinfo_ptr;
    char* alloc_ptr = NULL;
    char* cur_ptr = NULL;

    req = container_of(w, async_getaddrinfo_t, work_req);

    /* release input parameter memory */
    if (req->alloc != NULL) {
        memory_free(req->alloc);
        req->alloc = NULL;
    }

    if (status == ASYNC_ECANCELED) {
        req->retcode = ASYNC_EAI_CANCELED;
        if (req->res != NULL) {
            fn_FreeAddrInfoW(req->res);
            req->res = NULL;
        }
        goto complete;
    }

    if (req->retcode == 0) {
        /* convert addrinfoW to addrinfo */
        /* first calculate required length */
        addrinfow_ptr = req->res;
        while (addrinfow_ptr != NULL) {
            addrinfo_len += addrinfo_struct_len + ALIGNED_SIZE(addrinfow_ptr->ai_addrlen);
            if (addrinfow_ptr->ai_canonname != NULL) {
                name_len = utils_utf16_to_utf8(addrinfow_ptr->ai_canonname, -1, NULL, 0);
                if (name_len == 0) {
                    req->retcode = async_translate_sys_error(fn_GetLastError());
                    goto complete;
                }
                addrinfo_len += ALIGNED_SIZE(name_len);
            }
            addrinfow_ptr = addrinfow_ptr->ai_next;
        }

        /* allocate memory for addrinfo results */
        alloc_ptr = (char*)memory_alloc(addrinfo_len);

        /* do conversions */
        cur_ptr = alloc_ptr;
        addrinfow_ptr = req->res;

        while (addrinfow_ptr != NULL) {
            /* copy addrinfo struct data */
            addrinfo_ptr = (struct addrinfo*)cur_ptr;
            addrinfo_ptr->ai_family = addrinfow_ptr->ai_family;
            addrinfo_ptr->ai_socktype = addrinfow_ptr->ai_socktype;
            addrinfo_ptr->ai_protocol = addrinfow_ptr->ai_protocol;
            addrinfo_ptr->ai_flags = addrinfow_ptr->ai_flags;
            addrinfo_ptr->ai_addrlen = addrinfow_ptr->ai_addrlen;
            addrinfo_ptr->ai_canonname = NULL;
            addrinfo_ptr->ai_addr = NULL;
            addrinfo_ptr->ai_next = NULL;

            cur_ptr += addrinfo_struct_len;

            /* copy sockaddr */
            if (addrinfo_ptr->ai_addrlen > 0) {
                __movsb(cur_ptr, addrinfow_ptr->ai_addr, addrinfo_ptr->ai_addrlen);
                addrinfo_ptr->ai_addr = (struct sockaddr*)cur_ptr;
                cur_ptr += ALIGNED_SIZE(addrinfo_ptr->ai_addrlen);
            }

            /* convert canonical name to UTF-8 */
            if (addrinfow_ptr->ai_canonname != NULL) {
                name_len = utils_utf16_to_utf8(addrinfow_ptr->ai_canonname, -1, NULL, 0);
                name_len = utils_utf16_to_utf8(addrinfow_ptr->ai_canonname, -1, cur_ptr, name_len);
                addrinfo_ptr->ai_canonname = cur_ptr;
                cur_ptr += ALIGNED_SIZE(name_len);
            }

            /* set next ptr */
            addrinfow_ptr = addrinfow_ptr->ai_next;
            if (addrinfow_ptr != NULL) {
                addrinfo_ptr->ai_next = (struct addrinfo*)cur_ptr;
            }
        }
    }

    /* return memory to system */
    if (req->res != NULL) {
        fn_FreeAddrInfoW(req->res);
        req->res = NULL;
    }

complete:
    async__req_unregister(req->loop, req);

    /* finally do callback with converted result */
    req->getaddrinfo_cb(req, req->retcode, (struct addrinfo*)alloc_ptr);
}

void async_freeaddrinfo(struct addrinfo* ai)
{
    char* alloc_ptr = (char*)ai;

    /* release copied result memory */
    if (alloc_ptr != NULL) {
        memory_free(alloc_ptr);
    }
}


/*
 * Entry point for getaddrinfo
 * we convert the UTF-8 strings to UNICODE
 * and save the UNICODE string pointers in the req
 * We also copy hints so that caller does not need to keep memory until the
 * callback.
 * return 0 if a callback will be made
 * return error code if validation fails
 *
 * To minimize allocation we calculate total size required,
 * and copy all structs and referenced strings into the one block.
 * Each size calculation is adjusted to avoid unaligned pointers.
 */
int async_getaddrinfo(async_loop_t* loop, async_getaddrinfo_t* req, async_getaddrinfo_cb getaddrinfo_cb, const char* node, const char* service, const struct addrinfo* hints)
{
    int nodesize = 0;
    int servicesize = 0;
    int hintssize = 0;
    char* alloc_ptr = NULL;
    int err;

    if (req == NULL || getaddrinfo_cb == NULL || (node == NULL && service == NULL)) {
        err = WSAEINVAL;
        goto error;
    }

    async_req_init(loop, (async_req_t*)req);

    req->getaddrinfo_cb = getaddrinfo_cb;
    req->res = NULL;
    req->type = ASYNC_GETADDRINFO;
    req->loop = loop;
    req->retcode = 0;

    /* calculate required memory size for all input values */
    if (node != NULL) {
        nodesize = ALIGNED_SIZE(utils_utf8_to_utf16(node, NULL, 0) * sizeof(wchar_t));
        if (nodesize == 0) {
            err = fn_GetLastError();
            goto error;
        }
    }

    if (service != NULL) {
        servicesize = ALIGNED_SIZE(utils_utf8_to_utf16(service, NULL, 0) * sizeof(wchar_t));
        if (servicesize == 0) {
            err = fn_GetLastError();
            goto error;
        }
    }
    if (hints != NULL) {
        hintssize = ALIGNED_SIZE(sizeof(struct addrinfoW));
    }

    /* allocate memory for inputs, and partition it as needed */
    alloc_ptr = (char*)memory_alloc(nodesize + servicesize + hintssize);

    /* save alloc_ptr now so we can memory_free if error */
    req->alloc = (void*)alloc_ptr;

    /* convert node string to UTF16 into allocated memory and save pointer in */
    /* the reques. */
    if (node != NULL) {
        req->node = (wchar_t*)alloc_ptr;
        if (utils_utf8_to_utf16(node, (wchar_t*) alloc_ptr, nodesize / sizeof(wchar_t)) == 0) {
            err = fn_GetLastError();
            goto error;
        }
        alloc_ptr += nodesize;
    }
    else {
        req->node = NULL;
    }

    /* convert service string to UTF16 into allocated memory and save pointer */
    /* in the req. */
    if (service != NULL) {
        req->service = (wchar_t*)alloc_ptr;
        if (utils_utf8_to_utf16(service, (wchar_t*) alloc_ptr, servicesize / sizeof(wchar_t)) == 0) {
            err = fn_GetLastError();
            goto error;
        }
        alloc_ptr += servicesize;
    }
    else {
        req->service = NULL;
    }

    /* copy hints to allocated memory and save pointer in req */
    if (hints != NULL) {
        req->hints = (struct addrinfoW*)alloc_ptr;
        req->hints->ai_family = hints->ai_family;
        req->hints->ai_socktype = hints->ai_socktype;
        req->hints->ai_protocol = hints->ai_protocol;
        req->hints->ai_flags = hints->ai_flags;
        req->hints->ai_addrlen = 0;
        req->hints->ai_canonname = NULL;
        req->hints->ai_addr = NULL;
        req->hints->ai_next = NULL;
    }
    else {
        req->hints = NULL;
    }

    async__work_submit(loop, &req->work_req, async__getaddrinfo_work, async__getaddrinfo_done);
    async__req_register(loop, req);
    return 0;

error:
    if (req != NULL && req->alloc != NULL) {
        memory_free(req->alloc);
    }
    return async_translate_sys_error(err);
}
