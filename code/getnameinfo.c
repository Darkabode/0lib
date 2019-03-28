#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "req-inl.h"

void async__getnameinfo_work(struct async__work* w)
{
    async_getnameinfo_t* req;
    wchar_t host[NI_MAXHOST];
    wchar_t service[NI_MAXSERV];
    int ret = 0;

    req = container_of(w, async_getnameinfo_t, work_req);
    if (fn_GetNameInfoW((struct sockaddr*)&req->storage, sizeof(req->storage), host, ARRAY_SIZE(host), service, ARRAY_SIZE(service), req->flags)) {
        ret = fn_WSAGetLastError();
    }
    req->retcode = async__getaddrinfo_translate_error(ret);

    /* convert results to UTF-8 */
    fn_WideCharToMultiByte(CP_UTF8, 0, host, -1, req->host, sizeof(req->host), NULL, NULL);

    fn_WideCharToMultiByte(CP_UTF8, 0, service, -1, req->service, sizeof(req->service), NULL, NULL);
}

/*
* Called from async_run when complete.
*/
void async__getnameinfo_done(struct async__work* w, int status)
{
    async_getnameinfo_t* req;
    char* host;
    char* service;

    req = container_of(w, async_getnameinfo_t, work_req);
    async__req_unregister(req->loop, req);
    host = service = NULL;

    if (status == ASYNC_ECANCELED) {
        req->retcode = ASYNC_EAI_CANCELED;
    }
    else if (req->retcode == 0) {
        host = req->host;
        service = req->service;
    }

    req->getnameinfo_cb(req, req->retcode, host, service);
}

/*
* Entry point for getnameinfo
* return 0 if a callback will be made
* return error code if validation fails
*/
int async_getnameinfo(async_loop_t* loop, async_getnameinfo_t* req, async_getnameinfo_cb getnameinfo_cb, const struct sockaddr* addr, int flags)
{
    if (req == NULL || getnameinfo_cb == NULL || addr == NULL) {
        return ASYNC_EINVAL;
    }

    if (addr->sa_family == AF_INET) {
        __movsb((uint8_t*)&req->storage, (const uint8_t*)addr, sizeof(struct sockaddr_in));
    }
    else if (addr->sa_family == AF_INET6) {
        __movsb((uint8_t*)&req->storage, (const uint8_t*)addr, sizeof(struct sockaddr_in6));
    }
    else {
        return ASYNC_EINVAL;
    }

    async_req_init(loop, (async_req_t*)req);
    async__req_register(loop, req);

    req->getnameinfo_cb = getnameinfo_cb;
    req->flags = flags;
    req->type = ASYNC_GETNAMEINFO;
    req->loop = loop;
    req->retcode = 0;

    async__work_submit(loop, &req->work_req, async__getnameinfo_work, async__getnameinfo_done);

    return 0;
}
