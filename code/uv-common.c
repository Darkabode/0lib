#include "zmodule.h"
#include "async.h"
#include "uv-common.h"

#define XX(uc, lc) case ASYNC_##uc: return sizeof(async_##lc##_t);

size_t async_handle_size(async_handle_type type)
{
    switch (type) {
        ASYNC_HANDLE_TYPE_MAP(XX)
        default:
            return -1;
    }
}

size_t async_req_size(async_req_type type)
{
    switch(type) {
        ASYNC_REQ_TYPE_MAP(XX)
        default:
            return -1;
    }
}

#undef XX

size_t async_loop_size(void)
{
    return sizeof(async_loop_t);
}

async_buf_t async_buf_init(char* base, uint32_t len)
{
    async_buf_t buf;
    buf.base = base;
    buf.len = len;
    return buf;
}

#define ASYNC_ERR_NAME_GEN(name, _) case ASYNC_ ## name: return #name;
const char* async_err_name(int err)
{
    switch (err) {
        ASYNC_ERRNO_MAP(ASYNC_ERR_NAME_GEN)
        default:
            return NULL;
    }
}
#undef ASYNC_ERR_NAME_GEN

#define ASYNC_STRERROR_GEN(name, msg) case ASYNC_ ## name: return msg;
const char* async_strerror(int err)
{
    switch (err) {
        ASYNC_ERRNO_MAP(ASYNC_STRERROR_GEN)
        default:
            return "Unknown system error";
    }
}
#undef ASYNC_STRERROR_GEN

int async_ip4_addr(const char* ip, int port, struct sockaddr_in* addr)
{
    __stosb((uint8_t*)addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = fn_htons(port);
    return async_inet_pton(AF_INET, ip, &(addr->sin_addr.s_addr));
}

int async_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr)
{
    char address_part[40];
    size_t address_part_size;
    const char* zone_index;

    __stosb((uint8_t*)addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = fn_htons(port);

    zone_index = strchr(ip, '%');
    if (zone_index != NULL) {
        address_part_size = zone_index - ip;
        if (address_part_size >= sizeof(address_part)) {
            address_part_size = sizeof(address_part) - 1;
        }

        __movsb((uint8_t*)address_part, (const uint8_t*)ip, address_part_size);
        address_part[address_part_size] = '\0';
        ip = address_part;

        ++zone_index; /* skip '%' */
        /* NOTE: unknown interface (id=0) is silently ignored */
        addr->sin6_scope_id = atoi(zone_index);
    }

    return async_inet_pton(AF_INET6, ip, &addr->sin6_addr);
}

int async_ip4_name(const struct sockaddr_in* src, char* dst, size_t size)
{
    return async_inet_ntop(AF_INET, &src->sin_addr, dst, size);
}

int async_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size)
{
    return async_inet_ntop(AF_INET6, &src->sin6_addr, dst, size);
}

int async_tcp_bind(async_tcp_t* handle, const struct sockaddr* addr, uint32_t flags)
{
    uint32_t addrlen;

    if (handle->type != ASYNC_TCP) {
        return ASYNC_EINVAL;
    }

    if (addr->sa_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    }
    else if (addr->sa_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        return ASYNC_EINVAL;
    }

    return async__tcp_bind(handle, addr, addrlen, flags);
}

int async_udp_bind(async_udp_t* handle, const struct sockaddr* addr, uint32_t flags)
{
    uint32_t addrlen;

    if (handle->type != ASYNC_UDP) {
        return ASYNC_EINVAL;
    }

    if (addr->sa_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    }
    else if (addr->sa_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        return ASYNC_EINVAL;
    }

    return async__udp_bind(handle, addr, addrlen, flags);
}

int async_tcp_connect(async_connect_t* req, async_tcp_t* handle, const struct sockaddr* addr, async_connect_cb cb)
{
    uint32_t addrlen;

    if (handle->type != ASYNC_TCP) {
        return ASYNC_EINVAL;
    }

    if (addr->sa_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    }
    else if (addr->sa_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        return ASYNC_EINVAL;
    }

    return async__tcp_connect(req, handle, addr, addrlen, cb);
}

int async_udp_send(async_udp_send_t* req, async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, async_udp_send_cb send_cb)
{
    uint32_t addrlen;

    if (handle->type != ASYNC_UDP) {
        return ASYNC_EINVAL;
    }

    if (addr->sa_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    }
    else if (addr->sa_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        return ASYNC_EINVAL;
    }

    return async__udp_send(req, handle, bufs, nbufs, addr, addrlen, send_cb);
}

int async_udp_try_send(async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr)
{
    uint32_t addrlen;

    if (handle->type != ASYNC_UDP)
        return ASYNC_EINVAL;

    if (addr->sa_family == AF_INET)
        addrlen = sizeof(struct sockaddr_in);
    else if (addr->sa_family == AF_INET6)
        addrlen = sizeof(struct sockaddr_in6);
    else
        return ASYNC_EINVAL;

    return async__udp_try_send(handle, bufs, nbufs, addr, addrlen);
}

int async_udp_recv_start(async_udp_t* handle, async_alloc_cb alloc_cb, async_udp_recv_cb recv_cb)
{
    if (handle->type != ASYNC_UDP || alloc_cb == NULL || recv_cb == NULL) {
        return ASYNC_EINVAL;
    }
    else {
        return async__udp_recv_start(handle, alloc_cb, recv_cb);
    }
}

int async_udp_recv_stop(async_udp_t* handle)
{
    if (handle->type != ASYNC_UDP) {
        return ASYNC_EINVAL;
    }
    else {
        return async__udp_recv_stop(handle);
    }
}

struct thread_ctx
{
  void (*entry)(void* arg);
  void* arg;
};

DWORD __stdcall async__thread_start(void* arg)
{
    struct thread_ctx *ctx_p;
    struct thread_ctx ctx;

    ctx_p = arg;
    ctx = *ctx_p;
    memory_free(ctx_p);
    ctx.entry(ctx.arg);

    fn_ExitThread(0);
    return 0;
}

int async_thread_create(async_thread_t *tid, void (*entry)(void *arg), void *arg)
{
    struct thread_ctx* ctx;
    int err;

    ctx = memory_alloc(sizeof(*ctx));
    ctx->entry = entry;
    ctx->arg = arg;

    *tid = fn_CreateThread(NULL, 0, async__thread_start, ctx, 0, NULL);
    err = *tid ? 0 : fn_GetLastError();

    if (err) {
        memory_free(ctx);
    }

    return err ? -1 : 0;
}

unsigned long async_thread_self(void)
{
    return (unsigned long)fn_GetCurrentThreadId();
}

void async_walk(async_loop_t* loop, async_walk_cb walk_cb, void* arg)
{
    QUEUE* q;
    async_handle_t* h;

    QUEUE_FOREACH(q, &loop->handle_queue) {
        h = QUEUE_DATA(q, async_handle_t, handle_queue);
        if (h->flags & ASYNC__HANDLE_INTERNAL) {
            continue;
        }
        walk_cb(h, arg);
    }
}

void async_ref(async_handle_t* handle)
{
    async__handle_ref(handle);
}

void async_unref(async_handle_t* handle)
{
    async__handle_unref(handle);
}

int async_has_ref(const async_handle_t* handle)
{
    return async__has_ref(handle);
}

void async_stop(async_loop_t* loop)
{
    loop->stop_flag = 1;
}

uint64_t async_now(const async_loop_t* loop)
{
    return loop->time;
}

size_t async__count_bufs(const async_buf_t bufs[], uint32_t nbufs)
{
    uint32_t i;
    size_t bytes;

    bytes = 0;
    for (i = 0; i < nbufs; i++)
        bytes += (size_t)bufs[i].len;

    return bytes;
}

int async_recv_buffer_size(async_handle_t* handle, int* value)
{
    return async__socket_sockopt(handle, SO_RCVBUF, value);
}

int async_send_buffer_size(async_handle_t* handle, int *value)
{
    return async__socket_sockopt(handle, SO_SNDBUF, value);
}

int async_fs_event_getpath(async_fs_event_t* handle, wchar_t* buf, size_t* len)
{
    size_t required_len;

    if (!async__is_active(handle)) {
        *len = 0;
        return ASYNC_EINVAL;
    }

    required_len = fn_lstrlenW(handle->path) + 1;
    if (required_len > *len) {
        *len = required_len;
        return ASYNC_ENOBUFS;
    }

    fn_lstrcpyW(buf, handle->path);
    *len = required_len;

    return 0;
}
