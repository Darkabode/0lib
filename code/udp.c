#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

/*
 * Threshold of active udp streams for which to preallocate udp read buffers.
 */
const uint32_t async_active_udp_streams_threshold = 0;

/* A zero-size buffer for use by async_udp_read */
static char async_zero_[] = "";

int async_udp_getsockname(const async_udp_t* handle, struct sockaddr* name, int* namelen)
{
    int result;

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return ASYNC_EINVAL;
    }

    result = fn_getsockname(handle->socket, name, namelen);
    if (result != 0) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async_udp_set_socket(async_loop_t* loop, async_udp_t* handle, SOCKET socket, int family)
{
     DWORD yes = 1;
    WSAPROTOCOL_INFOW info;
    int opt_len;

    /* Set the socket to nonblocking mode */
    if (fn_ioctlsocket(socket, FIONBIO, &yes) == SOCKET_ERROR) {
        return fn_WSAGetLastError();
    }

    /* Make the socket non-inheritable */
    if (!fn_SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0)) {
        return fn_GetLastError();
    }

    /* Associate it with the I/O completion port. */
    /* Use async_handle_t pointer as completion key. */
    if (fn_CreateIoCompletionPort((HANDLE)socket, loop->iocp, (ULONG_PTR)socket, 0) == NULL) {
        return fn_GetLastError();
    }

    if (fn_SetFileCompletionNotificationModes != NULL) {
        /* All know windowses that support SetFileCompletionNotificationModes */
        /* have a bug that makes it impossible to use this function in */
        /* conjunction with datagram sockets. We can work around that but only */
        /* if the user is using the default UDP driver (AFD) and has no other */
        /* LSPs stacked on top. Here we check whether that is the case. */
        opt_len = (int) sizeof info;
        if (fn_getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*) &info, &opt_len) == SOCKET_ERROR) {
            return fn_GetLastError();
        }

        if (info.ProtocolChain.ChainLen == 1) {
            if (fn_SetFileCompletionNotificationModes((HANDLE)socket, FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)) {
                handle->flags |= ASYNC_HANDLE_SYNC_BYPASS_IOCP;
                handle->func_wsarecv = async_wsarecv_workaround;
                handle->func_wsarecvfrom = async_wsarecvfrom_workaround;
            }
            else if (fn_GetLastError() != ERROR_INVALID_FUNCTION) {
                return fn_GetLastError();
            }
        }
    }

    handle->socket = socket;

    if (family == AF_INET6) {
        handle->flags |= ASYNC_HANDLE_IPV6;
    }

    return 0;
}

int async_udp_init(async_loop_t* loop, async_udp_t* handle)
{
    async__handle_init(loop, (async_handle_t*) handle, ASYNC_UDP);

    handle->socket = INVALID_SOCKET;
    handle->reqs_pending = 0;
    handle->activecnt = 0;
    handle->func_wsarecv = fn_WSARecv;
    handle->func_wsarecvfrom = fn_WSARecvFrom;
    handle->send_queue_size = 0;
    handle->send_queue_count = 0;

    async_req_init(loop, (async_req_t*) &(handle->recv_req));
    handle->recv_req.type = ASYNC_UDP_RECV;
    handle->recv_req.data = handle;

    return 0;
}

void async_udp_close(async_loop_t* loop, async_udp_t* handle)
{
    async_udp_recv_stop(handle);
    fn_closesocket(handle->socket);
    handle->socket = INVALID_SOCKET;
    async__handle_closing(handle);

    if (handle->reqs_pending == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }
}

void async_udp_endgame(async_loop_t* loop, async_udp_t* handle)
{
    if (handle->flags & ASYNC__HANDLE_CLOSING && handle->reqs_pending == 0) {
        async__handle_close(handle);
    }
}

int async_udp_maybe_bind(async_udp_t* handle, const struct sockaddr* addr, uint32_t addrlen, uint32_t flags)
{
    int r;
    int err;
    DWORD no = 0;

    if (handle->flags & ASYNC_HANDLE_BOUND) {
        return 0;
    }

    if ((flags & ASYNC_UDP_IPV6ONLY) && addr->sa_family != AF_INET6) {
        /* ASYNC_UDP_IPV6ONLY is supported only for IPV6 sockets */
        return ERROR_INVALID_PARAMETER;
    }

    if (handle->socket == INVALID_SOCKET) {
        SOCKET sock = fn_socket(addr->sa_family, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) {
            return fn_WSAGetLastError();
        }

        err = async_udp_set_socket(handle->loop, handle, sock, addr->sa_family);
        if (err) {
            fn_closesocket(sock);
            return err;
        }

        if (flags & ASYNC_UDP_REUSEADDR) {
            DWORD yes = 1;
            /* Set SO_REUSEADDR on the socket. */
            if (fn_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &yes, sizeof yes) == SOCKET_ERROR) {
                err = fn_WSAGetLastError();
                fn_closesocket(sock);
                return err;
            }
        }

        if (addr->sa_family == AF_INET6) {
            handle->flags |= ASYNC_HANDLE_IPV6;
        }
    }

    if (addr->sa_family == AF_INET6 && !(flags & ASYNC_UDP_IPV6ONLY)) {
        /* On windows IPV6ONLY is on by default. */
        /* If the user doesn't specify it libuv turns it off. */

        /* TODO: how to handle errors? This may fail if there is no ipv4 stack */
        /* available, or when run on XP/2003 which have no support for dualstack */
        /* sockets. For now we're silently ignoring the error. */
        fn_setsockopt(handle->socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &no, sizeof(no));
    }

    r = fn_bind(handle->socket, addr, addrlen);
    if (r == SOCKET_ERROR) {
        return fn_WSAGetLastError();
    }

    handle->flags |= ASYNC_HANDLE_BOUND;

    return 0;
}

void async_udp_queue_recv(async_loop_t* loop, async_udp_t* handle)
{
    async_req_t* req;
    async_buf_t buf;
    DWORD bytes, flags;
    int result;

    req = &handle->recv_req;
    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    /*
    * Preallocate a read buffer if the number of active streams is below
    * the threshold.
    */
    if (loop->active_udp_streams < async_active_udp_streams_threshold) {
        handle->flags &= ~ASYNC_HANDLE_ZERO_READ;

        handle->alloc_cb((async_handle_t*) handle, 65536, &handle->recv_buffer);
        if (handle->recv_buffer.len == 0) {
            handle->recv_cb(handle, ASYNC_ENOBUFS, &handle->recv_buffer, NULL, 0);
            return;
        }

        buf = handle->recv_buffer;
        __stosb((uint8_t*)&handle->recv_from, 0, sizeof handle->recv_from);
        handle->recv_from_len = sizeof handle->recv_from;
        flags = 0;

        result = handle->func_wsarecvfrom(handle->socket, (WSABUF*) &buf, 1, &bytes, &flags, (struct sockaddr*) &handle->recv_from, &handle->recv_from_len, &req->overlapped, NULL);

        if (ASYNC_SUCCEEDED_WITHOUT_IOCP(result == 0)) {
            /* Process the req without IOCP. */
            handle->flags |= ASYNC_HANDLE_READ_PENDING;
            req->overlapped.InternalHigh = bytes;
            handle->reqs_pending++;
            async_insert_pending_req(loop, req);
        }
        else if (ASYNC_SUCCEEDED_WITH_IOCP(result == 0)) {
            /* The req will be processed with IOCP. */
            handle->flags |= ASYNC_HANDLE_READ_PENDING;
            handle->reqs_pending++;
        }
        else {
            /* Make this req pending reporting an error. */
            SET_REQ_ERROR(req, fn_WSAGetLastError());
            async_insert_pending_req(loop, req);
            handle->reqs_pending++;
        }
    }
    else {
        handle->flags |= ASYNC_HANDLE_ZERO_READ;

        buf.base = (char*) async_zero_;
        buf.len = 0;
        flags = MSG_PEEK;

        result = handle->func_wsarecv(handle->socket, (WSABUF*) &buf, 1, &bytes, &flags, &req->overlapped, NULL);

        if (ASYNC_SUCCEEDED_WITHOUT_IOCP(result == 0)) {
            /* Process the req without IOCP. */
            handle->flags |= ASYNC_HANDLE_READ_PENDING;
            req->overlapped.InternalHigh = bytes;
            handle->reqs_pending++;
            async_insert_pending_req(loop, req);
        }
        else if (ASYNC_SUCCEEDED_WITH_IOCP(result == 0)) {
            /* The req will be processed with IOCP. */
            handle->flags |= ASYNC_HANDLE_READ_PENDING;
            handle->reqs_pending++;
        }
        else {
            /* Make this req pending reporting an error. */
            SET_REQ_ERROR(req, fn_WSAGetLastError());
            async_insert_pending_req(loop, req);
            handle->reqs_pending++;
        }
    }
}

int async__udp_recv_start(async_udp_t* handle, async_alloc_cb alloc_cb, async_udp_recv_cb recv_cb)
{
    async_loop_t* loop = handle->loop;
    int err;

    if (handle->flags & ASYNC_HANDLE_READING) {
        return WSAEALREADY;
    }

    err = async_udp_maybe_bind(handle, (const struct sockaddr*) &async_addr_ip4_any_, sizeof(async_addr_ip4_any_), 0);
    if (err) {
        return err;
    }

    handle->flags |= ASYNC_HANDLE_READING;
    INCREASE_ACTIVE_COUNT(loop, handle);
    loop->active_udp_streams++;

    handle->recv_cb = recv_cb;
    handle->alloc_cb = alloc_cb;

    /* If reading was stopped and then started again, there could still be a */
    /* recv request pending. */
    if (!(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
        async_udp_queue_recv(loop, handle);
    }

    return 0;
}

int async__udp_recv_stop(async_udp_t* handle)
{
    if (handle->flags & ASYNC_HANDLE_READING) {
        handle->flags &= ~ASYNC_HANDLE_READING;
        handle->loop->active_udp_streams--;
        DECREASE_ACTIVE_COUNT(loop, handle);
    }

    return 0;
}

int async__send(async_udp_send_t* req, async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, uint32_t addrlen, async_udp_send_cb cb)
{
    async_loop_t* loop = handle->loop;
    DWORD result, bytes;

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_UDP_SEND;
    req->handle = handle;
    req->cb = cb;
    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    result = fn_WSASendTo(handle->socket, (WSABUF*)bufs, nbufs, &bytes, 0, addr, addrlen, &req->overlapped, NULL);

    if (ASYNC_SUCCEEDED_WITHOUT_IOCP(result == 0)) {
        /* Request completed immediately. */
        req->queued_bytes = 0;
        handle->reqs_pending++;
        handle->send_queue_size += req->queued_bytes;
        handle->send_queue_count++;
        REGISTER_HANDLE_REQ(loop, handle, req);
        async_insert_pending_req(loop, (async_req_t*)req);
    }
    else if (ASYNC_SUCCEEDED_WITH_IOCP(result == 0)) {
        /* Request queued by the kernel. */
        req->queued_bytes = async__count_bufs(bufs, nbufs);
        handle->reqs_pending++;
        handle->send_queue_size += req->queued_bytes;
        handle->send_queue_count++;
        REGISTER_HANDLE_REQ(loop, handle, req);
    }
    else {
        /* Send failed due to an error. */
        return fn_WSAGetLastError();
    }

    return 0;
}

void async_process_udp_recv_req(async_loop_t* loop, async_udp_t* handle, async_req_t* req)
{
    async_buf_t buf;
    int partial;

    handle->flags &= ~ASYNC_HANDLE_READ_PENDING;

    if (!REQ_SUCCESS(req)) {
        DWORD err = GET_REQ_SOCK_ERROR(req);
        if (err == WSAEMSGSIZE) {
            /* Not a real error, it just indicates that the received packet */
            /* was bigger than the receive buffer. */
        }
        else if (err == WSAECONNRESET || err == WSAENETRESET) {
            /* A previous sendto operation failed; ignore this error. If */
            /* zero-reading we need to call WSARecv/WSARecvFrom _without_ the */
            /* MSG_PEEK flag to clear out the error queue. For nonzero reads, */
            /* immediately queue a new receive. */
            if (!(handle->flags & ASYNC_HANDLE_ZERO_READ)) {
                goto done;
            }
        }
        else {
            /* A real error occurred. Report the error to the user only if we're */
            /* currently reading. */
            if (handle->flags & ASYNC_HANDLE_READING) {
                async_udp_recv_stop(handle);
                buf = (handle->flags & ASYNC_HANDLE_ZERO_READ) ? async_buf_init(NULL, 0) : handle->recv_buffer;
                handle->recv_cb(handle, async_translate_sys_error(err), &buf, NULL, 0);
            }
            goto done;
        }
    }

    if (!(handle->flags & ASYNC_HANDLE_ZERO_READ)) {
        /* Successful read */
        partial = !REQ_SUCCESS(req);
        handle->recv_cb(handle, req->overlapped.InternalHigh, &handle->recv_buffer, (const struct sockaddr*) &handle->recv_from, partial ? ASYNC_UDP_PARTIAL : 0);
    }
    else if (handle->flags & ASYNC_HANDLE_READING) {
        DWORD bytes, err, flags;
        struct sockaddr_storage from;
        int from_len;

        /* Do a nonblocking receive */
        /* TODO: try to read multiple datagrams at once. FIONREAD maybe? */
        handle->alloc_cb((async_handle_t*) handle, 65536, &buf);
        if (buf.len == 0) {
            handle->recv_cb(handle, ASYNC_ENOBUFS, &buf, NULL, 0);
            goto done;
        }

        __stosb((uint8_t*)&from, 0, sizeof from);
        from_len = sizeof from;

        flags = 0;

        if (fn_WSARecvFrom(handle->socket, (WSABUF*)&buf, 1, &bytes, &flags, (struct sockaddr*) &from, &from_len, NULL, NULL) != SOCKET_ERROR) {
            /* Message received */
            handle->recv_cb(handle, bytes, &buf, (const struct sockaddr*) &from, 0);
        }
        else {
            err = fn_WSAGetLastError();
            if (err == WSAEMSGSIZE) {
                /* Message truncated */
                handle->recv_cb(handle, bytes, &buf, (const struct sockaddr*) &from, ASYNC_UDP_PARTIAL);
            }
            else if (err == WSAEWOULDBLOCK) {
                /* Kernel buffer empty */
                handle->recv_cb(handle, 0, &buf, NULL, 0);
            }
            else if (err == WSAECONNRESET || err == WSAENETRESET) {
                /* WSAECONNRESET/WSANETRESET is ignored because this just indicates
                * that a previous sendto operation failed.
                */
                handle->recv_cb(handle, 0, &buf, NULL, 0);
            }
            else {
                /* Any other error that we want to report back to the user. */
                async_udp_recv_stop(handle);
                handle->recv_cb(handle, async_translate_sys_error(err), &buf, NULL, 0);
            }
        }
    }

done:
    /* Post another read if still reading and not closing. */
    if ((handle->flags & ASYNC_HANDLE_READING) && !(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
        async_udp_queue_recv(loop, handle);
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_udp_send_req(async_loop_t* loop, async_udp_t* handle, async_udp_send_t* req)
{
    int err;

    handle->send_queue_size -= req->queued_bytes;
    handle->send_queue_count--;

    UNREGISTER_HANDLE_REQ(loop, handle, req);

    if (req->cb) {
        err = 0;
        if (!REQ_SUCCESS(req)) {
            err = GET_REQ_SOCK_ERROR(req);
        }
        req->cb(req, async_translate_sys_error(err));
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

int async__udp_set_membership4(async_udp_t* handle, const struct sockaddr_in* multicast_addr, const char* interface_addr, async_membership membership)
{
    int err;
    int optname;
    struct ip_mreq mreq;

    if (handle->flags & ASYNC_HANDLE_IPV6) {
        return ASYNC_EINVAL;
    }

    /* If the socket is unbound, bind to inaddr_any. */
    err = async_udp_maybe_bind(handle, (const struct sockaddr*) &async_addr_ip4_any_, sizeof(async_addr_ip4_any_), ASYNC_UDP_REUSEADDR);
    if (err) {
        return async_translate_sys_error(err);
    }

    __stosb((uint8_t*)&mreq, 0, sizeof(mreq));

    if (interface_addr) {
        err = async_inet_pton(AF_INET, interface_addr, &mreq.imr_interface.s_addr);
        if (err) {
            return err;
        }
    }
    else {
        mreq.imr_interface.s_addr = fn_htonl(INADDR_ANY);
    }

    mreq.imr_multiaddr.s_addr = multicast_addr->sin_addr.s_addr;

    switch (membership) {
        case ASYNC_JOIN_GROUP:
            optname = IP_ADD_MEMBERSHIP;
            break;
        case ASYNC_LEAVE_GROUP:
            optname = IP_DROP_MEMBERSHIP;
            break;
        default:
            return ASYNC_EINVAL;
    }

    if (fn_setsockopt(handle->socket, IPPROTO_IP, optname, (char*) &mreq, sizeof mreq) == SOCKET_ERROR) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async__udp_set_membership6(async_udp_t* handle, const struct sockaddr_in6* multicast_addr, const char* interface_addr, async_membership membership)
{
    int optname;
    int err;
    struct ipv6_mreq mreq;
    struct sockaddr_in6 addr6;

    if ((handle->flags & ASYNC_HANDLE_BOUND) && !(handle->flags & ASYNC_HANDLE_IPV6)) {
        return ASYNC_EINVAL;
    }

    err = async_udp_maybe_bind(handle, (const struct sockaddr*) &async_addr_ip6_any_, sizeof(async_addr_ip6_any_), ASYNC_UDP_REUSEADDR);

    if (err) {
        return async_translate_sys_error(err);
    }

  __stosb((uint8_t*)&mreq, 0, sizeof(mreq));

    if (interface_addr) {
        if (async_ip6_addr(interface_addr, 0, &addr6)) {
            return ASYNC_EINVAL;
        }
        mreq.ipv6mr_interface = addr6.sin6_scope_id;
    }
    else {
        mreq.ipv6mr_interface = 0;
    }

    mreq.ipv6mr_multiaddr = multicast_addr->sin6_addr;

    switch (membership) {
        case ASYNC_JOIN_GROUP:
            optname = IPV6_ADD_MEMBERSHIP;
            break;
        case ASYNC_LEAVE_GROUP:
            optname = IPV6_DROP_MEMBERSHIP;
            break;
        default:
            return ASYNC_EINVAL;
    }

    if (fn_setsockopt(handle->socket, IPPROTO_IPV6, optname, (char*) &mreq, sizeof mreq) == SOCKET_ERROR) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async_udp_set_membership(async_udp_t* handle, const char* multicast_addr, const char* interface_addr, async_membership membership)
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if (async_ip4_addr(multicast_addr, 0, &addr4) == 0) {
        return async__udp_set_membership4(handle, &addr4, interface_addr, membership);
    }
    else if (async_ip6_addr(multicast_addr, 0, &addr6) == 0) {
        return async__udp_set_membership6(handle, &addr6, interface_addr, membership);
    }
    else {
        return ASYNC_EINVAL;
    }
}


int async_udp_set_multicast_interface(async_udp_t* handle, const char* interface_addr)
{
    struct sockaddr_storage addr_st;
    struct sockaddr_in* addr4;
    struct sockaddr_in6* addr6;

    addr4 = (struct sockaddr_in*) &addr_st;
    addr6 = (struct sockaddr_in6*) &addr_st;

    if (!interface_addr) {
        __stosb((uint8_t*)&addr_st, 0, sizeof addr_st);
        if (handle->flags & ASYNC_HANDLE_IPV6) {
            addr_st.ss_family = AF_INET6;
            addr6->sin6_scope_id = 0;
        }
        else {
            addr_st.ss_family = AF_INET;
            addr4->sin_addr.s_addr = fn_htonl(INADDR_ANY);
        }
    }
    else if (async_ip4_addr(interface_addr, 0, addr4) == 0) {
        /* nothing, address was parsed */
    }
    else if (async_ip6_addr(interface_addr, 0, addr6) == 0) {
        /* nothing, address was parsed */
    }
    else {
        return ASYNC_EINVAL;
    }

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return ASYNC_EBADF;
    }

    if (addr_st.ss_family == AF_INET) {
        if (fn_setsockopt(handle->socket, IPPROTO_IP, IP_MULTICAST_IF, (char*) &addr4->sin_addr, sizeof(addr4->sin_addr)) == SOCKET_ERROR) {
            return async_translate_sys_error(fn_WSAGetLastError());
        }
    }
    else if (addr_st.ss_family == AF_INET6) {
        if (fn_setsockopt(handle->socket, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*) &addr6->sin6_scope_id, sizeof(addr6->sin6_scope_id)) == SOCKET_ERROR) {
            return async_translate_sys_error(fn_WSAGetLastError());
        }
    }

    return 0;
}

int async_udp_set_broadcast(async_udp_t* handle, int value)
{
    BOOL optval = (BOOL) value;

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return ASYNC_EBADF;
    }

    if (fn_setsockopt(handle->socket, SOL_SOCKET, SO_BROADCAST, (char*) &optval, sizeof optval)) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async_udp_open(async_udp_t* handle, async_os_sock_t sock)
{
    WSAPROTOCOL_INFOW protocol_info;
    int opt_len;
    int err;

    /* Detect the address family of the socket. */
    opt_len = (int) sizeof protocol_info;
    if (fn_getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*) &protocol_info, &opt_len) == SOCKET_ERROR) {
        return async_translate_sys_error(fn_GetLastError());
    }

    err = async_udp_set_socket(handle->loop, handle, sock, protocol_info.iAddressFamily); 
    return async_translate_sys_error(err);
}

#define SOCKOPT_SETTER(name, option4, option6, validate)                      \
  int async_udp_set_##name(async_udp_t* handle, int value) {                        \
    DWORD optval = (DWORD) value;                                             \
                                                                              \
    if (!(validate(value))) {                                                 \
      return ASYNC_EINVAL;                                                       \
    }                                                                         \
                                                                              \
    if (!(handle->flags & ASYNC_HANDLE_BOUND))                                   \
      return ASYNC_EBADF;                                                        \
                                                                              \
    if (!(handle->flags & ASYNC_HANDLE_IPV6)) {                                  \
      /* Set IPv4 socket option */                                            \
      if (fn_setsockopt(handle->socket, IPPROTO_IP, option4, (char*)&optval, sizeof(optval))) { \
        return async_translate_sys_error(fn_WSAGetLastError());                     \
      }                                                                       \
    } else {                                                                  \
      /* Set IPv6 socket option */                                            \
      if (fn_setsockopt(handle->socket, IPPROTO_IPV6, option6, (char*)&optval, sizeof(optval))) { \
        return async_translate_sys_error(fn_WSAGetLastError());                     \
      }                                                                       \
    }                                                                         \
    return 0;                                                                 \
  }

#define VALIDATE_TTL(value) ((value) >= 1 && (value) <= 255)
#define VALIDATE_MULTICAST_TTL(value) ((value) >= -1 && (value) <= 255)
#define VALIDATE_MULTICAST_LOOP(value) (1)

SOCKOPT_SETTER(ttl, IP_TTL, IPV6_HOPLIMIT, VALIDATE_TTL)
SOCKOPT_SETTER(multicast_ttl, IP_MULTICAST_TTL, IPV6_MULTICAST_HOPS, VALIDATE_MULTICAST_TTL)
SOCKOPT_SETTER(multicast_loop, IP_MULTICAST_LOOP, IPV6_MULTICAST_LOOP, VALIDATE_MULTICAST_LOOP)

#undef SOCKOPT_SETTER
#undef VALIDATE_TTL
#undef VALIDATE_MULTICAST_TTL
#undef VALIDATE_MULTICAST_LOOP


/* This function is an egress point, i.e. it returns libuv errors rather than
 * system errors.
 */
int async__udp_bind(async_udp_t* handle, const struct sockaddr* addr, uint32_t addrlen, uint32_t flags)
{
    int err;

    err = async_udp_maybe_bind(handle, addr, addrlen, flags);
    if (err) {
        return async_translate_sys_error(err);
    }

    return 0;
}

/* This function is an egress point, i.e. it returns libuv errors rather than
 * system errors.
 */
int async__udp_send(async_udp_send_t* req, async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, uint32_t addrlen, async_udp_send_cb send_cb)
{
    const struct sockaddr* bind_addr;
    int err;

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        if (addrlen == sizeof(async_addr_ip4_any_)) {
            bind_addr = (const struct sockaddr*) &async_addr_ip4_any_;
        }
        else if (addrlen == sizeof(async_addr_ip6_any_)) {
            bind_addr = (const struct sockaddr*) &async_addr_ip6_any_;
        }

        err = async_udp_maybe_bind(handle, bind_addr, addrlen, 0);
        if (err) {
            return async_translate_sys_error(err);
        }
    }

    err = async__send(req, handle, bufs, nbufs, addr, addrlen, send_cb);
    if (err) {
        return async_translate_sys_error(err);
    }

    return 0;
}

int async__udp_try_send(async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, uint32_t addrlen)
{
    return ASYNC_ENOSYS;
}
