#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"


/*
 * Threshold of active tcp streams for which to preallocate tcp read buffers.
 * (Due to node slab allocator performing poorly under this pattern,
 *  the optimization is temporarily disabled (threshold=0).  This will be
 *  revisited once node allocator is improved.)
 */
const uint32_t async_active_tcp_streams_threshold = 0;

/*
 * Number of simultaneous pending AcceptEx calls.
 */
const uint32_t async_simultaneous_server_accepts = 32;

/* A zero-size buffer for use by async_tcp_read */
static char async_zero_[] = "";

int async__tcp_nodelay(async_tcp_t* handle, SOCKET socket, int enable)
{
    if (fn_setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&enable, sizeof enable) == -1) {
        return fn_WSAGetLastError();
    }
    return 0;
}

static int async__tcp_keepalive(async_tcp_t* handle, SOCKET socket, int enable, uint32_t delay)
{
    if (fn_setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (const char*)&enable, sizeof enable) == -1) {
        return fn_WSAGetLastError();
    }
    if (enable && fn_setsockopt(socket, IPPROTO_TCP, TCP_KEEPALIVE, (const char*)&delay, sizeof delay) == -1) {
        return fn_WSAGetLastError();
    }
    return 0;
}

static int async_tcp_set_socket(async_loop_t* loop, async_tcp_t* handle, SOCKET socket, int family, int imported)
{
    DWORD yes = 1;
    int non_ifs_lsp;
    int err;

    /* Set the socket to nonblocking mode */
    if (fn_ioctlsocket(socket, FIONBIO, &yes) == SOCKET_ERROR) {
        return fn_WSAGetLastError();
    }

    /* Associate it with the I/O completion port. */
    /* Use async_handle_t pointer as completion key. */
    if (fn_CreateIoCompletionPort((HANDLE)socket, loop->iocp, (ULONG_PTR)socket, 0) == NULL) {
        if (imported) {
            handle->flags |= ASYNC_HANDLE_EMULATE_IOCP;
        }
        else {
            return fn_GetLastError();
        }
    }

    if (family == AF_INET6) {
        non_ifs_lsp = async_tcp_non_ifs_lsp_ipv6;
    }
    else {
        non_ifs_lsp = async_tcp_non_ifs_lsp_ipv4;
    }

    if (fn_SetFileCompletionNotificationModes != NULL && !(handle->flags & ASYNC_HANDLE_EMULATE_IOCP) && !non_ifs_lsp) {
        if (fn_SetFileCompletionNotificationModes((HANDLE) socket, FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)) {
            handle->flags |= ASYNC_HANDLE_SYNC_BYPASS_IOCP;
        }
        else if (fn_GetLastError() != ERROR_INVALID_FUNCTION) {
            return fn_GetLastError();
        }
    }

    if (handle->flags & ASYNC_HANDLE_TCP_NODELAY) {
        err = async__tcp_nodelay(handle, socket, 1);
        if (err) {
            return err;
        }
  }

    /* TODO: Use stored delay. */
    if (handle->flags & ASYNC_HANDLE_TCP_KEEPALIVE) {
        err = async__tcp_keepalive(handle, socket, 1, 60);
        if (err) {
            return err;
        }
    }

    handle->socket = socket;

    if (family == AF_INET6) {
        handle->flags |= ASYNC_HANDLE_IPV6;
    }

    return 0;
}

int async_tcp_init(async_loop_t* loop, async_tcp_t* handle)
{
    async_stream_init(loop, (async_stream_t*) handle, ASYNC_TCP);

    handle->accept_reqs = NULL;
    handle->pending_accepts = NULL;
    handle->socket = INVALID_SOCKET;
    handle->reqs_pending = 0;
    handle->func_acceptex = NULL;
    handle->func_connectex = NULL;
    handle->processed_accepts = 0;
    handle->delayed_error = 0;

    return 0;
}

void async_tcp_endgame(async_loop_t* loop, async_tcp_t* handle)
{
    int err;
    uint32_t i;
    async_tcp_accept_t* req;

    if (handle->flags & ASYNC_HANDLE_CONNECTION && handle->shutdown_req != NULL && handle->write_reqs_pending == 0) {
        UNREGISTER_HANDLE_REQ(loop, handle, handle->shutdown_req);

        err = 0;
        if (handle->flags & ASYNC__HANDLE_CLOSING) {
            err = ERROR_OPERATION_ABORTED;
        }
        else if (fn_shutdown(handle->socket, SD_SEND) == SOCKET_ERROR) {
            err = fn_WSAGetLastError();
        }

        if (handle->shutdown_req->cb) {
            handle->shutdown_req->cb(handle->shutdown_req, async_translate_sys_error(err));
        }

        handle->shutdown_req = NULL;
        DECREASE_PENDING_REQ_COUNT(handle);
        return;
    }

    if (handle->flags & ASYNC__HANDLE_CLOSING && handle->reqs_pending == 0) {
        if (!(handle->flags & ASYNC_HANDLE_TCP_SOCKET_CLOSED)) {
            fn_closesocket(handle->socket);
            handle->socket = INVALID_SOCKET;
            handle->flags |= ASYNC_HANDLE_TCP_SOCKET_CLOSED;
        }

        if (!(handle->flags & ASYNC_HANDLE_CONNECTION) && handle->accept_reqs) {
            if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
                for (i = 0; i < async_simultaneous_server_accepts; i++) {
                    req = &handle->accept_reqs[i];
                    if (req->wait_handle != INVALID_HANDLE_VALUE) {
                        fn_UnregisterWait(req->wait_handle);
                        req->wait_handle = INVALID_HANDLE_VALUE;
                    }
                    if (req->event_handle) {
                        fn_CloseHandle(req->event_handle);
                        req->event_handle = NULL;
                    }
                }
            }

            memory_free(handle->accept_reqs);
            handle->accept_reqs = NULL;
        }

        if (handle->flags & ASYNC_HANDLE_CONNECTION && handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
            if (handle->read_req.wait_handle != INVALID_HANDLE_VALUE) {
                fn_UnregisterWait(handle->read_req.wait_handle);
                handle->read_req.wait_handle = INVALID_HANDLE_VALUE;
            }
            if (handle->read_req.event_handle) {
                fn_CloseHandle(handle->read_req.event_handle);
                handle->read_req.event_handle = NULL;
            }
        }

        async__handle_close(handle);
        loop->active_tcp_streams--;
    }
}

/* Unlike on Unix, here we don't set SO_REUSEADDR, because it doesn't just
* allow binding to addresses that are in use by sockets in TIME_WAIT, it
* effectively allows 'stealing' a port which is in use by another application.
*
* SO_EXCLUSIVEADDRUSE is also not good here because it does cehck all sockets,
* regardless of state, so we'd get an error even if the port is in use by a
* socket in TIME_WAIT state.
*
* See issue #1360.
*
*/
int async_tcp_try_bind(async_tcp_t* handle, const struct sockaddr* addr, uint32_t addrlen, uint32_t flags)
{
    DWORD err;
    int r;

    if (handle->socket == INVALID_SOCKET) {
        SOCKET sock;

        /* Cannot set IPv6-only mode on non-IPv6 socket. */
        if ((flags & ASYNC_TCP_IPV6ONLY) && addr->sa_family != AF_INET6) {
            return ERROR_INVALID_PARAMETER;
        }

        sock = fn_socket(addr->sa_family, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            return fn_WSAGetLastError();
        }

        // Make the socket non-inheritable
        if (!fn_SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0)) {
            err = fn_GetLastError();
            fn_closesocket(sock);
            return err;
        }

        err = async_tcp_set_socket(handle->loop, handle, sock, addr->sa_family, 0);
        if (err) {
            fn_closesocket(sock);
            return err;
        }
    }

#ifdef IPV6_V6ONLY
    if (addr->sa_family == AF_INET6) {
        int on = (flags & ASYNC_TCP_IPV6ONLY) != 0;

        /* TODO: how to handle errors? This may fail if there is no ipv4 stack */
        /* available, or when run on XP/2003 which have no support for dualstack */
        /* sockets. For now we're silently ignoring the error. */
        fn_setsockopt(handle->socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof on);
    }
#endif

    r = fn_bind(handle->socket, addr, addrlen);

    if (r == SOCKET_ERROR) {
        err = fn_WSAGetLastError();
        if (err == WSAEADDRINUSE) {
            /* Some errors are not to be reported until connect() or listen() */
            handle->delayed_error = err;
        }
        else {
            return err;
        }
    }

    handle->flags |= ASYNC_HANDLE_BOUND;

    return 0;
}

void CALLBACK post_completion(void* context, BOOLEAN timed_out)
{
    async_req_t* req;
    async_tcp_t* handle;

    req = (async_req_t*) context;
    handle = (async_tcp_t*)req->data;

    if (!fn_PostQueuedCompletionStatus(handle->loop->iocp, req->overlapped.InternalHigh, 0, &req->overlapped)) {
        LOG("PostQueuedCompletionStatus failed with error 0x%08X", fn_GetLastError());
    }
}

void CALLBACK post_write_completion(void* context, BOOLEAN timed_out)
{
    async_write_t* req;
    async_tcp_t* handle;

    req = (async_write_t*) context;
    handle = (async_tcp_t*)req->handle;

    if (!fn_PostQueuedCompletionStatus(handle->loop->iocp, req->overlapped.InternalHigh, 0, &req->overlapped)) {
        LOG("PostQueuedCompletionStatus failed with error 0x%08X", fn_GetLastError());
    }
}

void async_tcp_queue_accept(async_tcp_t* handle, async_tcp_accept_t* req)
{
    async_loop_t* loop = handle->loop;
    BOOL success;
    DWORD bytes;
    SOCKET accept_socket;
    short family;

    /* choose family and extension function */
    if (handle->flags & ASYNC_HANDLE_IPV6) {
        family = AF_INET6;
    }
    else {
        family = AF_INET;
    }

    /* Open a socket for the accepted connection. */
    accept_socket = fn_socket(family, SOCK_STREAM, 0);
    if (accept_socket == INVALID_SOCKET) {
        SET_REQ_ERROR(req, fn_WSAGetLastError());
        async_insert_pending_req(loop, (async_req_t*)req);
        ++handle->reqs_pending;
        return;
    }

    /* Make the socket non-inheritable */
    if (!fn_SetHandleInformation((HANDLE) accept_socket, HANDLE_FLAG_INHERIT, 0)) {
        SET_REQ_ERROR(req, fn_GetLastError());
        async_insert_pending_req(loop, (async_req_t*)req);
        handle->reqs_pending++;
        fn_closesocket(accept_socket);
        return;
    }

    /* Prepare the overlapped structure. */
    __stosb((uint8_t*)&(req->overlapped), 0, sizeof(req->overlapped));
    if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
        req->overlapped.hEvent = (HANDLE) ((ULONG_PTR) req->event_handle | 1);
    }

    success = handle->func_acceptex(handle->socket, accept_socket, (void*)req->accept_buffer, 0, sizeof(struct sockaddr_storage), sizeof(struct sockaddr_storage), &bytes, &req->overlapped);

    if (ASYNC_SUCCEEDED_WITHOUT_IOCP(success)) {
        /* Process the req without IOCP. */
        req->accept_socket = accept_socket;
        handle->reqs_pending++;
        async_insert_pending_req(loop, (async_req_t*)req);
    }
    else if (ASYNC_SUCCEEDED_WITH_IOCP(success)) {
        /* The req will be processed with IOCP. */
        req->accept_socket = accept_socket;
        handle->reqs_pending++;
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP && req->wait_handle == INVALID_HANDLE_VALUE && !fn_RegisterWaitForSingleObject(&req->wait_handle, req->event_handle, post_completion, (void*) req, INFINITE, WT_EXECUTEINWAITTHREAD)) {
            SET_REQ_ERROR(req, fn_GetLastError());
            async_insert_pending_req(loop, (async_req_t*)req);
            handle->reqs_pending++;
            return;
        }
    }
    else {
        /* Make this req pending reporting an error. */
        SET_REQ_ERROR(req, fn_WSAGetLastError());
        async_insert_pending_req(loop, (async_req_t*)req);
        handle->reqs_pending++;
        /* Destroy the preallocated client socket. */
        fn_closesocket(accept_socket);
        /* Destroy the event handle */
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
            fn_CloseHandle(req->overlapped.hEvent);
            req->event_handle = NULL;
        }
    }
}


void async_tcp_queue_read(async_loop_t* loop, async_tcp_t* handle)
{
    async_read_t* req;
    async_buf_t buf;
    int result;
    DWORD bytes, flags;

    req = &handle->read_req;
    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    /*
    * Preallocate a read buffer if the number of active streams is below
    * the threshold.
    */
    if (loop->active_tcp_streams < async_active_tcp_streams_threshold) {
        handle->flags &= ~ASYNC_HANDLE_ZERO_READ;
        handle->alloc_cb((async_handle_t*) handle, 65536, &handle->read_buffer);
        if (handle->read_buffer.len == 0) {
            handle->read_cb((async_stream_t*) handle, ASYNC_ENOBUFS, &handle->read_buffer);
            return;
        }
        buf = handle->read_buffer;
    }
    else {
        handle->flags |= ASYNC_HANDLE_ZERO_READ;
        buf.base = (char*) &async_zero_;
        buf.len = 0;
    }

    /* Prepare the overlapped structure. */
    __stosb((uint8_t*)&(req->overlapped), 0, sizeof(req->overlapped));
    if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
        req->overlapped.hEvent = (HANDLE) ((ULONG_PTR) req->event_handle | 1);
    }

    flags = 0;
    result = fn_WSARecv(handle->socket, (WSABUF*)&buf, 1, &bytes, &flags, &req->overlapped, NULL);

    if (ASYNC_SUCCEEDED_WITHOUT_IOCP(result == 0)) {
        /* Process the req without IOCP. */
        handle->flags |= ASYNC_HANDLE_READ_PENDING;
        req->overlapped.InternalHigh = bytes;
        handle->reqs_pending++;
        async_insert_pending_req(loop, (async_req_t*)req);
    }
    else if (ASYNC_SUCCEEDED_WITH_IOCP(result == 0)) {
        /* The req will be processed with IOCP. */
        handle->flags |= ASYNC_HANDLE_READ_PENDING;
        handle->reqs_pending++;
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP && req->wait_handle == INVALID_HANDLE_VALUE && !fn_RegisterWaitForSingleObject(&req->wait_handle, req->event_handle, post_completion, (void*) req, INFINITE, WT_EXECUTEINWAITTHREAD)) {
            SET_REQ_ERROR(req, fn_GetLastError());
            async_insert_pending_req(loop, (async_req_t*)req);
        }
    }
    else {
        /* Make this req pending reporting an error. */
        SET_REQ_ERROR(req, fn_WSAGetLastError());
        async_insert_pending_req(loop, (async_req_t*)req);
        handle->reqs_pending++;
    }
}


int async_tcp_listen(async_tcp_t* handle, int backlog, async_connection_cb cb)
{
    async_loop_t* loop = handle->loop;
    uint32_t i, simultaneous_accepts;
    async_tcp_accept_t* req;
    int err;

    if (handle->flags & ASYNC_HANDLE_LISTENING) {
        handle->connection_cb = cb;
    }

    if (handle->flags & ASYNC_HANDLE_READING) {
        return WSAEISCONN;
    }

    if (handle->delayed_error) {
        return handle->delayed_error;
    }

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        err = async_tcp_try_bind(handle, (const struct sockaddr*) &async_addr_ip4_any_, sizeof(async_addr_ip4_any_), 0);
        if (err) {
            return err;
        }
        if (handle->delayed_error) {
            return handle->delayed_error;
        }
    }

    if (!handle->func_acceptex) {
        if (!async_get_acceptex_function(handle->socket, &handle->func_acceptex)) {
            return WSAEAFNOSUPPORT;
        }
    }

    if (!(handle->flags & ASYNC_HANDLE_SHARED_TCP_SOCKET) && fn_listen(handle->socket, backlog) == SOCKET_ERROR) {
        return fn_WSAGetLastError();
    }

    handle->flags |= ASYNC_HANDLE_LISTENING;
    handle->connection_cb = cb;
    INCREASE_ACTIVE_COUNT(loop, handle);

    simultaneous_accepts = handle->flags & ASYNC_HANDLE_TCP_SINGLE_ACCEPT ? 1 : async_simultaneous_server_accepts;

    if (!handle->accept_reqs) {
        handle->accept_reqs = (async_tcp_accept_t*)memory_alloc(async_simultaneous_server_accepts * sizeof(async_tcp_accept_t));

        for (i = 0; i < simultaneous_accepts; ++i) {
            req = &handle->accept_reqs[i];
            async_req_init(loop, (async_req_t*)req);
            req->type = ASYNC_ACCEPT;
            req->accept_socket = INVALID_SOCKET;
            req->data = handle;

            req->wait_handle = INVALID_HANDLE_VALUE;
            if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
                req->event_handle = fn_CreateEventW(NULL, 0, 0, NULL);
                if (!req->event_handle) {
                    LOG("CreateEvent failed with error 0x%08X", fn_GetLastError());
                    return fn_GetLastError();
                }
            }
            else {
                req->event_handle = NULL;
            }

            async_tcp_queue_accept(handle, req);
        }

        /* Initialize other unused requests too, because async_tcp_endgame */
        /* doesn't know how how many requests were intialized, so it will */
        /* try to clean up {async_simultaneous_server_accepts} requests. */
        for (i = simultaneous_accepts; i < async_simultaneous_server_accepts; i++) {
            req = &handle->accept_reqs[i];
            async_req_init(loop, (async_req_t*) req);
            req->type = ASYNC_ACCEPT;
            req->accept_socket = INVALID_SOCKET;
            req->data = handle;
            req->wait_handle = INVALID_HANDLE_VALUE;
            req->event_handle = NULL;
        }
    }

    return 0;
}

int async_tcp_accept(async_tcp_t* server, async_tcp_t* client)
{
    async_loop_t* loop = server->loop;
    int err = 0;
    int family;

    async_tcp_accept_t* req = server->pending_accepts;

    if (!req) {
        /* No valid connections found, so we error out. */
        return WSAEWOULDBLOCK;
    }

    if (req->accept_socket == INVALID_SOCKET) {
        return WSAENOTCONN;
    }

    if (server->flags & ASYNC_HANDLE_IPV6) {
        family = AF_INET6;
    }
    else {
        family = AF_INET;
    }

    err = async_tcp_set_socket(client->loop, client, req->accept_socket, family, 0);
    if (err) {
        fn_closesocket(req->accept_socket);
    }
    else {
        async_connection_init((async_stream_t*) client);
        /* AcceptEx() implicitly binds the accepted socket. */
        client->flags |= ASYNC_HANDLE_BOUND | ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE;
    }

    /* Prepare the req to pick up a new connection */
    server->pending_accepts = req->next_pending;
    req->next_pending = NULL;
    req->accept_socket = INVALID_SOCKET;

    if (!(server->flags & ASYNC__HANDLE_CLOSING)) {
        /* Check if we're in a middle of changing the number of pending accepts. */
        if (!(server->flags & ASYNC_HANDLE_TCP_ACCEPT_STATE_CHANGING)) {
            async_tcp_queue_accept(server, req);
        }
        else {
            /* We better be switching to a single pending accept. */

            server->processed_accepts++;

            if (server->processed_accepts >= async_simultaneous_server_accepts) {
                server->processed_accepts = 0;
                /*
                * All previously queued accept requests are now processed.
                * We now switch to queueing just a single accept.
                */
                async_tcp_queue_accept(server, &server->accept_reqs[0]);
                server->flags &= ~ASYNC_HANDLE_TCP_ACCEPT_STATE_CHANGING;
                server->flags |= ASYNC_HANDLE_TCP_SINGLE_ACCEPT;
            }
        }
    }

    loop->active_tcp_streams++;

    return err;
}

int async_tcp_read_start(async_tcp_t* handle, async_alloc_cb alloc_cb, async_read_cb read_cb)
{
    async_loop_t* loop = handle->loop;

    handle->flags |= ASYNC_HANDLE_READING;
    handle->read_cb = read_cb;
    handle->alloc_cb = alloc_cb;
    INCREASE_ACTIVE_COUNT(loop, handle);

    /* If reading was stopped and then started again, there could still be a */
    /* read request pending. */
    if (!(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP && !handle->read_req.event_handle) {
            handle->read_req.event_handle = fn_CreateEventW(NULL, 0, 0, NULL);
            if (!handle->read_req.event_handle) {
                LOG("CreateEvent failed with error 0x%08X", fn_GetLastError());
                return fn_GetLastError();
            }
        }
        async_tcp_queue_read(loop, handle);
    }

    return 0;
}


int async_tcp_try_connect(async_connect_t* req, async_tcp_t* handle, const struct sockaddr* addr, uint32_t addrlen, async_connect_cb cb)
{
    async_loop_t* loop = handle->loop;
    const struct sockaddr* bind_addr;
    BOOL success;
    DWORD bytes;
    int err;

    if (handle->delayed_error) {
        return handle->delayed_error;
    }

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        if (addrlen == sizeof(async_addr_ip4_any_)) {
            bind_addr = (const struct sockaddr*) &async_addr_ip4_any_;
        }
        else if (addrlen == sizeof(async_addr_ip6_any_)) {
            bind_addr = (const struct sockaddr*) &async_addr_ip6_any_;
        }
        err = async_tcp_try_bind(handle, bind_addr, addrlen, 0);
        if (err) {
            return err;
        }
        if (handle->delayed_error) {
            return handle->delayed_error;
        }
    }

    if (!handle->func_connectex) {
        if (!async_get_connectex_function(handle->socket, &handle->func_connectex)) {
            return WSAEAFNOSUPPORT;
        }
    }

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_CONNECT;
    req->handle = (async_stream_t*) handle;
    req->cb = cb;
    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    success = handle->func_connectex(handle->socket, addr, addrlen, NULL, 0, &bytes, &req->overlapped);

    if (ASYNC_SUCCEEDED_WITHOUT_IOCP(success)) {
        /* Process the req without IOCP. */
        handle->reqs_pending++;
        REGISTER_HANDLE_REQ(loop, handle, req);
        async_insert_pending_req(loop, (async_req_t*)req);
    }
    else if (ASYNC_SUCCEEDED_WITH_IOCP(success)) {
        /* The req will be processed with IOCP. */
        handle->reqs_pending++;
        REGISTER_HANDLE_REQ(loop, handle, req);
    }
    else {
        return fn_WSAGetLastError();
    }

    return 0;
}

int async_tcp_getsockname(const async_tcp_t* handle, struct sockaddr* name, int* namelen)
{
    int result;

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return ASYNC_EINVAL;
    }

    if (handle->delayed_error) {
        return async_translate_sys_error(handle->delayed_error);
    }

    result = fn_getsockname(handle->socket, name, namelen);
    if (result != 0) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async_tcp_getpeername(const async_tcp_t* handle, struct sockaddr* name, int* namelen)
{
    int result;

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return ASYNC_EINVAL;
    }

    if (handle->delayed_error) {
        return async_translate_sys_error(handle->delayed_error);
    }

    result = fn_getpeername(handle->socket, name, namelen);
    if (result != 0) {
        return async_translate_sys_error(fn_WSAGetLastError());
    }

    return 0;
}

int async_tcp_write(async_loop_t* loop, async_write_t* req, async_tcp_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb)
{
    int result;
    DWORD bytes;

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_WRITE;
    req->handle = (async_stream_t*) handle;
    req->cb = cb;

    /* Prepare the overlapped structure. */
    __stosb((uint8_t*)&(req->overlapped), 0, sizeof(req->overlapped));
    if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
        req->event_handle = fn_CreateEventW(NULL, 0, 0, NULL);
        if (!req->event_handle) {
            LOG("CreateEvent failed with error 0x%08X", fn_GetLastError());
            return fn_GetLastError();
        }
        req->overlapped.hEvent = (HANDLE) ((ULONG_PTR) req->event_handle | 1);
        req->wait_handle = INVALID_HANDLE_VALUE;
    }

    result = fn_WSASend(handle->socket, (WSABUF*) bufs, nbufs, &bytes, 0, &req->overlapped, NULL);

    if (ASYNC_SUCCEEDED_WITHOUT_IOCP(result == 0)) {
        /* Request completed immediately. */
        req->queued_bytes = 0;
        handle->reqs_pending++;
        handle->write_reqs_pending++;
        REGISTER_HANDLE_REQ(loop, handle, req);
        async_insert_pending_req(loop, (async_req_t*) req);
    }
    else if (ASYNC_SUCCEEDED_WITH_IOCP(result == 0)) {
        /* Request queued by the kernel. */
        req->queued_bytes = async__count_bufs(bufs, nbufs);
        handle->reqs_pending++;
        handle->write_reqs_pending++;
        REGISTER_HANDLE_REQ(loop, handle, req);
        handle->write_queue_size += req->queued_bytes;
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP && !fn_RegisterWaitForSingleObject(&req->wait_handle, req->event_handle, post_write_completion, (void*) req, INFINITE, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)) {
            SET_REQ_ERROR(req, fn_GetLastError());
            async_insert_pending_req(loop, (async_req_t*)req);
        }
    }
    else {
        /* Send failed due to an error. */
        return fn_WSAGetLastError();
    }

    return 0;
}

void async_process_tcp_read_req(async_loop_t* loop, async_tcp_t* handle, async_req_t* req)
{
    DWORD bytes, flags, err;
    async_buf_t buf;

    handle->flags &= ~ASYNC_HANDLE_READ_PENDING;

    if (!REQ_SUCCESS(req)) {
        /* An error occurred doing the read. */
        if ((handle->flags & ASYNC_HANDLE_READING) || !(handle->flags & ASYNC_HANDLE_ZERO_READ)) {
            handle->flags &= ~ASYNC_HANDLE_READING;
            DECREASE_ACTIVE_COUNT(loop, handle);
            buf = (handle->flags & ASYNC_HANDLE_ZERO_READ) ? async_buf_init(NULL, 0) : handle->read_buffer;

            err = GET_REQ_SOCK_ERROR(req);

            if (err == WSAECONNABORTED) {
                /*
                * Turn WSAECONNABORTED into ASYNC_ECONNRESET to be consistent with Unix.
                */
                err = WSAECONNRESET;
            }

            handle->read_cb((async_stream_t*)handle, async_translate_sys_error(err), &buf);
        }
    }
    else {
        if (!(handle->flags & ASYNC_HANDLE_ZERO_READ)) {
            /* The read was done with a non-zero buffer length. */
            if (req->overlapped.InternalHigh > 0) {
                /* Successful read */
                handle->read_cb((async_stream_t*)handle, req->overlapped.InternalHigh, &handle->read_buffer);
                /* Read again only if bytes == buf.len */
                if (req->overlapped.InternalHigh < handle->read_buffer.len) {
                    goto done;
                }
            }
            else {
                /* Connection closed */
                if (handle->flags & ASYNC_HANDLE_READING) {
                    handle->flags &= ~ASYNC_HANDLE_READING;
                    DECREASE_ACTIVE_COUNT(loop, handle);
                }
                handle->flags &= ~ASYNC_HANDLE_READABLE;

                buf.base = 0;
                buf.len = 0;
                handle->read_cb((async_stream_t*)handle, ASYNC_EOF, &handle->read_buffer);
                goto done;
            }
        }

        /* Do nonblocking reads until the buffer is empty */
        while (handle->flags & ASYNC_HANDLE_READING) {
            handle->alloc_cb((async_handle_t*) handle, 65536, &buf);
            if (buf.len == 0) {
                handle->read_cb((async_stream_t*) handle, ASYNC_ENOBUFS, &buf);
                break;
            }

            flags = 0;
            if (fn_WSARecv(handle->socket, (WSABUF*)&buf, 1, &bytes, &flags, NULL, NULL) != SOCKET_ERROR) {
                if (bytes > 0) {
                    /* Successful read */
                    handle->read_cb((async_stream_t*)handle, bytes, &buf);
                    /* Read again only if bytes == buf.len */
                    if (bytes < buf.len) {
                        break;
                    }
                }
                else {
                    /* Connection closed */
                    handle->flags &= ~(ASYNC_HANDLE_READING | ASYNC_HANDLE_READABLE);
                    DECREASE_ACTIVE_COUNT(loop, handle);
                    handle->read_cb((async_stream_t*)handle, ASYNC_EOF, &buf);
                    break;
                }
            }
            else {
                err = fn_WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    /* Read buffer was completely empty, report a 0-byte read. */
                    handle->read_cb((async_stream_t*)handle, 0, &buf);
                }
                else {
                    /* Ouch! serious error. */
                    handle->flags &= ~ASYNC_HANDLE_READING;
                    DECREASE_ACTIVE_COUNT(loop, handle);

                    if (err == WSAECONNABORTED) {
                        /* Turn WSAECONNABORTED into ASYNC_ECONNRESET to be consistent with */
                        /* Unix. */
                        err = WSAECONNRESET;
                    }

                    handle->read_cb((async_stream_t*)handle, async_translate_sys_error(err), &buf);
                }
                break;
            }
        }

done:
        /* Post another read if still reading and not closing. */
        if ((handle->flags & ASYNC_HANDLE_READING) && !(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
            async_tcp_queue_read(loop, handle);
        }
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}


void async_process_tcp_write_req(async_loop_t* loop, async_tcp_t* handle, async_write_t* req)
{
    int err;

    handle->write_queue_size -= req->queued_bytes;

    UNREGISTER_HANDLE_REQ(loop, handle, req);

    if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
        if (req->wait_handle != INVALID_HANDLE_VALUE) {
            fn_UnregisterWait(req->wait_handle);
            req->wait_handle = INVALID_HANDLE_VALUE;
        }
        if (req->event_handle) {
            fn_CloseHandle(req->event_handle);
            req->event_handle = NULL;
        }
    }

    if (req->cb) {
        err = async_translate_sys_error(GET_REQ_SOCK_ERROR(req));
        if (err == ASYNC_ECONNABORTED) {
            /* use UV_ECANCELED for consistency with Unix */
            err = ASYNC_ECANCELED;
        }
        req->cb(req, err);
    }

    --handle->write_reqs_pending;
    if (handle->shutdown_req != NULL && handle->write_reqs_pending == 0) {
        async_want_endgame(loop, (async_handle_t*)handle);
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_tcp_accept_req(async_loop_t* loop, async_tcp_t* handle, async_req_t* raw_req)
{
    async_tcp_accept_t* req = (async_tcp_accept_t*) raw_req;
    int err;

    /* If handle->accepted_socket is not a valid socket, then */
    /* async_queue_accept must have failed. This is a serious error. We stop */
    /* accepting connections and report this error to the connection */
    /* callback. */
    if (req->accept_socket == INVALID_SOCKET) {
        if (handle->flags & ASYNC_HANDLE_LISTENING) {
            handle->flags &= ~ASYNC_HANDLE_LISTENING;
            DECREASE_ACTIVE_COUNT(loop, handle);
            if (handle->connection_cb) {
                err = GET_REQ_SOCK_ERROR(req);
                handle->connection_cb((async_stream_t*)handle, async_translate_sys_error(err));
            }
        }
    }
    else if (REQ_SUCCESS(req) && fn_setsockopt(req->accept_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&handle->socket, sizeof(handle->socket)) == 0) {
        req->next_pending = handle->pending_accepts;
        handle->pending_accepts = req;

        /* Accept and SO_UPDATE_ACCEPT_CONTEXT were successful. */
        if (handle->connection_cb) {
            handle->connection_cb((async_stream_t*)handle, 0);
        }
    }
    else {
        /* Error related to accepted socket is ignored because the server */
        /* socket may still be healthy. If the server socket is broken */
        /* async_queue_accept will detect it. */
        fn_closesocket(req->accept_socket);
        req->accept_socket = INVALID_SOCKET;
        if (handle->flags & ASYNC_HANDLE_LISTENING) {
            async_tcp_queue_accept(handle, req);
        }
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_tcp_connect_req(async_loop_t* loop, async_tcp_t* handle, async_connect_t* req)
{
    int err;

    UNREGISTER_HANDLE_REQ(loop, handle, req);

    err = 0;
    if (REQ_SUCCESS(req)) {
        if (fn_setsockopt(handle->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0) {
            async_connection_init((async_stream_t*)handle);
            handle->flags |= ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE;
            loop->active_tcp_streams++;
        }
        else {
            err = fn_WSAGetLastError();
        }
    }
    else {
        err = GET_REQ_SOCK_ERROR(req);
    }
    req->cb(req, async_translate_sys_error(err));

    DECREASE_PENDING_REQ_COUNT(handle);
}

int async_tcp_import(async_tcp_t* tcp, async__ipc_socket_info_ex* socket_info_ex, int tcp_connection)
{
    int err;

    SOCKET socket = fn_WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &socket_info_ex->socket_info, 0, WSA_FLAG_OVERLAPPED);

    if (socket == INVALID_SOCKET) {
        return fn_WSAGetLastError();
    }

    if (!fn_SetHandleInformation((HANDLE) socket, HANDLE_FLAG_INHERIT, 0)) {
        err = fn_GetLastError();
        fn_closesocket(socket);
        return err;
    }

    err = async_tcp_set_socket(tcp->loop, tcp, socket, socket_info_ex->socket_info.iAddressFamily, 1);
    if (err) {
        fn_closesocket(socket);
        return err;
    }

    if (tcp_connection) {
        async_connection_init((async_stream_t*)tcp);
        tcp->flags |= ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE;
    }

    tcp->flags |= ASYNC_HANDLE_BOUND;
    tcp->flags |= ASYNC_HANDLE_SHARED_TCP_SOCKET;

    tcp->delayed_error = socket_info_ex->delayed_error;

    tcp->loop->active_tcp_streams++;
    return 0;
}

int async_tcp_nodelay(async_tcp_t* handle, int enable)
{
    int err;

    if (handle->socket != INVALID_SOCKET) {
        err = async__tcp_nodelay(handle, handle->socket, enable);
        if (err) {
            return err;
        }
    }

    if (enable) {
        handle->flags |= ASYNC_HANDLE_TCP_NODELAY;
    }
    else {
        handle->flags &= ~ASYNC_HANDLE_TCP_NODELAY;
    }

    return 0;
}

int async_tcp_keepalive(async_tcp_t* handle, int enable, uint32_t delay)
{
    int err;

    if (handle->socket != INVALID_SOCKET) {
        err = async__tcp_keepalive(handle, handle->socket, enable, delay);
        if (err) {
            return err;
        }
  }

    if (enable) {
        handle->flags |= ASYNC_HANDLE_TCP_KEEPALIVE;
    }
    else {
        handle->flags &= ~ASYNC_HANDLE_TCP_KEEPALIVE;
    }

    /* TODO: Store delay if handle->socket isn't created yet. */

    return 0;
}

int async_tcp_duplicate_socket(async_tcp_t* handle, int pid, LPWSAPROTOCOL_INFOW protocol_info)
{
    if (!(handle->flags & ASYNC_HANDLE_CONNECTION)) {
        /*
         * We're about to share the socket with another process.  Because
         * this is a listening socket, we assume that the other process will
         * be accepting connections on it.  So, before sharing the socket
         * with another process, we call listen here in the parent process.
         */

        if (!(handle->flags & ASYNC_HANDLE_LISTENING)) {
            if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
                return ERROR_INVALID_PARAMETER;
            }

            if (!(handle->delayed_error)) {
                if (fn_listen(handle->socket, SOMAXCONN) == SOCKET_ERROR) {
                    handle->delayed_error = fn_WSAGetLastError();
                }
            }
        }
    }

    if (fn_WSADuplicateSocketW(handle->socket, pid, protocol_info)) {
        return fn_WSAGetLastError();
    }

    handle->flags |= ASYNC_HANDLE_SHARED_TCP_SOCKET;

    return 0;
}

int async_tcp_simultaneous_accepts(async_tcp_t* handle, int enable)
{
    if (handle->flags & ASYNC_HANDLE_CONNECTION) {
        return ASYNC_EINVAL;
    }

    /* Check if we're already in the desired mode. */
    if ((enable && !(handle->flags & ASYNC_HANDLE_TCP_SINGLE_ACCEPT)) || (!enable && handle->flags & ASYNC_HANDLE_TCP_SINGLE_ACCEPT)) {
        return 0;
    }

    /* Don't allow switching from single pending accept to many. */
    if (enable) {
        return ASYNC_ENOTSUP;
    }

    /* Check if we're in a middle of changing the number of pending accepts. */
    if (handle->flags & ASYNC_HANDLE_TCP_ACCEPT_STATE_CHANGING) {
        return 0;
    }

    handle->flags |= ASYNC_HANDLE_TCP_SINGLE_ACCEPT;

    /* Flip the changing flag if we have already queued multiple accepts. */
    if (handle->flags & ASYNC_HANDLE_LISTENING) {
        handle->flags |= ASYNC_HANDLE_TCP_ACCEPT_STATE_CHANGING;
    }

    return 0;
}

int async_tcp_try_cancel_io(async_tcp_t* tcp)
{
    SOCKET socket = tcp->socket;
    int non_ifs_lsp;

    /* Check if we have any non-IFS LSPs stacked on top of TCP */
    non_ifs_lsp = (tcp->flags & ASYNC_HANDLE_IPV6) ? async_tcp_non_ifs_lsp_ipv6 : async_tcp_non_ifs_lsp_ipv4;

    /* If there are non-ifs LSPs then try to obtain a base handle for the */
    /* socket. This will always fail on Windows XP/3k. */
    if (non_ifs_lsp) {
        DWORD bytes;
        if (fn_WSAIoctl(socket, SIO_BASE_HANDLE, NULL, 0, &socket, sizeof socket, &bytes, NULL, NULL) != 0) {
            /* Failed. We can't do CancelIo. */
            return -1;
        }
    }

    if (!fn_CancelIo((HANDLE) socket)) {
        return fn_GetLastError();
    }

    /* It worked. */
    return 0;
}


void async_tcp_close(async_loop_t* loop, async_tcp_t* tcp)
{
    int close_socket = 1;

    if (tcp->flags & ASYNC_HANDLE_READ_PENDING) {
        /* In order for winsock to do a graceful close there must not be any */
        /* any pending reads, or the socket must be shut down for writing */
        if (!(tcp->flags & ASYNC_HANDLE_SHARED_TCP_SOCKET)) {
            /* Just do shutdown on non-shared sockets, which ensures graceful close. */
            fn_shutdown(tcp->socket, SD_SEND);
        }
        else if (async_tcp_try_cancel_io(tcp) == 0) {
            /* In case of a shared socket, we try to cancel all outstanding I/O, */
            /* If that works, don't close the socket yet - wait for the read req to */
            /* return and close the socket in async_tcp_endgame. */
            close_socket = 0;
        }
        else {
            /* When cancelling isn't possible - which could happen when an LSP is */
            /* present on an old Windows version, we will have to close the socket */
            /* with a read pending. That is not nice because trailing sent bytes */
            /* may not make it to the other side. */
        }
    }
    else if ((tcp->flags & ASYNC_HANDLE_SHARED_TCP_SOCKET) && tcp->accept_reqs != NULL) {
        /* Under normal circumstances closesocket() will ensure that all pending */
        /* accept reqs are canceled. However, when the socket is shared the */
        /* presence of another reference to the socket in another process will */
        /* keep the accept reqs going, so we have to ensure that these are */
        /* canceled. */
        if (async_tcp_try_cancel_io(tcp) != 0) {
            /* When cancellation is not possible, there is another option: we can */
            /* close the incoming sockets, which will also cancel the accept */
            /* operations. However this is not cool because we might inadvertedly */
            /* close a socket that just accepted a new connection, which will */
            /* cause the connection to be aborted. */
            uint32_t i;
            for (i = 0; i < async_simultaneous_server_accepts; ++i) {
                async_tcp_accept_t* req = &tcp->accept_reqs[i];
                if (req->accept_socket != INVALID_SOCKET && !HasOverlappedIoCompleted(&req->overlapped)) {
                    fn_closesocket(req->accept_socket);
                    req->accept_socket = INVALID_SOCKET;
                }
            }
        }
    }

    if (tcp->flags & ASYNC_HANDLE_READING) {
        tcp->flags &= ~ASYNC_HANDLE_READING;
        DECREASE_ACTIVE_COUNT(loop, tcp);
    }

    if (tcp->flags & ASYNC_HANDLE_LISTENING) {
        tcp->flags &= ~ASYNC_HANDLE_LISTENING;
        DECREASE_ACTIVE_COUNT(loop, tcp);
    }

    if (close_socket) {
        fn_closesocket(tcp->socket);
        tcp->flags |= ASYNC_HANDLE_TCP_SOCKET_CLOSED;
    }

    tcp->flags &= ~(ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE);
    async__handle_closing(tcp);

    if (tcp->reqs_pending == 0) {
        async_want_endgame(tcp->loop, (async_handle_t*)tcp);
    }
}


int async_tcp_open(async_tcp_t* handle, async_os_sock_t sock)
{
    WSAPROTOCOL_INFOW protocol_info;
    int opt_len;
    int err;

    /* Detect the address family of the socket. */
    opt_len = (int) sizeof protocol_info;
    if (fn_getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*) &protocol_info, &opt_len) == SOCKET_ERROR) {
        return async_translate_sys_error(fn_GetLastError());
    }

    /* Make the socket non-inheritable */
    if (!fn_SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0)) {
        return async_translate_sys_error(fn_GetLastError());
    }

    err = async_tcp_set_socket(handle->loop, handle, sock, protocol_info.iAddressFamily, 1);
    if (err) {
        return async_translate_sys_error(err);
    }

    return 0;
}

/* This function is an egress point, i.e. it returns libuv errors rather than
 * system errors.
 */
int async__tcp_bind(async_tcp_t* handle, const struct sockaddr* addr, uint32_t addrlen, uint32_t flags)
{
    int err;

    err = async_tcp_try_bind(handle, addr, addrlen, flags);
    if (err) {
        return async_translate_sys_error(err);
    }

    return 0;
}

/* This function is an egress point, i.e. it returns libuv errors rather than
 * system errors.
 */
int async__tcp_connect(async_connect_t* req, async_tcp_t* handle, const struct sockaddr* addr, uint32_t addrlen, async_connect_cb cb)
{
    int err;

    err = async_tcp_try_connect(req, handle, addr, addrlen, cb);
    if (err) {
        return async_translate_sys_error(err);
    }

    return 0;
}
