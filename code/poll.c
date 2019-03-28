#include "zmodule.h"
#include <stdint.h>

#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"


static const GUID async_msafd_provider_ids[ASYNC_MSAFD_PROVIDER_COUNT] = {
    {0xe70f1aa0, 0xab8b, 0x11cf, {0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}},
    {0xf9eab0c0, 0x26d4, 0x11d0, {0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4}},
    {0x9fc48064, 0x7298, 0x43e4, {0xb7, 0xbd, 0x18, 0x1f, 0x20, 0x89, 0x79, 0x2a}}
};

typedef struct async_single_fd_set_s {
    uint32_t fd_count;
    SOCKET fd_array[1];
} async_single_fd_set_t;


static OVERLAPPED overlapped_dummy_;
static async_once_t overlapped_dummy_init_guard_ = ASYNC_ONCE_INIT;

void async__init_overlapped_dummy(void)
{
    HANDLE event;

    event = fn_CreateEventW(NULL, TRUE, TRUE, NULL);
    if (event != NULL) {
        __stosb((uint8_t*)&overlapped_dummy_, 0, sizeof overlapped_dummy_);
        overlapped_dummy_.hEvent = (HANDLE)((uintptr_t)event | 1);
    }
}

static OVERLAPPED* async__get_overlapped_dummy()
{
    async_once(&overlapped_dummy_init_guard_, async__init_overlapped_dummy);
    return &overlapped_dummy_;
}

static void async__fast_poll_submit_poll_req(async_loop_t* loop, async_poll_t* handle)
{
    async_req_t* req;
    AFD_POLL_INFO* afd_poll_info;
    DWORD result;

    /* Find a yet unsubmitted req to submit. */
    if (handle->submitted_events_1 == 0) {
        req = &handle->poll_req_1;
        afd_poll_info = &handle->afd_poll_info_1;
        handle->submitted_events_1 = handle->events;
        handle->mask_events_1 = 0;
        handle->mask_events_2 = handle->events;
    }
    else if (handle->submitted_events_2 == 0) {
        req = &handle->poll_req_2;
        afd_poll_info = &handle->afd_poll_info_2;
        handle->submitted_events_2 = handle->events;
        handle->mask_events_1 = handle->events;
        handle->mask_events_2 = 0;
    }
    else {
        return;
    }

    // Setting Exclusive to TRUE makes the other poll request return if there is any.
    afd_poll_info->Exclusive = TRUE;
    afd_poll_info->NumberOfHandles = 1;
    afd_poll_info->Timeout.QuadPart = INT64_MAX;
    afd_poll_info->Handles[0].Handle = (HANDLE) handle->socket;
    afd_poll_info->Handles[0].Status = 0;
    afd_poll_info->Handles[0].Events = 0;

    if (handle->events & ASYNC_READABLE) {
        afd_poll_info->Handles[0].Events |= AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT | AFD_POLL_ABORT;
    }
    if (handle->events & ASYNC_WRITABLE) {
        afd_poll_info->Handles[0].Events |= AFD_POLL_SEND | AFD_POLL_CONNECT_FAIL;
    }

    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    result = async_msafd_poll((SOCKET) handle->peer_socket, afd_poll_info, &req->overlapped);
    if (result != 0 && fn_WSAGetLastError() != WSA_IO_PENDING) {
        /* Queue this req, reporting an error. */
        SET_REQ_ERROR(req, fn_WSAGetLastError());
        async_insert_pending_req(loop, req);
    }
}

static int async__fast_poll_cancel_poll_req(async_loop_t* loop, async_poll_t* handle)
{
    AFD_POLL_INFO afd_poll_info;
    int result;

    afd_poll_info.Exclusive = TRUE;
    afd_poll_info.NumberOfHandles = 1;
    afd_poll_info.Timeout.QuadPart = INT64_MAX;
    afd_poll_info.Handles[0].Handle = (HANDLE) handle->socket;
    afd_poll_info.Handles[0].Status = 0;
    afd_poll_info.Handles[0].Events = AFD_POLL_ALL;

    result = async_msafd_poll(handle->socket, &afd_poll_info, async__get_overlapped_dummy());

    if (result == SOCKET_ERROR) {
        DWORD error = fn_WSAGetLastError();
        if (error != WSA_IO_PENDING) {
            return fn_WSAGetLastError();
        }
    }

    return 0;
}


static void async__fast_poll_process_poll_req(async_loop_t* loop, async_poll_t* handle, async_req_t* req)
{
    uint8_t mask_events;
    AFD_POLL_INFO* afd_poll_info;

    if (req == &handle->poll_req_1) {
        afd_poll_info = &handle->afd_poll_info_1;
        handle->submitted_events_1 = 0;
        mask_events = handle->mask_events_1;
    }
    else if (req == &handle->poll_req_2) {
        afd_poll_info = &handle->afd_poll_info_2;
        handle->submitted_events_2 = 0;
        mask_events = handle->mask_events_2;
    }
    else {
        return;
    }

    /* Report an error unless the select was just interrupted. */
    if (!REQ_SUCCESS(req)) {
        DWORD error = GET_REQ_SOCK_ERROR(req);
        if (error != WSAEINTR && handle->events != 0) {
            handle->events = 0; /* Stop the watcher */
            handle->poll_cb(handle, async_translate_sys_error(error), 0);
        }
    }
    else if (afd_poll_info->NumberOfHandles >= 1) {
        uint8_t events = 0;

        if ((afd_poll_info->Handles[0].Events & (AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT | AFD_POLL_ABORT)) != 0) {
            events |= ASYNC_READABLE;
        }
        if ((afd_poll_info->Handles[0].Events & (AFD_POLL_SEND | AFD_POLL_CONNECT_FAIL)) != 0) {
            events |= ASYNC_WRITABLE;
        }

        events &= handle->events & ~mask_events;

        if (afd_poll_info->Handles[0].Events & AFD_POLL_LOCAL_CLOSE) {
            /* Stop polling. */
            handle->events = 0;
            if (async__is_active(handle)) {
                async__handle_stop(handle);
            }
        }

        if (events != 0) {
            handle->poll_cb(handle, 0, events);
        }
    }

    if ((handle->events & ~(handle->submitted_events_1 | handle->submitted_events_2)) != 0) {
        async__fast_poll_submit_poll_req(loop, handle);
    }
    else if ((handle->flags & ASYNC__HANDLE_CLOSING) && handle->submitted_events_1 == 0 && handle->submitted_events_2 == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }
}

int async__fast_poll_set(async_loop_t* loop, async_poll_t* handle, int events)
{
     handle->events = events;

    if (handle->events != 0) {
        async__handle_start(handle);
    }
    else {
        async__handle_stop(handle);
    }

    if ((handle->events & ~(handle->submitted_events_1 | handle->submitted_events_2)) != 0) {
        async__fast_poll_submit_poll_req(handle->loop, handle);
    }

    return 0;
}

int async__fast_poll_close(async_loop_t* loop, async_poll_t* handle)
{
    handle->events = 0;
    async__handle_closing(handle);

    if (handle->submitted_events_1 == 0 && handle->submitted_events_2 == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
        return 0;
    }
    else {
        /* Cancel outstanding poll requests by executing another, unique poll */
        /* request that forces the outstanding ones to return. */
        return async__fast_poll_cancel_poll_req(loop, handle);
    }
}

static SOCKET async__fast_poll_create_peer_socket(HANDLE iocp, WSAPROTOCOL_INFOW* protocol_info)
{
    SOCKET sock = 0;

    sock = fn_WSASocketW(protocol_info->iAddressFamily, protocol_info->iSocketType, protocol_info->iProtocol, protocol_info, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    if (!fn_SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, 0)) {
        goto error;
    };

    if (fn_CreateIoCompletionPort((HANDLE) sock, iocp, (ULONG_PTR) sock, 0) == NULL) {
        goto error;
    }

    return sock;

error:
    fn_closesocket(sock);
    return INVALID_SOCKET;
}


SOCKET async__fast_poll_get_peer_socket(async_loop_t* loop, WSAPROTOCOL_INFOW* protocol_info)
{
    int index, i;
    SOCKET peer_socket;

    index = -1;
    for (i = 0; (size_t)i < ARRAY_SIZE(async_msafd_provider_ids); ++i) {
        if (fn_RtlCompareMemory((void*)&protocol_info->ProviderId, (void*)&async_msafd_provider_ids[i], sizeof(protocol_info->ProviderId)) == sizeof(protocol_info->ProviderId)) {
            index = i;
        }
    }

    /* Check if the protocol uses an msafd socket. */
    if (index < 0) {
        return INVALID_SOCKET;
    }

    /* If we didn't (try) to create a peer socket yet, try to make one. Don't */
    /* try again if the peer socket creation failed earlier for the same */
    /* protocol. */
    peer_socket = loop->poll_peer_sockets[index];
    if (peer_socket == 0) {
        peer_socket = async__fast_poll_create_peer_socket(loop->iocp, protocol_info);
        loop->poll_peer_sockets[index] = peer_socket;
    }

    return peer_socket;
}


static DWORD WINAPI async__slow_poll_thread_proc(void* arg)
{
    async_req_t* req = (async_req_t*) arg;
    async_poll_t* handle = (async_poll_t*) req->data;
    uint8_t reported_events;
    int r;
    async_single_fd_set_t rfds, wfds, efds;
    struct timeval timeout;

    if (handle->events & ASYNC_READABLE) {
        rfds.fd_count = 1;
        rfds.fd_array[0] = handle->socket;
    }
    else {
        rfds.fd_count = 0;
    }

    if (handle->events & ASYNC_WRITABLE) {
        wfds.fd_count = 1;
        wfds.fd_array[0] = handle->socket;
        efds.fd_count = 1;
        efds.fd_array[0] = handle->socket;
    }
    else {
        wfds.fd_count = 0;
        efds.fd_count = 0;
    }

    /* Make the select() time out after 3 minutes. If select() hangs because */
    /* the user closed the socket, we will at least not hang indefinitely. */
    timeout.tv_sec = 3 * 60;
    timeout.tv_usec = 0;

    r = fn_select(1, (fd_set*) &rfds, (fd_set*) &wfds, (fd_set*) &efds, &timeout);
    if (r == SOCKET_ERROR) {
        /* Queue this req, reporting an error. */
        SET_REQ_ERROR(&handle->poll_req_1, fn_WSAGetLastError());
        POST_COMPLETION_FOR_REQ(handle->loop, req);
        return 0;
    }

    reported_events = 0;

    if (r > 0) {
        if (rfds.fd_count > 0) {
            reported_events |= ASYNC_READABLE;
        }

        if (wfds.fd_count > 0) {
            reported_events |= ASYNC_WRITABLE;
        }
        else if (efds.fd_count > 0) {
            reported_events |= ASYNC_WRITABLE;
        }
    }

    SET_REQ_SUCCESS(req);
    req->overlapped.InternalHigh = (DWORD) reported_events;
    POST_COMPLETION_FOR_REQ(handle->loop, req);

    return 0;
}

void async__slow_poll_submit_poll_req(async_loop_t* loop, async_poll_t* handle)
{
    async_req_t* req;

    /* Find a yet unsubmitted req to submit. */
    if (handle->submitted_events_1 == 0) {
        req = &handle->poll_req_1;
        handle->submitted_events_1 = handle->events;
        handle->mask_events_1 = 0;
        handle->mask_events_2 = handle->events;
    }
    else if (handle->submitted_events_2 == 0) {
        req = &handle->poll_req_2;
        handle->submitted_events_2 = handle->events;
        handle->mask_events_1 = handle->events;
        handle->mask_events_2 = 0;
    }
    else {
        return;
    }

    if (!fn_QueueUserWorkItem(async__slow_poll_thread_proc, (void*) req, WT_EXECUTELONGFUNCTION)) {
        /* Make this req pending, reporting an error. */
        SET_REQ_ERROR(req, fn_GetLastError());
        async_insert_pending_req(loop, req);
    }
}

void async__slow_poll_process_poll_req(async_loop_t* loop, async_poll_t* handle, async_req_t* req)
{
    uint8_t mask_events;
    int err;

    if (req == &handle->poll_req_1) {
        handle->submitted_events_1 = 0;
        mask_events = handle->mask_events_1;
    }
    else if (req == &handle->poll_req_2) {
        handle->submitted_events_2 = 0;
        mask_events = handle->mask_events_2;
    }
    else {
        return;
    }

    if (!REQ_SUCCESS(req)) {
        /* Error. */
        if (handle->events != 0) {
            err = GET_REQ_ERROR(req);
            handle->events = 0; /* Stop the watcher */
            handle->poll_cb(handle, async_translate_sys_error(err), 0);
        }
    }
    else {
        /* Got some events. */
        int events = req->overlapped.InternalHigh & handle->events & ~mask_events;
        if (events != 0) {
            handle->poll_cb(handle, 0, events);
        }
    }

    if ((handle->events & ~(handle->submitted_events_1 | handle->submitted_events_2)) != 0) {
        async__slow_poll_submit_poll_req(loop, handle);
    }
    else if ((handle->flags & ASYNC__HANDLE_CLOSING) && handle->submitted_events_1 == 0 && handle->submitted_events_2 == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }
}

int async__slow_poll_set(async_loop_t* loop, async_poll_t* handle, int events)
{
    handle->events = events;

    if (handle->events != 0) {
        async__handle_start(handle);
    }
    else {
        async__handle_stop(handle);
    }

    if ((handle->events & ~(handle->submitted_events_1 | handle->submitted_events_2)) != 0) {
        async__slow_poll_submit_poll_req(handle->loop, handle);
    }

  return 0;
}

int async__slow_poll_close(async_loop_t* loop, async_poll_t* handle)
{
    handle->events = 0;
    async__handle_closing(handle);

    if (handle->submitted_events_1 == 0 && handle->submitted_events_2 == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }

    return 0;
}

int async_poll_init(async_loop_t* loop, async_poll_t* handle, HANDLE hFile)
{
    return async_poll_init_socket(loop, handle, (SOCKET)hFile);
}

int async_poll_init_socket(async_loop_t* loop, async_poll_t* handle, async_os_sock_t socket)
{
    WSAPROTOCOL_INFOW protocol_info;
    int len;
    SOCKET peer_socket, base_socket;
    DWORD bytes;

    /* Try to obtain a base handle for the socket. This increases this chances */
    /* that we find an AFD handle and are able to use the fast poll mechanism. */
    /* This will always fail on windows XP/2k3, since they don't support the */
    /* SIO_BASE_HANDLE ioctl. */
    if (fn_WSAIoctl(socket, SIO_BASE_HANDLE, NULL, 0, &base_socket, sizeof(base_socket), &bytes, NULL, NULL) == 0) {
        socket = base_socket;
    }

    async__handle_init(loop, (async_handle_t*) handle, ASYNC_POLL);
    handle->socket = socket;
    handle->events = 0;

    /* Obtain protocol information about the socket. */
    len = sizeof protocol_info;
    if (fn_getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocol_info, &len) != 0) {
        return fn_WSAGetLastError();
    }

    /* Get the peer socket that is needed to enable fast poll. If the returned */
    /* value is NULL, the protocol is not implemented by MSAFD and we'll have */
    /* to use slow mode. */
    peer_socket = async__fast_poll_get_peer_socket(loop, &protocol_info);

    if (peer_socket != INVALID_SOCKET) {
        /* Initialize fast poll specific fields. */
        handle->peer_socket = peer_socket;
    }
    else {
        /* Initialize slow poll specific fields. */
        handle->flags |= ASYNC_HANDLE_POLL_SLOW;
    }

    /* Intialize 2 poll reqs. */
    handle->submitted_events_1 = 0;
    async_req_init(loop, (async_req_t*) &(handle->poll_req_1));
    handle->poll_req_1.type = ASYNC_POLL_REQ;
    handle->poll_req_1.data = handle;

    handle->submitted_events_2 = 0;
    async_req_init(loop, (async_req_t*) &(handle->poll_req_2));
    handle->poll_req_2.type = ASYNC_POLL_REQ;
    handle->poll_req_2.data = handle;

    return 0;
}

int async_poll_start(async_poll_t* handle, int events, async_poll_cb cb)
{
    int err;

    if (!(handle->flags & ASYNC_HANDLE_POLL_SLOW)) {
        err = async__fast_poll_set(handle->loop, handle, events);
    }
    else {
        err = async__slow_poll_set(handle->loop, handle, events);
    }

    if (err) {
        return async_translate_sys_error(err);
    }

    handle->poll_cb = cb;

    return 0;
}

int async_poll_stop(async_poll_t* handle)
{
    int err;

    if (!(handle->flags & ASYNC_HANDLE_POLL_SLOW)) {
        err = async__fast_poll_set(handle->loop, handle, 0);
    }
    else {
        err = async__slow_poll_set(handle->loop, handle, 0);
    }

    return async_translate_sys_error(err);
}

void async_process_poll_req(async_loop_t* loop, async_poll_t* handle, async_req_t* req)
{
    if (!(handle->flags & ASYNC_HANDLE_POLL_SLOW)) {
        async__fast_poll_process_poll_req(loop, handle, req);
    }
    else {
        async__slow_poll_process_poll_req(loop, handle, req);
    }
}

int async_poll_close(async_loop_t* loop, async_poll_t* handle)
{
    if (!(handle->flags & ASYNC_HANDLE_POLL_SLOW)) {
        return async__fast_poll_close(loop, handle);
    }
    else {
        return async__slow_poll_close(loop, handle);
    }
}

void async_poll_endgame(async_loop_t* loop, async_poll_t* handle)
{
    async__handle_close(handle);
}
