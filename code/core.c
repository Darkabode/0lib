#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

async_loop_t _defaultLoop;
async_once_t _defaultLoopInitGuard = ASYNC_ONCE_INIT;

void async_loop_init(void)
{
    /* Initialize libuv itself first */
    /* Tell Windows that we will handle critical errors. */
    fn_SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    /* Initialize winsock */
    async_winsock_init();

    /* Initialize utilities */
    async__util_init(); 
    
    /* Create an I/O completion port */
    _defaultLoop.iocp = fn_CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (_defaultLoop.iocp == NULL) {
        //LOG();
        return;
    }

    /* To prevent uninitialized memory access, loop->time must be intialized */
    /* to zero before calling async_update_time for the first time. */
    _defaultLoop.time = 0;
    _defaultLoop.last_tick_count = 0;
    async_update_time(&_defaultLoop);

    queue_init(&_defaultLoop.wq);
    queue_init(&_defaultLoop.handle_queue);
    queue_init(&_defaultLoop.active_reqs);
    _defaultLoop.active_handles = 0;

    _defaultLoop.pending_reqs_tail = NULL;

    _defaultLoop.endgame_handles = NULL;

    RB_INIT(&_defaultLoop.timers);

    _defaultLoop.check_handles = NULL;
    _defaultLoop.prepare_handles = NULL;
    _defaultLoop.idle_handles = NULL;

    _defaultLoop.next_prepare_handle = NULL;
    _defaultLoop.next_check_handle = NULL;
    _defaultLoop.next_idle_handle = NULL;

    __stosb((uint8_t*)&_defaultLoop.poll_peer_sockets, 0, sizeof _defaultLoop.poll_peer_sockets);

    _defaultLoop.active_tcp_streams = 0;
    _defaultLoop.active_udp_streams = 0;

    _defaultLoop.timer_counter = 0;
    _defaultLoop.stop_flag = 0;

    mutex_init(&_defaultLoop.wq_mutex);

    async_async_init(&_defaultLoop, &_defaultLoop.wq_async, async__work_done);

    async__handle_unref(&_defaultLoop.wq_async);
    _defaultLoop.wq_async.flags |= ASYNC__HANDLE_INTERNAL;
}

async_loop_t* async_default_loop(void)
{
    async_once(&_defaultLoopInitGuard, async_loop_init);
    return &_defaultLoop;
}

static void async__loop_close(async_loop_t* loop)
{
    /* close the async handle without needeing an extra loop iteration */
    loop->wq_async.close_cb = NULL;
    async__handle_closing(&loop->wq_async);
    async__handle_close(&loop->wq_async);

    if (loop != &_defaultLoop) {
        size_t i;
        for (i = 0; i < ARRAY_SIZE(loop->poll_peer_sockets); i++) {
            SOCKET sock = loop->poll_peer_sockets[i];
            if (sock != 0 && sock != INVALID_SOCKET)
                fn_closesocket(sock);
        }
    }
    /* TODO: cleanup default loop*/

    mutex_lock(&loop->wq_mutex);
    mutex_unlock(&loop->wq_mutex);
    mutex_destroy(&loop->wq_mutex);
}

int async_loop_close(async_loop_t* loop)
{
    QUEUE* q;
    async_handle_t* h;
    if (!queue_empty(&(loop)->active_reqs)) {
        return ASYNC_EBUSY;
    }
    QUEUE_FOREACH(q, &loop->handle_queue) {
        h = QUEUE_DATA(q, async_handle_t, handle_queue);
        if (!(h->flags & ASYNC__HANDLE_INTERNAL)) {
            return ASYNC_EBUSY;
        }
    }
    
    async__loop_close(loop);
    return 0;
}

int async_backend_timeout(const async_loop_t* loop)
{
    if (loop->stop_flag != 0)
        return 0;

    if (!async__has_active_handles(loop) && !async__has_active_reqs(loop))
        return 0;

    if (loop->pending_reqs_tail)
        return 0;

    if (loop->endgame_handles)
        return 0;

    if (loop->idle_handles)
        return 0;

    return async__next_timeout(loop);
}

int async_poll(async_loop_t* loop, DWORD timeout)
{
    DWORD bytes;
    ULONG_PTR key;
    OVERLAPPED* overlapped;
    async_req_t* req;

    fn_GetQueuedCompletionStatus(loop->iocp, &bytes, &key, &overlapped, timeout);

    if (overlapped) {
        /* Package was dequeued */
        req = async_overlapped_to_req(overlapped);
        async_insert_pending_req(loop, req);
    }
    else if (fn_GetLastError() != WAIT_TIMEOUT) {
        return -1;
    }
    else {
        /* We're sure that at least `timeout` milliseconds have expired, but */
        /* this may not be reflected yet in the GetTickCount() return value. */
        /* Therefore we ensure it's taken into account here. */
        async__time_forward(loop, timeout);
    }

    return 0;
}

int async_poll_ex(async_loop_t* loop, DWORD timeout)
{
    BOOL success;
    async_req_t* req;
    OVERLAPPED_ENTRY overlappeds[128];
    ULONG count;
    ULONG i;

    success = fn_GetQueuedCompletionStatusEx(loop->iocp, overlappeds, ARRAY_SIZE(overlappeds), &count, timeout, FALSE);

    if (success) {
        for (i = 0; i < count; i++) {
            /* Package was dequeued */
            req = async_overlapped_to_req(overlappeds[i].lpOverlapped);
            async_insert_pending_req(loop, req);
        }
    }
    else if (fn_GetLastError() != WAIT_TIMEOUT) {
        /* Serious error */
        return -1;
    }
    else if (timeout > 0) {
        /* We're sure that at least `timeout` milliseconds have expired, but */
        /* this may not be reflected yet in the GetTickCount() return value. */
        /* Therefore we ensure it's taken into account here. */
        async__time_forward(loop, timeout);
    }

    return 0;
}

static int async__loop_alive(const async_loop_t* loop)
{
    return loop->active_handles > 0 || !queue_empty(&loop->active_reqs) || loop->endgame_handles != NULL;
}

int async_loop_alive(const async_loop_t* loop)
{
    return async__loop_alive(loop);
}

int async_run(async_loop_t *loop, async_run_mode mode)
{
    DWORD timeout;
    int r;
    int(*poll)(async_loop_t* loop, DWORD timeout);

    if (fn_GetQueuedCompletionStatusEx != NULL) {
        poll = &async_poll_ex;
    }
    else {
        poll = &async_poll;
    }

    r = async__loop_alive(loop);
    if (!r) {
        async_update_time(loop);
    }

    while (r != 0 && loop->stop_flag == 0) {
        async_update_time(loop);
        async_process_timers(loop);

        async_process_reqs(loop);
        async_idle_invoke(loop);
        async_prepare_invoke(loop);

        timeout = 0;
        if ((mode & ASYNC_RUN_NOWAIT) == 0) {
            timeout = async_backend_timeout(loop);
        }

        r = (*poll)(loop, timeout);
        if (r != 0) {
            break;
        }

        async_check_invoke(loop);
        async_process_endgames(loop);

        if (mode == ASYNC_RUN_ONCE) {
          /* ASYNC_RUN_ONCE implies forward progess: at least one callback must have
           * been invoked when it returns. async__io_poll() can return without doing
           * I/O (meaning: no callbacks) when its timeout expires - which means we
           * have pending timers that satisfy the forward progress constraint.
           *
           * ASYNC_RUN_NOWAIT makes no guarantees about progress so it's omitted from
           * the check.
           */
            async_update_time(loop);
            async_process_timers(loop);
        }

        r = async__loop_alive(loop);
        if (mode & (ASYNC_RUN_ONCE | ASYNC_RUN_NOWAIT)) {
            break;
        }
    }

    /* The if statement lets the compiler compile it to a conditional store.
    * Avoids dirtying a cache line.
    */
    if (loop->stop_flag != 0) {
        loop->stop_flag = 0;
    }

    return r;
}

int async__socket_sockopt(async_handle_t* handle, int optname, int* value)
{
    int r;
    int len;
    SOCKET socket;

    if (handle == NULL || value == NULL)
        return ASYNC_EINVAL;

    if (handle->type == ASYNC_TCP)
        socket = ((async_tcp_t*)handle)->socket;
    else if (handle->type == ASYNC_UDP)
        socket = ((async_udp_t*)handle)->socket;
    else
        return ASYNC_ENOTSUP;

    len = sizeof(*value);

    if (*value == 0)
        r = fn_getsockopt(socket, SOL_SOCKET, optname, (char*)value, &len);
    else
        r = fn_setsockopt(socket, SOL_SOCKET, optname, (const char*)value, len);

    if (r == SOCKET_ERROR)
        return async_translate_sys_error(fn_WSAGetLastError());

    return 0;
}
