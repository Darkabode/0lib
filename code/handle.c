#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"

int async_is_active(const async_handle_t* handle)
{
    return (handle->flags & ASYNC__HANDLE_ACTIVE) && !(handle->flags & ASYNC__HANDLE_CLOSING);
}

void async_close(async_handle_t* handle, async_close_cb cb)
{
    async_loop_t* loop = handle->loop;

    if (handle->flags & ASYNC__HANDLE_CLOSING) {
        return;
    }

    handle->close_cb = cb;

    /* Handle-specific close actions */
    switch (handle->type) {
        case ASYNC_TCP:
            async_tcp_close(loop, (async_tcp_t*)handle);
            return;

        case ASYNC_NAMED_PIPE:
            async_pipe_close(loop, (async_pipe_t*) handle);
            return;

        case ASYNC_UDP:
            async_udp_close(loop, (async_udp_t*) handle);
            return;

        case ASYNC_POLL:
            async_poll_close(loop, (async_poll_t*) handle);
            return;

        case ASYNC_TIMER:
            async_timer_stop((async_timer_t*)handle);
            async__handle_closing(handle);
            async_want_endgame(loop, handle);
            return;

        case ASYNC_PREPARE:
            async_prepare_stop((async_prepare_t*)handle);
            async__handle_closing(handle);
            async_want_endgame(loop, handle);
            return;

        case ASYNC_CHECK:
            async_check_stop((async_check_t*)handle);
            async__handle_closing(handle);
            async_want_endgame(loop, handle);
            return;

        case ASYNC_IDLE:
            async_idle_stop((async_idle_t*)handle);
            async__handle_closing(handle);
            async_want_endgame(loop, handle);
            return;

        case ASYNC_ASYNC:
            async_async_close(loop, (async_async_t*) handle);
            return;

        case ASYNC_FS_EVENT:
            async_fs_event_close(loop, (async_fs_event_t*) handle);
            return;

        case ASYNC_FS_POLL:
            async__fs_poll_close((async_fs_poll_t*) handle);
            async__handle_closing(handle);
            async_want_endgame(loop, handle);
            return;
    }
}


int async_is_closing(const async_handle_t* handle)
{
    return !!(handle->flags & (ASYNC__HANDLE_CLOSING | ASYNC_HANDLE_CLOSED));
}

void async_want_endgame(async_loop_t* loop, async_handle_t* handle)
{
    if (!(handle->flags & ASYNC_HANDLE_ENDGAME_QUEUED)) {
        handle->flags |= ASYNC_HANDLE_ENDGAME_QUEUED;

        handle->endgame_next = loop->endgame_handles;
        loop->endgame_handles = handle;
    }
}

void async_process_endgames(async_loop_t* loop)
{
    async_handle_t* handle;

    while (loop->endgame_handles) {
        handle = loop->endgame_handles;
        loop->endgame_handles = handle->endgame_next;

        handle->flags &= ~ASYNC_HANDLE_ENDGAME_QUEUED;

        switch (handle->type) {
        case ASYNC_TCP:
            async_tcp_endgame(loop, (async_tcp_t*)handle);
            break;
        case ASYNC_NAMED_PIPE:
            async_pipe_endgame(loop, (async_pipe_t*)handle);
            break;
        case ASYNC_UDP:
            async_udp_endgame(loop, (async_udp_t*)handle);
            break;
        case ASYNC_POLL:
            async_poll_endgame(loop, (async_poll_t*)handle);
            break;
        case ASYNC_TIMER:
            async_timer_endgame(loop, (async_timer_t*)handle);
            break;
        case ASYNC_PREPARE:
        case ASYNC_CHECK:
        case ASYNC_IDLE:
            async_loop_watcher_endgame(loop, handle);
            break;
        case ASYNC_ASYNC:
            async_async_endgame(loop, (async_async_t*)handle);
            break;
        case ASYNC_FS_EVENT:
            async_fs_event_endgame(loop, (async_fs_event_t*)handle);
            break;
        case ASYNC_FS_POLL:
            async__fs_poll_endgame(loop, (async_fs_poll_t*)handle);
            break;
        default:
            break;
        }
    }
}
