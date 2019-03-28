#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

void async_async_endgame(async_loop_t* loop, async_async_t* handle)
{
    if (handle->flags & ASYNC__HANDLE_CLOSING && !handle->async_sent) {
        async__handle_close(handle);
    }
}

void async_async_init(async_loop_t* loop, async_async_t* handle, async_async_cb async_cb)
{
    async_req_t* req;

    async__handle_init(loop, (async_handle_t*) handle, ASYNC_ASYNC);
    handle->async_sent = 0;
    handle->async_cb = async_cb;

    req = &handle->async_req;
    async_req_init(loop, req);
    req->type = ASYNC_WAKEUP;
    req->data = handle;

    async__handle_start(handle);

    return 0;
}

void async_async_close(async_loop_t* loop, async_async_t* handle)
{
    if (!((async_async_t*)handle)->async_sent) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }

    async__handle_closing(handle);
}

int async_async_send(async_async_t* handle)
{
    async_loop_t* loop = handle->loop;

    if (handle->type != ASYNC_ASYNC) {
        /* Can't set errno because that's not thread-safe. */
        return -1;
    }

    /* The user should make sure never to call async_async_send to a closing */
    /* or closed handle. */

    if (!_InterlockedOr8(&handle->async_sent, 1)) {
        POST_COMPLETION_FOR_REQ(loop, &handle->async_req);
    }

    return 0;
}

void async_process_async_wakeup_req(async_loop_t* loop, async_async_t* handle, async_req_t* req)
{
    handle->async_sent = 0;

    if (handle->flags & ASYNC__HANDLE_CLOSING) {
        async_want_endgame(loop, (async_handle_t*)handle);
    }
    else if (handle->async_cb != NULL) {
        handle->async_cb(handle);
    }
}
