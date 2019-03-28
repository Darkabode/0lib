#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

int async_listen(async_stream_t* stream, int backlog, async_connection_cb cb)
{
    int err;

    err = ERROR_INVALID_PARAMETER;
    switch (stream->type) {
        case ASYNC_TCP:
            err = async_tcp_listen((async_tcp_t*)stream, backlog, cb);
            break;
        case ASYNC_NAMED_PIPE:
            err = async_pipe_listen((async_pipe_t*)stream, backlog, cb);
            break;
    }

    return async_translate_sys_error(err);
}

int async_accept(async_stream_t* server, async_stream_t* client)
{
    int err;

    err = ERROR_INVALID_PARAMETER;
    switch (server->type) {
        case ASYNC_TCP:
            err = async_tcp_accept((async_tcp_t*)server, (async_tcp_t*)client);
            break;
        case ASYNC_NAMED_PIPE:
            err = async_pipe_accept((async_pipe_t*)server, client);
            break;
    }

    return async_translate_sys_error(err);
}

int async_read_start(async_stream_t* handle, async_alloc_cb alloc_cb, async_read_cb read_cb)
{
    int err;

    if (handle->flags & ASYNC_HANDLE_READING) {
        return ASYNC_EALREADY;
    }

    if (!(handle->flags & ASYNC_HANDLE_READABLE)) {
        return ASYNC_ENOTCONN;
    }

    err = ERROR_INVALID_PARAMETER;
    switch (handle->type) {
        case ASYNC_TCP:
            err = async_tcp_read_start((async_tcp_t*)handle, alloc_cb, read_cb);
            break;
        case ASYNC_NAMED_PIPE:
            err = async_pipe_read_start((async_pipe_t*)handle, alloc_cb, read_cb);
            break;
    }

    return async_translate_sys_error(err);
}

int async_read_stop(async_stream_t* handle)
{
    int err;

    if (!(handle->flags & ASYNC_HANDLE_READING)) {
        return 0;
    }

    err = 0;
    if (handle->type == ASYNC_NAMED_PIPE) {
        async__pipe_stop_read((async_pipe_t*)handle);
    }
    else {
        handle->flags &= ~ASYNC_HANDLE_READING;
    }
    DECREASE_ACTIVE_COUNT(handle->loop, handle);

    return async_translate_sys_error(err);
}

int async_write(async_write_t* req, async_stream_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb)
{
    async_loop_t* loop = handle->loop;
    int err;

    if (!(handle->flags & ASYNC_HANDLE_WRITABLE)) {
        return ASYNC_EPIPE;
    }

    err = ERROR_INVALID_PARAMETER;
    switch (handle->type) {
        case ASYNC_TCP:
            err = async_tcp_write(loop, req, (async_tcp_t*) handle, bufs, nbufs, cb);
            break;
        case ASYNC_NAMED_PIPE:
            err = async_pipe_write(loop, req, (async_pipe_t*) handle, bufs, nbufs, cb);
            break;
    }

    return async_translate_sys_error(err);
}

int async_write2(async_write_t* req, async_stream_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_stream_t* send_handle, async_write_cb cb)
{
    async_loop_t* loop = handle->loop;
    int err;

    if (!(handle->flags & ASYNC_HANDLE_WRITABLE)) {
        return ASYNC_EPIPE;
    }

    err = ERROR_INVALID_PARAMETER;
    switch (handle->type) {
        case ASYNC_NAMED_PIPE:
            err = async_pipe_write2(loop, req, (async_pipe_t*) handle, bufs, nbufs, send_handle, cb);
            break;
    }

    return async_translate_sys_error(err);
}

int async_try_write(async_stream_t* stream, const async_buf_t bufs[], uint32_t nbufs)
{
    /* NOTE: Won't work with overlapped writes */
    return ASYNC_ENOSYS;
}

int async_shutdown(async_shutdown_t* req, async_stream_t* handle, async_shutdown_cb cb)
{
    async_loop_t* loop = handle->loop;

    if (!(handle->flags & ASYNC_HANDLE_WRITABLE)) {
        return ASYNC_EPIPE;
    }

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_SHUTDOWN;
    req->handle = handle;
    req->cb = cb;

    handle->flags &= ~ASYNC_HANDLE_WRITABLE;
    handle->shutdown_req = req;
    handle->reqs_pending++;
    REGISTER_HANDLE_REQ(loop, handle, req);

    async_want_endgame(loop, (async_handle_t*)handle);

    return 0;
}

int async_is_readable(const async_stream_t* handle)
{
    return !!(handle->flags & ASYNC_HANDLE_READABLE);
}

int async_is_writable(const async_stream_t* handle)
{
    return !!(handle->flags & ASYNC_HANDLE_WRITABLE);
}

int async_stream_set_blocking(async_stream_t* handle, int blocking)
{
    if (handle->type != ASYNC_NAMED_PIPE) {
        return ASYNC_EINVAL;
    }

    if (blocking != 0) {
        handle->flags |= ASYNC_HANDLE_BLOCKING_WRITES;
    }
    else {
        handle->flags &= ~ASYNC_HANDLE_BLOCKING_WRITES;
    }

    return 0;
}

void async_stream_init(async_loop_t* loop, async_stream_t* handle, async_handle_type type)
{
    async__handle_init(loop, (async_handle_t*)handle, type);
    handle->write_queue_size = 0;
    handle->activecnt = 0;
}

void async_connection_init(async_stream_t* handle)
{
    handle->flags |= ASYNC_HANDLE_CONNECTION;
    handle->write_reqs_pending = 0;

    async_req_init(handle->loop, (async_req_t*)&(handle->read_req));
    handle->read_req.event_handle = NULL;
    handle->read_req.wait_handle = INVALID_HANDLE_VALUE;
    handle->read_req.type = ASYNC_READ;
    handle->read_req.data = handle;

    handle->shutdown_req = NULL;
}
