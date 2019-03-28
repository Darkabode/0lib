#include "zmodule.h"
#include "async.h"
#include "uv-common.h"

struct poll_ctx {
    async_fs_poll_t* parent_handle; /* NULL if parent has been stopped or closed */
    int busy_polling;
    uint32_t interval;
    uint64_t start_time;
    async_loop_t* loop;
    async_fs_poll_cb poll_cb;
    async_timer_t timer_handle;
    async_fs_t fs_req; /* TODO(bnoordhuis) mark fs_req internal */
    async_stat_t statbuf;
    wchar_t path[1]; /* variable length */
};

static int statbuf_eq(const async_stat_t* a, const async_stat_t* b);
static void poll_cb(async_fs_t* req);
static void timer_cb(async_timer_t* timer);
static void timer_close_cb(async_handle_t* handle);

static async_stat_t zero_statbuf;

int async_fs_poll_init(async_loop_t* loop, async_fs_poll_t* handle)
{
    async__handle_init(loop, (async_handle_t*)handle, ASYNC_FS_POLL);
    return 0;
}


int async_fs_poll_start(async_fs_poll_t* handle, async_fs_poll_cb cb, const wchar_t* path, uint32_t interval)
{
    struct poll_ctx* ctx;
    async_loop_t* loop;
    size_t len;
    int err;

    if (async__is_active(handle)) {
        return 0;
    }

    loop = handle->loop;
    len = fn_lstrlenW(path);
    ctx = memory_alloc(sizeof(*ctx) + (len * sizeof(wchar_t)));

    ctx->loop = loop;
    ctx->poll_cb = cb;
    ctx->interval = interval ? interval : 1;
    ctx->start_time = async_now(loop);
    ctx->parent_handle = handle;
    fn_lstrcpyW(ctx->path, path);

    async_timer_init(loop, &ctx->timer_handle);

    ctx->timer_handle.flags |= ASYNC__HANDLE_INTERNAL;
    async__handle_unref(&ctx->timer_handle);

    err = async_fs_stat(loop, &ctx->fs_req, ctx->path, poll_cb);
    if (err < 0) {
        goto error;
    }

    handle->poll_ctx = ctx;
    async__handle_start(handle);

    return 0;

error:
    memory_free(ctx);
    return err;
}


int async_fs_poll_stop(async_fs_poll_t* handle)
{
    struct poll_ctx* ctx;

    if (!async__is_active(handle)) {
        return 0;
    }

    ctx = handle->poll_ctx;
    ctx->parent_handle = NULL;
    handle->poll_ctx = NULL;

      /* Close the timer if it's active. If it's inactive, there's a stat request
       * in progress and poll_cb will take care of the cleanup.
       */
    if (async__is_active(&ctx->timer_handle)) {
        async_close((async_handle_t*)&ctx->timer_handle, timer_close_cb);
    }

    async__handle_stop(handle);

    return 0;
}

int async_fs_poll_getpath(async_fs_poll_t* handle, wchar_t* buf, size_t* len)
{
    struct poll_ctx* ctx;
    size_t required_len;

    if (!async__is_active(handle)) {
        *len = 0;
        return ASYNC_EINVAL;
    }

    ctx = handle->poll_ctx;

    required_len = fn_lstrlenW(ctx->path) + 1;
    if (required_len > *len) {
        *len = required_len;
        return ASYNC_ENOBUFS;
    }

    fn_lstrcpyW(buf, ctx->path);
    *len = required_len;

    return 0;
}

void async__fs_poll_close(async_fs_poll_t* handle)
{
    async_fs_poll_stop(handle);
}

static void timer_cb(async_timer_t* timer)
{
    struct poll_ctx* ctx;

    ctx = container_of(timer, struct poll_ctx, timer_handle);
    ctx->start_time = async_now(ctx->loop);

    if (async_fs_stat(ctx->loop, &ctx->fs_req, ctx->path, poll_cb)) {
        LOG(__FUNCTION__": async_fs_stat failed");
    }
}


static void poll_cb(async_fs_t* req)
{
    async_stat_t* statbuf;
    struct poll_ctx* ctx;
    uint64_t interval;

    ctx = container_of(req, struct poll_ctx, fs_req);

    if (ctx->parent_handle == NULL) { /* handle has been stopped or closed */
        async_close((async_handle_t*)&ctx->timer_handle, timer_close_cb);
        async_fs_req_cleanup(req);
        return;
    }

    if (req->result != 0) {
        if (ctx->busy_polling != req->result) {
            ctx->poll_cb(ctx->parent_handle, req->result, &ctx->statbuf, &zero_statbuf);
            ctx->busy_polling = req->result;
        }
        goto out;
    }

    statbuf = &req->statbuf;

    if (ctx->busy_polling != 0) {
        if (ctx->busy_polling < 0 || !statbuf_eq(&ctx->statbuf, statbuf)) {
            ctx->poll_cb(ctx->parent_handle, 0, &ctx->statbuf, statbuf);
        }
    }

    ctx->statbuf = *statbuf;
    ctx->busy_polling = 1;

out:
    async_fs_req_cleanup(req);

    if (ctx->parent_handle == NULL) { /* handle has been stopped by callback */
        async_close((async_handle_t*)&ctx->timer_handle, timer_close_cb);
        return;
    }

    /* Reschedule timer, subtract the delay from doing the stat(). */
    interval = ctx->interval;
    interval -= (async_now(ctx->loop) - ctx->start_time) % interval;

    async_timer_start(&ctx->timer_handle, timer_cb, interval, 0);
}

static void timer_close_cb(async_handle_t* handle)
{
    memory_free(container_of(handle, struct poll_ctx, timer_handle));
}


static int statbuf_eq(const async_stat_t* a, const async_stat_t* b)
{
  return a->st_ctim.tv_nsec == b->st_ctim.tv_nsec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_birthtim.tv_nsec == b->st_birthtim.tv_nsec &&
      a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_birthtim.tv_sec == b->st_birthtim.tv_sec && a->st_size == b->st_size &&
      a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_ino == b->st_ino && a->st_dev == b->st_dev && a->st_flags == b->st_flags && a->st_gen == b->st_gen;
}


#include "internal.h"
#include "handle-inl.h"

void async__fs_poll_endgame(async_loop_t* loop, async_fs_poll_t* handle)
{
    async__handle_close(handle);
}
