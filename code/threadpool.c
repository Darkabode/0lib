#include "zmodule.h"
#include "uv-common.h"

#include "req-inl.h"

async_once_t once = ASYNC_ONCE_INIT;
async_cond_t cond = { 0 };
mutex_t mutex = { 0 };
uint32_t nthreads = 0;
async_thread_t _threads[4] = { 0 };
QUEUE exit_message = { 0 };
QUEUE wq = {0};
volatile int initialized = 0;


void async__cancelled(struct async__work* w)
{

    //abort();
}

/* To avoid deadlock with async_cancel() it's crucial that the worker
 * never holds the global mutex and the loop-local mutex at the same time.
 */
void worker(void* arg)
{
    struct async__work* w;
    QUEUE* q;

    (void) arg;

    for (;;) {
        mutex_lock(&mutex);

        while (queue_empty(&wq)) {
            async_cond_wait(&cond, &mutex);
        }

        q = queue_head(&wq);

        if (q == &exit_message) {
            async_cond_signal(&cond);
        }
        else {
            queue_remove(q);
            queue_init(q); // Signal async_cancel() that the work req is executing.
        }

        mutex_unlock(&mutex);

        if (q == &exit_message) {
            break;
        }

        w = QUEUE_DATA(q, struct async__work, wq);
        w->work(w);

        mutex_lock(&w->loop->wq_mutex);
        w->work = NULL;  // Signal async_cancel() that the work req is done executing.
        queue_insert_tail(&w->loop->wq, &w->wq);
        async_async_send(&w->loop->wq_async);
        mutex_unlock(&w->loop->wq_mutex);
    }
}

void post(QUEUE* q)
{
    mutex_lock(&mutex);
    queue_insert_tail(&wq, q);
    async_cond_signal(&cond);
    mutex_unlock(&mutex);
}

#ifndef _WIN32
UV_DESTRUCTOR(static void cleanup(void)) {
void __stdcall cleanup(void)
{
    uint32_t i;

    if (initialized == 0) {
        return;
    }

    post(&exit_message);

    for (i = 0; i < nthreads; ++i) {
        if (async_thread_join(&_threads[i])) {
            LOG(__FUNCTION__": async_thread_join faled");
        }
    }

    mutex_destroy(&mutex);
    async_cond_destroy(&cond);

    nthreads = 0;
    initialized = 0;
}
#endif

void init_once(void)
{
    uint32_t i;
    const char* val;

    nthreads = ARRAY_SIZE(_threads);

    async_cond_init(&cond);
    mutex_init(&mutex);
    queue_init(&wq);

    for (i = 0; i < nthreads; ++i) {
        if (async_thread_create(&_threads[i], worker, NULL)) {
            LOG(__FUNCTION__": async_thread_create failed");
        }
    }
    initialized = 1;
    //runtime_atexit(cleanup);
}

void async__work_submit(async_loop_t* loop, struct async__work* w, void (*work)(struct async__work* w), void (*done)(struct async__work* w, int status))
{
    async_once(&once, init_once);
    w->loop = loop;
    w->work = work;
    w->done = done;
    post(&w->wq);
}

int async__work_cancel(async_loop_t* loop, async_req_t* req, struct async__work* w)
{
    int cancelled;

    mutex_lock(&mutex);
    mutex_lock(&w->loop->wq_mutex);

    cancelled = !queue_empty(&w->wq) && w->work != NULL;
    if (cancelled) {
        queue_remove(&w->wq);
    }

    mutex_unlock(&w->loop->wq_mutex);
    mutex_unlock(&mutex);

    if (!cancelled) {
        return ASYNC_EBUSY;
    }

    w->work = async__cancelled;
    mutex_lock(&loop->wq_mutex);
    queue_insert_tail(&loop->wq, &w->wq);
    async_async_send(&loop->wq_async);
    mutex_unlock(&loop->wq_mutex);

    return 0;
}

void async__work_done(async_async_t* handle)
{
    struct async__work* w;
    async_loop_t* loop;
    QUEUE* q;
    QUEUE wq;
    int err;

    loop = container_of(handle, async_loop_t, wq_async);
    queue_init(&wq);

    mutex_lock(&loop->wq_mutex);
    if (!queue_empty(&loop->wq)) {
        q = queue_head(&loop->wq);
        queue_split(&loop->wq, q, &wq);
    }
    mutex_unlock(&loop->wq_mutex);

    while (!queue_empty(&wq)) {
        q = queue_head(&wq);
        queue_remove(q);

        w = container_of(q, struct async__work, wq);
        err = (w->work == async__cancelled) ? ASYNC_ECANCELED : 0;
        w->done(w, err);
    }
}

void async__queue_work(struct async__work* w)
{
    async_work_t* req = container_of(w, async_work_t, work_req);

    req->work_cb(req);
}

void async__queue_done(struct async__work* w, int err)
{
    async_work_t* req;

    req = container_of(w, async_work_t, work_req);
    async__req_unregister(req->loop, req);

    if (req->after_work_cb == NULL) {
        return;
    }

    req->after_work_cb(req, err);
}

int async_queue_work(async_loop_t* loop, async_work_t* req, async_work_cb work_cb, async_after_work_cb after_work_cb)
{
    if (work_cb == NULL) {
        return ASYNC_EINVAL;
    }

    async_req_init(loop, req);
    req->type = ASYNC_WORK;
    async__req_register(loop, req);

    req->loop = loop;
    req->work_cb = work_cb;
    req->after_work_cb = after_work_cb;
    async__work_submit(loop, &req->work_req, async__queue_work, async__queue_done);
    return 0;
}

int async_cancel(async_req_t* req)
{
    struct async__work* wreq;
    async_loop_t* loop;

    switch (req->type) {
        case ASYNC_FS:
            loop =  ((async_fs_t*) req)->loop;
            wreq = &((async_fs_t*) req)->work_req;
            break;
        case ASYNC_GETADDRINFO:
            loop =  ((async_getaddrinfo_t*) req)->loop;
            wreq = &((async_getaddrinfo_t*) req)->work_req;
            break;
        case ASYNC_GETNAMEINFO:
            loop = ((async_getnameinfo_t*) req)->loop;
            wreq = &((async_getnameinfo_t*) req)->work_req;
            break;
        case ASYNC_WORK:
            loop =  ((async_work_t*) req)->loop;
            wreq = &((async_work_t*) req)->work_req;
            break;
        default:
            return ASYNC_EINVAL;
    }
    return async__work_cancel(loop, req, wreq);
}
