#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "tree.h"
#include "handle-inl.h"

void async_update_time(async_loop_t* loop)
{
    DWORD ticks;
    ULARGE_INTEGER time;

    ticks = fn_GetTickCount();

    time.QuadPart = loop->time;

    /* GetTickCount() can conceivably wrap around, so when the current tick */
    /* count is lower than the last tick count, we'll assume it has wrapped. */
    /* async_poll must make sure that the timer can never overflow more than */
    /* once between two subsequent async_update_time calls. */
    time.LowPart = ticks;
    if (ticks < loop->last_tick_count) {
        ++time.HighPart;
    }

    /* Remember the last tick count. */
    loop->last_tick_count = ticks;

    /* The GetTickCount() resolution isn't too good. Sometimes it'll happen */
    /* that GetQueuedCompletionStatus() or GetQueuedCompletionStatusEx() has */
    /* waited for a couple of ms but this is not reflected in the GetTickCount */
    /* result yet. Therefore whenever GetQueuedCompletionStatus times out */
    /* we'll add the number of ms that it has waited to the current loop time. */
    /* When that happened the loop time might be a little ms farther than what */
    /* we've just computed, and we shouldn't update the loop time. */
    if (loop->time < time.QuadPart) {
        loop->time = time.QuadPart;
    }
}

void async__time_forward(async_loop_t* loop, uint64_t msecs)
{
    loop->time += msecs;
}

static int async_timer_compare(async_timer_t* a, async_timer_t* b)
{
    if (a->due < b->due) {
        return -1;
    }
    if (a->due > b->due) {
        return 1;
    }
  /*
   *  compare start_id when both has the same due. start_id is
   *  allocated with loop->timer_counter in async_timer_start().
   */
    if (a->start_id < b->start_id) {
        return -1;
    }
    if (a->start_id > b->start_id) {
        return 1;
    }
    return 0;
}

RB_GENERATE_STATIC(async_timer_tree_s, async_timer_s, tree_entry, async_timer_compare);

void async_timer_init(async_loop_t* loop, async_timer_t* handle)
{
    async__handle_init(loop, (async_handle_t*) handle, ASYNC_TIMER);
    handle->timer_cb = NULL;
    handle->repeat = 0;
}

void async_timer_endgame(async_loop_t* loop, async_timer_t* handle)
{
    if (handle->flags & ASYNC__HANDLE_CLOSING) {
        async__handle_close(handle);
    }
}

static uint64_t get_clamped_due_time(uint64_t loop_time, uint64_t timeout)
{
    uint64_t clamped_timeout;

    clamped_timeout = loop_time + timeout;
    if (clamped_timeout < timeout) {
        clamped_timeout = (uint64_t)-1;
    }

    return clamped_timeout;
}

void async_timer_start(async_timer_t* handle, async_timer_cb timer_cb, uint64_t timeout, uint64_t repeat)
{
    async_loop_t* loop = handle->loop;
    async_timer_t* old;

    if (handle->flags & ASYNC_HANDLE_ACTIVE) {
        RB_REMOVE(async_timer_tree_s, &loop->timers, handle);
    }

    handle->timer_cb = timer_cb;
    handle->due = get_clamped_due_time(loop->time, timeout);
    handle->repeat = repeat;
    handle->flags |= ASYNC_HANDLE_ACTIVE;
    async__handle_start(handle);

    /* start_id is the second index to be compared in async__timer_cmp() */
    handle->start_id = handle->loop->timer_counter++;

    old = RB_INSERT(async_timer_tree_s, &loop->timers, handle);
}

int async_timer_stop(async_timer_t* handle)
{
    async_loop_t* loop = handle->loop;

    if (!(handle->flags & ASYNC_HANDLE_ACTIVE)) {
        return 0;
    }

    RB_REMOVE(async_timer_tree_s, &loop->timers, handle);

    handle->flags &= ~ASYNC_HANDLE_ACTIVE;
    async__handle_stop(handle);

    return 0;
}

int async_timer_again(async_timer_t* handle)
{
    async_loop_t* loop = handle->loop;

    /* If timer_cb is NULL that means that the timer was never started. */
    if (!handle->timer_cb) {
        return ASYNC_EINVAL;
    }

    if (handle->flags & ASYNC_HANDLE_ACTIVE) {
        RB_REMOVE(async_timer_tree_s, &loop->timers, handle);
        handle->flags &= ~ASYNC_HANDLE_ACTIVE;
        async__handle_stop(handle);
    }

    if (handle->repeat) {
        handle->due = get_clamped_due_time(loop->time, handle->repeat);

        if (RB_INSERT(async_timer_tree_s, &loop->timers, handle) != NULL) {
            LOG("RB_INSERT failed");
            return ASYNC_EINVAL;
        }

        handle->flags |= ASYNC_HANDLE_ACTIVE;
        async__handle_start(handle);
    }

    return 0;
}

void async_timer_set_repeat(async_timer_t* handle, uint64_t repeat)
{
    handle->repeat = repeat;
}

uint64_t async_timer_get_repeat(const async_timer_t* handle)
{
    return handle->repeat;
}

DWORD async__next_timeout(const async_loop_t* loop)
{
    async_timer_t* timer;
    int64_t delta;

    /* Check if there are any running timers
    * Need to cast away const first, since RB_MIN doesn't know what we are
    * going to do with this return value, it can't be marked const
    */
    timer = RB_MIN(async_timer_tree_s, &((async_loop_t*)loop)->timers);
    if (timer) {
        delta = timer->due - loop->time;
        if (delta >= UINT_MAX >> 1) {
            /* A timeout value of UINT_MAX means infinite, so that's no good. But */
            /* more importantly, there's always the risk that GetTickCount wraps. */
            /* async_update_time can detect this, but we must make sure that the */
            /* tick counter never overflows twice between two subsequent */
            /* async_update_time calls. We do this by never sleeping more than half */
            /* the time it takes to wrap  the counter - which is huge overkill, */
            /* but hey, it's not so bad to wake up every 25 days. */
            return UINT_MAX >> 1;
        }
        else if (delta < 0) {
            /* Negative timeout values are not allowed */
            return 0;
        }
        else {
            return (DWORD)delta;
        }
    }
    else {
        /* No timers */
        return INFINITE;
    }
}

void async_process_timers(async_loop_t* loop)
{
    async_timer_t* timer;

    /* Call timer callbacks */
    for (timer = RB_MIN(async_timer_tree_s, &loop->timers); timer != NULL && timer->due <= loop->time; timer = RB_MIN(async_timer_tree_s, &loop->timers)) {
        RB_REMOVE(async_timer_tree_s, &loop->timers, timer);

        if (timer->repeat != 0) {
            /* If it is a repeating timer, reschedule with repeat timeout. */
            timer->due = get_clamped_due_time(timer->due, timer->repeat);
            if (timer->due < loop->time) {
                timer->due = loop->time;
            }
            if (RB_INSERT(async_timer_tree_s, &loop->timers, timer) != NULL) {
                LOG("RB_INSERT failed");
            }
        }
        else {
            /* If non-repeating, mark the timer as inactive. */
            timer->flags &= ~ASYNC_HANDLE_ACTIVE;
            async__handle_stop(timer);
        }
        timer->timer_cb((async_timer_t*) timer);
    }
}
