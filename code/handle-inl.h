#ifndef ASYNC_WIN_HANDLE_INL_H_
#define ASYNC_WIN_HANDLE_INL_H_

#include "async.h"
#include "internal.h"


#define DECREASE_ACTIVE_COUNT(loop, handle)                             \
  do {                                                                  \
    if (--(handle)->activecnt == 0 &&                                   \
        !((handle)->flags & ASYNC__HANDLE_CLOSING)) {                      \
      async__handle_stop((handle));                                        \
    }                                                                   \
  } while (0)


#define INCREASE_ACTIVE_COUNT(loop, handle)                             \
  do {                                                                  \
    if ((handle)->activecnt++ == 0) {                                   \
      async__handle_start((handle));                                       \
    }                                                                   \
  } while (0)


#define DECREASE_PENDING_REQ_COUNT(handle)                              \
  do {                                                                  \
    handle->reqs_pending--;                                             \
                                                                        \
    if (handle->flags & ASYNC__HANDLE_CLOSING &&                           \
        handle->reqs_pending == 0) {                                    \
      async_want_endgame(loop, (async_handle_t*)handle);                      \
    }                                                                   \
  } while (0)


#define async__handle_closing(handle)                                      \
  do {                                                                  \
    if (!(((handle)->flags & ASYNC__HANDLE_ACTIVE) &&                      \
          ((handle)->flags & ASYNC__HANDLE_REF)))                          \
      async__active_handle_add((async_handle_t*) (handle));                   \
                                                                        \
    (handle)->flags |= ASYNC__HANDLE_CLOSING;                              \
    (handle)->flags &= ~ASYNC__HANDLE_ACTIVE;                              \
  } while (0)


#define async__handle_close(handle)                                        \
  do {                                                                  \
    queue_remove(&(handle)->handle_queue);                              \
    async__active_handle_rm((async_handle_t*) (handle));                      \
                                                                        \
    (handle)->flags |= ASYNC_HANDLE_CLOSED;                                \
                                                                        \
    if ((handle)->close_cb)                                             \
      (handle)->close_cb((async_handle_t*) (handle));                      \
  } while (0)


void async_want_endgame(async_loop_t* loop, async_handle_t* handle);

#endif /* ASYNC_WIN_HANDLE_INL_H_ */
