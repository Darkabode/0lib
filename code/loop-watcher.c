#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"


void async_loop_watcher_endgame(async_loop_t* loop, async_handle_t* handle)
{
    if (handle->flags & ASYNC__HANDLE_CLOSING) {
        handle->flags |= ASYNC_HANDLE_CLOSED;
        async__handle_close(handle);
    }
}


#define ASYNC_LOOP_WATCHER_DEFINE(name, NAME)                                    \
  int async_##name##_init(async_loop_t* loop, async_##name##_t* handle) {              \
    async__handle_init(loop, (async_handle_t*) handle, ASYNC_##NAME);                  \
                                                                              \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
                                                                              \
  int async_##name##_start(async_##name##_t* handle, async_##name##_cb cb) {           \
    async_loop_t* loop = handle->loop;                                           \
    async_##name##_t* old_head;                                                  \
                                                                              \
    if (handle->flags & ASYNC_HANDLE_ACTIVE)                                     \
      return 0;                                                               \
                                                                              \
    if (cb == NULL)                                                           \
      return ASYNC_EINVAL;                                                       \
                                                                              \
    old_head = loop->name##_handles;                                          \
                                                                              \
    handle->name##_next = old_head;                                           \
    handle->name##_prev = NULL;                                               \
                                                                              \
    if (old_head) {                                                           \
      old_head->name##_prev = handle;                                         \
    }                                                                         \
                                                                              \
    loop->name##_handles = handle;                                            \
                                                                              \
    handle->name##_cb = cb;                                                   \
    handle->flags |= ASYNC_HANDLE_ACTIVE;                                        \
    async__handle_start(handle);                                                 \
                                                                              \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
                                                                              \
  int async_##name##_stop(async_##name##_t* handle) {                               \
    async_loop_t* loop = handle->loop;                                           \
                                                                              \
    if (!(handle->flags & ASYNC_HANDLE_ACTIVE))                                  \
      return 0;                                                               \
                                                                              \
    /* Update loop head if needed */                                          \
    if (loop->name##_handles == handle) {                                     \
      loop->name##_handles = handle->name##_next;                             \
    }                                                                         \
                                                                              \
    /* Update the iterator-next pointer of needed */                          \
    if (loop->next_##name##_handle == handle) {                               \
      loop->next_##name##_handle = handle->name##_next;                       \
    }                                                                         \
                                                                              \
    if (handle->name##_prev) {                                                \
      handle->name##_prev->name##_next = handle->name##_next;                 \
    }                                                                         \
    if (handle->name##_next) {                                                \
      handle->name##_next->name##_prev = handle->name##_prev;                 \
    }                                                                         \
                                                                              \
    handle->flags &= ~ASYNC_HANDLE_ACTIVE;                                       \
    async__handle_stop(handle);                                                  \
                                                                              \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
                                                                              \
  void async_##name##_invoke(async_loop_t* loop) {                                  \
    async_##name##_t* handle;                                                    \
                                                                              \
    (loop)->next_##name##_handle = (loop)->name##_handles;                    \
                                                                              \
    while ((loop)->next_##name##_handle != NULL) {                            \
      handle = (loop)->next_##name##_handle;                                  \
      (loop)->next_##name##_handle = handle->name##_next;                     \
                                                                              \
      handle->name##_cb(handle);                                              \
    }                                                                         \
  }

ASYNC_LOOP_WATCHER_DEFINE(prepare, PREPARE)
ASYNC_LOOP_WATCHER_DEFINE(check, CHECK)
ASYNC_LOOP_WATCHER_DEFINE(idle, IDLE)
