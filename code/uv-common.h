#ifndef ASYNC_COMMON_H_
#define ASYNC_COMMON_H_

#include "async.h"
#include "tree.h"
#include "queue.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define container_of(ptr, type, member) \
  ((type *) ((char *) (ptr) - offsetof(type, member)))

# define ASYNC__HANDLE_INTERNAL  0x80
# define ASYNC__HANDLE_ACTIVE    0x40
# define ASYNC__HANDLE_REF       0x20
# define ASYNC__HANDLE_CLOSING   0x01

int async__tcp_bind(async_tcp_t* tcp, const struct sockaddr* addr, uint32_t addrlen, uint32_t flags);

int async__tcp_connect(async_connect_t* req, async_tcp_t* handle, const struct sockaddr* addr, uint32_t addrlen, async_connect_cb cb);

int async__udp_bind(async_udp_t* handle, const struct sockaddr* addr, uint32_t  addrlen, uint32_t flags);

int async__udp_send(async_udp_send_t* req, async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, uint32_t addrlen, async_udp_send_cb send_cb);

int async__udp_try_send(async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, uint32_t addrlen);

int async__udp_recv_start(async_udp_t* handle, async_alloc_cb alloccb, async_udp_recv_cb recv_cb);

int async__udp_recv_stop(async_udp_t* handle);

void async__fs_poll_close(async_fs_poll_t* handle);

int async__getaddrinfo_translate_error(int sys_err);    /* EAI_* error. */

void async__work_submit(async_loop_t* loop, struct async__work *w, void (*work)(struct async__work *w), void (*done)(struct async__work *w, int status));

size_t async__count_bufs(const async_buf_t bufs[], uint32_t nbufs);

void async__work_done(async_async_t* handle);

int async__socket_sockopt(async_handle_t* handle, int optname, int* value);


#define async__has_active_reqs(loop)                                             \
  (queue_empty(&(loop)->active_reqs) == 0)

#define async__req_register(loop, req)                                           \
  do {                                                                        \
    queue_insert_tail(&(loop)->active_reqs, &(req)->active_queue);            \
  }                                                                           \
  while (0)

#define async__req_unregister(loop, req)                                         \
  do {                                                                        \
    queue_remove(&(req)->active_queue);                                       \
  }                                                                           \
  while (0)

#define async__has_active_handles(loop)                                          \
  ((loop)->active_handles > 0)

#define async__active_handle_add(h)                                              \
  do {                                                                        \
    (h)->loop->active_handles++;                                              \
  }                                                                           \
  while (0)

#define async__active_handle_rm(h)                                               \
  do {                                                                        \
    (h)->loop->active_handles--;                                              \
  }                                                                           \
  while (0)

#define async__is_active(h)                                                      \
  (((h)->flags & ASYNC__HANDLE_ACTIVE) != 0)

#define async__is_closing(h)                                                     \
  (((h)->flags & (ASYNC_CLOSING |  ASYNC_CLOSED)) != 0)

#define async__handle_start(h)                                                   \
  do {                                                                        \
    if (((h)->flags & ASYNC__HANDLE_ACTIVE) != 0) break;                         \
    (h)->flags |= ASYNC__HANDLE_ACTIVE;                                          \
    if (((h)->flags & ASYNC__HANDLE_REF) != 0) async__active_handle_add(h);         \
  }                                                                           \
  while (0)

#define async__handle_stop(h)                                                    \
  do {                                                                        \
    if (((h)->flags & ASYNC__HANDLE_ACTIVE) == 0) break;                         \
    (h)->flags &= ~ASYNC__HANDLE_ACTIVE;                                         \
    if (((h)->flags & ASYNC__HANDLE_REF) != 0) async__active_handle_rm(h);          \
  }                                                                           \
  while (0)

#define async__handle_ref(h)                                                     \
  do {                                                                        \
    if (((h)->flags & ASYNC__HANDLE_REF) != 0) break;                            \
    (h)->flags |= ASYNC__HANDLE_REF;                                             \
    if (((h)->flags & ASYNC__HANDLE_CLOSING) != 0) break;                        \
    if (((h)->flags & ASYNC__HANDLE_ACTIVE) != 0) async__active_handle_add(h);      \
  }                                                                           \
  while (0)

#define async__handle_unref(h)                                                   \
  do {                                                                        \
    if (((h)->flags & ASYNC__HANDLE_REF) == 0) break;                            \
    (h)->flags &= ~ASYNC__HANDLE_REF;                                            \
    if (((h)->flags & ASYNC__HANDLE_CLOSING) != 0) break;                        \
    if (((h)->flags & ASYNC__HANDLE_ACTIVE) != 0) async__active_handle_rm(h);       \
  }                                                                           \
  while (0)

#define async__has_ref(h)                                                        \
  (((h)->flags & ASYNC__HANDLE_REF) != 0)

#define async__handle_init(loop_, h, type_)                                      \
  do {                                                                        \
    (h)->loop = (loop_);                                                      \
    (h)->type = (type_);                                                      \
    (h)->flags = ASYNC__HANDLE_REF;  /* Ref the loop when active. */             \
    queue_insert_tail(&(loop_)->handle_queue, &(h)->handle_queue);            \
  }                                                                           \
  while (0)

#endif /* ASYNC_COMMON_H_ */
