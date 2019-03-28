#ifndef ASYNC_WIN_REQ_INL_H_
#define ASYNC_WIN_REQ_INL_H_

#include "async.h"
#include "internal.h"


#define SET_REQ_STATUS(req, status)                                     \
   (req)->overlapped.Internal = (ULONG_PTR) (status)

#define SET_REQ_ERROR(req, error)                                       \
  SET_REQ_STATUS((req), NTSTATUS_FROM_WIN32((error)))

#define SET_REQ_SUCCESS(req)                                            \
  SET_REQ_STATUS((req), STATUS_SUCCESS)

#define GET_REQ_STATUS(req)                                             \
  ((NTSTATUS) (req)->overlapped.Internal)

#define REQ_SUCCESS(req)                                                \
  (NT_SUCCESS(GET_REQ_STATUS((req))))

#define GET_REQ_ERROR(req)                                              \
  (fn_RtlNtStatusToDosError(GET_REQ_STATUS((req))))

#define GET_REQ_SOCK_ERROR(req)                                         \
  (async_ntstatus_to_winsock_error(GET_REQ_STATUS((req))))


#define REGISTER_HANDLE_REQ(loop, handle, req)                          \
  do {                                                                  \
    INCREASE_ACTIVE_COUNT((loop), (handle));                            \
    async__req_register((loop), (req));                                    \
  } while (0)

#define UNREGISTER_HANDLE_REQ(loop, handle, req)                        \
  do {                                                                  \
    DECREASE_ACTIVE_COUNT((loop), (handle));                            \
    async__req_unregister((loop), (req));                                  \
  } while (0)


#define ASYNC_SUCCEEDED_WITHOUT_IOCP(result)                               \
  ((result) && (handle->flags & ASYNC_HANDLE_SYNC_BYPASS_IOCP))

#define ASYNC_SUCCEEDED_WITH_IOCP(result)                                  \
  ((result) || (fn_GetLastError() == ERROR_IO_PENDING))


#define POST_COMPLETION_FOR_REQ(loop, req)                              \
  if (!fn_PostQueuedCompletionStatus((loop)->iocp, 0, 0, &((req)->overlapped))) {            \
        LOG("PostQueuedCompletionStatus failed with error 0x%08X", fn_GetLastError());       \
  }

static void async_req_init(async_loop_t* loop, async_req_t* req)
{
  req->type = ASYNC_UNKNOWN_REQ;
  SET_REQ_SUCCESS(req);
}


static async_req_t* async_overlapped_to_req(OVERLAPPED* overlapped) {
  return CONTAINING_RECORD(overlapped, async_req_t, overlapped);
}


static void async_insert_pending_req(async_loop_t* loop, async_req_t* req) {
  req->next_req = NULL;
  if (loop->pending_reqs_tail) {
    req->next_req = loop->pending_reqs_tail->next_req;
    loop->pending_reqs_tail->next_req = req;
    loop->pending_reqs_tail = req;
  } else {
    req->next_req = req;
    loop->pending_reqs_tail = req;
  }
}


#define DELEGATE_STREAM_REQ(loop, req, method, handle_at)                     \
  do {                                                                        \
    switch (((async_handle_t*) (req)->handle_at)->type) {                        \
      case ASYNC_TCP:                                                            \
        async_process_tcp_##method##_req(loop,                                   \
                                      (async_tcp_t*) ((req)->handle_at),         \
                                      req);                                   \
        break;                                                                \
                                                                              \
      case ASYNC_NAMED_PIPE:                                                     \
        async_process_pipe_##method##_req(loop,                                  \
                                       (async_pipe_t*) ((req)->handle_at),       \
                                       req);                                  \
        break;                                                                \
                                                                              \
    }                                                                         \
  } while (0)


static void async_process_reqs(async_loop_t* loop)
{
    async_req_t* req;
    async_req_t* first;
    async_req_t* next;

    if (loop->pending_reqs_tail == NULL) {
        return;
    }

    first = loop->pending_reqs_tail->next_req;
    next = first;
    loop->pending_reqs_tail = NULL;

    while (next != NULL) {
        req = next;
        next = req->next_req != first ? req->next_req : NULL;

        switch (req->type) {
            case ASYNC_READ:
                DELEGATE_STREAM_REQ(loop, req, read, data);
                break;
            case ASYNC_WRITE:
                DELEGATE_STREAM_REQ(loop, (async_write_t*) req, write, handle);
                break;
            case ASYNC_ACCEPT:
                DELEGATE_STREAM_REQ(loop, req, accept, data);
                break;
            case ASYNC_CONNECT:
                DELEGATE_STREAM_REQ(loop, (async_connect_t*) req, connect, handle);
                break;
            case ASYNC_SHUTDOWN:
                /* Tcp shutdown requests don't come here. */
                async_process_pipe_shutdown_req(loop, (async_pipe_t*) ((async_shutdown_t*) req)->handle, (async_shutdown_t*) req);
                break;
            case ASYNC_UDP_RECV:
                async_process_udp_recv_req(loop, (async_udp_t*) req->data, req);
                break;
            case ASYNC_UDP_SEND:
                async_process_udp_send_req(loop, ((async_udp_send_t*) req)->handle, (async_udp_send_t*) req);
                break;
            case ASYNC_WAKEUP:
                async_process_async_wakeup_req(loop, (async_async_t*) req->data, req);
                break;
            case ASYNC_POLL_REQ:
                async_process_poll_req(loop, (async_poll_t*) req->data, req);
                break;
            case ASYNC_FS_EVENT_REQ:
                async_process_fs_event_req(loop, req, (async_fs_event_t*) req->data);
                break;
        }
    }
}

#endif /* ASYNC_WIN_REQ_INL_H_ */
