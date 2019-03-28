#ifndef ASYNC_WIN_INTERNAL_H_
#define ASYNC_WIN_INTERNAL_H_

#include "async.h"
#include "uv-common.h"

#include "tree.h"
#include "winsock.h"

# define INLINE __inline

/*
 * Handles
 * (also see handle-inl.h)
 */

/* Used by all handles. */
#define ASYNC_HANDLE_CLOSED                        0x00000002
#define ASYNC_HANDLE_ENDGAME_QUEUED                0x00000004
#define ASYNC_HANDLE_ACTIVE                        0x00000010

/* uv-common.h: #define ASYNC__HANDLE_CLOSING      0x00000001 */
/* uv-common.h: #define ASYNC__HANDLE_ACTIVE       0x00000040 */
/* uv-common.h: #define ASYNC__HANDLE_REF          0x00000020 */
/* uv-common.h: #define ASYNC_HANDLE_INTERNAL      0x00000080 */

/* Used by streams and UDP handles. */
#define ASYNC_HANDLE_READING                       0x00000100
#define ASYNC_HANDLE_BOUND                         0x00000200
#define ASYNC_HANDLE_LISTENING                     0x00000800
#define ASYNC_HANDLE_CONNECTION                    0x00001000
#define ASYNC_HANDLE_CONNECTED                     0x00002000
#define ASYNC_HANDLE_READABLE                      0x00008000
#define ASYNC_HANDLE_WRITABLE                      0x00010000
#define ASYNC_HANDLE_READ_PENDING                  0x00020000
#define ASYNC_HANDLE_SYNC_BYPASS_IOCP              0x00040000
#define ASYNC_HANDLE_ZERO_READ                     0x00080000
#define ASYNC_HANDLE_EMULATE_IOCP                  0x00100000
#define ASYNC_HANDLE_BLOCKING_WRITES               0x00200000

/* Used by async_tcp_t and async_udp_t handles */
#define ASYNC_HANDLE_IPV6                          0x01000000

/* Only used by async_tcp_t handles. */
#define ASYNC_HANDLE_TCP_NODELAY                   0x02000000
#define ASYNC_HANDLE_TCP_KEEPALIVE                 0x04000000
#define ASYNC_HANDLE_TCP_SINGLE_ACCEPT             0x08000000
#define ASYNC_HANDLE_TCP_ACCEPT_STATE_CHANGING     0x10000000
#define ASYNC_HANDLE_TCP_SOCKET_CLOSED             0x20000000
#define ASYNC_HANDLE_SHARED_TCP_SOCKET             0x40000000

/* Only used by async_pipe_t handles. */
#define ASYNC_HANDLE_NON_OVERLAPPED_PIPE           0x01000000
#define ASYNC_HANDLE_PIPESERVER                    0x02000000
#define ASYNC_HANDLE_PIPE_READ_CANCELABLE             0x04000000

/* Only used by async_poll_t handles. */
#define ASYNC_HANDLE_POLL_SLOW                     0x02000000

/*
 * TCP
 */

typedef struct {
    WSAPROTOCOL_INFOW socket_info;
    int delayed_error;
} async__ipc_socket_info_ex;

int async_tcp_listen(async_tcp_t* handle, int backlog, async_connection_cb cb);
int async_tcp_accept(async_tcp_t* server, async_tcp_t* client);
int async_tcp_read_start(async_tcp_t* handle, async_alloc_cb alloc_cb,
    async_read_cb read_cb);
int async_tcp_write(async_loop_t* loop, async_write_t* req, async_tcp_t* handle,
    const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb);

void async_process_tcp_read_req(async_loop_t* loop, async_tcp_t* handle, async_req_t* req);
void async_process_tcp_write_req(async_loop_t* loop, async_tcp_t* handle,
    async_write_t* req);
void async_process_tcp_accept_req(async_loop_t* loop, async_tcp_t* handle,
    async_req_t* req);
void async_process_tcp_connect_req(async_loop_t* loop, async_tcp_t* handle,
    async_connect_t* req);

void async_tcp_close(async_loop_t* loop, async_tcp_t* tcp);
void async_tcp_endgame(async_loop_t* loop, async_tcp_t* handle);

int async_tcp_import(async_tcp_t* tcp, async__ipc_socket_info_ex* socket_info_ex,
    int tcp_connection);

int async_tcp_duplicate_socket(async_tcp_t* handle, int pid,
    LPWSAPROTOCOL_INFOW protocol_info);


/*
 * UDP
 */
void async_process_udp_recv_req(async_loop_t* loop, async_udp_t* handle, async_req_t* req);
void async_process_udp_send_req(async_loop_t* loop, async_udp_t* handle,
    async_udp_send_t* req);

void async_udp_close(async_loop_t* loop, async_udp_t* handle);
void async_udp_endgame(async_loop_t* loop, async_udp_t* handle);


/*
 * Pipes
 */
int async_stdio_pipe_server(async_loop_t* loop, async_pipe_t* handle, DWORD access,
    char* name, size_t nameSize);

int async_pipe_listen(async_pipe_t* handle, int backlog, async_connection_cb cb);
int async_pipe_accept(async_pipe_t* server, async_stream_t* client);
int async_pipe_read_start(async_pipe_t* handle, async_alloc_cb alloc_cb,
    async_read_cb read_cb);
int async_pipe_write(async_loop_t* loop, async_write_t* req, async_pipe_t* handle,
    const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb);
int async_pipe_write2(async_loop_t* loop, async_write_t* req, async_pipe_t* handle,
    const async_buf_t bufs[], uint32_t nbufs, async_stream_t* send_handle,
    async_write_cb cb);
void async__pipe_pause_read(async_pipe_t* handle);
void async__pipe_unpause_read(async_pipe_t* handle);
void async__pipe_stop_read(async_pipe_t* handle);

void async_process_pipe_read_req(async_loop_t* loop, async_pipe_t* handle,
    async_req_t* req);
void async_process_pipe_write_req(async_loop_t* loop, async_pipe_t* handle,
    async_write_t* req);
void async_process_pipe_accept_req(async_loop_t* loop, async_pipe_t* handle,
    async_req_t* raw_req);
void async_process_pipe_connect_req(async_loop_t* loop, async_pipe_t* handle,
    async_connect_t* req);
void async_process_pipe_shutdown_req(async_loop_t* loop, async_pipe_t* handle,
    async_shutdown_t* req);

void async_pipe_close(async_loop_t* loop, async_pipe_t* handle);
void async_pipe_cleanup(async_loop_t* loop, async_pipe_t* handle);
void async_pipe_endgame(async_loop_t* loop, async_pipe_t* handle);

/*
 * Poll watchers
 */
void async_process_poll_req(async_loop_t* loop, async_poll_t* handle,
    async_req_t* req);

int async_poll_close(async_loop_t* loop, async_poll_t* handle);
void async_poll_endgame(async_loop_t* loop, async_poll_t* handle);


/*
 * Timers
 */
void async_timer_endgame(async_loop_t* loop, async_timer_t* handle);

DWORD async__next_timeout(const async_loop_t* loop);
void async__time_forward(async_loop_t* loop, uint64_t msecs);
void async_process_timers(async_loop_t* loop);


/*
 * Loop watchers
 */
void async_loop_watcher_endgame(async_loop_t* loop, async_handle_t* handle);

void async_prepare_invoke(async_loop_t* loop);
void async_check_invoke(async_loop_t* loop);
void async_idle_invoke(async_loop_t* loop);

/*
 * Async watcher
 */
void async_async_close(async_loop_t* loop, async_async_t* handle);
void async_async_endgame(async_loop_t* loop, async_async_t* handle);

void async_process_async_wakeup_req(async_loop_t* loop, async_async_t* handle,
    async_req_t* req);


/*
 * Spawn
 */
void async_process_proc_exit(async_loop_t* loop, async_process_t* handle);
void async_process_close(async_loop_t* loop, async_process_t* handle);
void async_process_endgame(async_loop_t* loop, async_process_t* handle);


/*
 * Error
 */
int async_translate_sys_error(int sys_errno);

/*
 * FS Event
 */
void async_process_fs_event_req(async_loop_t* loop, async_req_t* req,
    async_fs_event_t* handle);
void async_fs_event_close(async_loop_t* loop, async_fs_event_t* handle);
void async_fs_event_endgame(async_loop_t* loop, async_fs_event_t* handle);


/*
 * Stat poller.
 */
void async__fs_poll_endgame(async_loop_t* loop, async_fs_poll_t* handle);


/*
 * Utilities.
 */
void async__util_init();

int async_parent_pid();

/*
 * Winsock utility functions
 */
int async_winsock_init();

int async_ntstatus_to_winsock_error(NTSTATUS status);

BOOL async_get_acceptex_function(SOCKET socket, LPFN_ACCEPTEX* target);
BOOL async_get_connectex_function(SOCKET socket, LPFN_CONNECTEX* target);

int WSAAPI async_wsarecv_workaround(SOCKET socket, WSABUF* buffers,
    DWORD buffer_count, DWORD* bytes, DWORD* flags, WSAOVERLAPPED *overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);
int WSAAPI async_wsarecvfrom_workaround(SOCKET socket, WSABUF* buffers,
    DWORD buffer_count, DWORD* bytes, DWORD* flags, struct sockaddr* addr,
    int* addr_len, WSAOVERLAPPED *overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);

int WSAAPI async_msafd_poll(SOCKET socket, AFD_POLL_INFO* info,
    OVERLAPPED* overlapped);

/* Whether there are any non-IFS LSPs stacked on TCP */
extern int async_tcp_non_ifs_lsp_ipv4;
extern int async_tcp_non_ifs_lsp_ipv6;

/* Ip address used to bind to any port at any interface */
extern struct sockaddr_in async_addr_ip4_any_;
extern struct sockaddr_in6 async_addr_ip6_any_;

#endif /* ASYNC_WIN_INTERNAL_H_ */
