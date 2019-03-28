#ifndef __0LIB_ASYNC_H_
#define __0LIB_ASYNC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "uv-errno.h"
#include <stddef.h>

#include "tree.h"
#include "uv-threadpool.h"

#define MAX_PIPENAME_LEN 256

#ifndef S_IFLNK
# define S_IFLNK 0xA000
#endif

    /* Additional signals supported by async_signal and or async_kill. The CRT defines
    * the following signals already:
    *
    *   #define SIGINT           2
    *   #define SIGILL           4
    *   #define SIGABRT_COMPAT   6
    *   #define SIGFPE           8
    *   #define SIGSEGV         11
    *   #define SIGTERM         15
    *   #define SIGBREAK        21
    *   #define SIGABRT         22
    *
    * The additional signals have values that are common on other Unix
    * variants (Linux and Darwin)
    */
#define SIGHUP                1
#define SIGKILL               9
#define SIGWINCH             28

    /* The CRT defines SIGABRT_COMPAT as 6, which equals SIGABRT on many */
    /* unix-like platforms. However MinGW doesn't define it, so we do. */
#ifndef SIGABRT_COMPAT
# define SIGABRT_COMPAT       6
#endif

    typedef int (WSAAPI* LPFN_WSARECV)(SOCKET socket, LPWSABUF buffers, DWORD buffer_count, LPDWORD bytes, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);
    typedef int (WSAAPI* LPFN_WSARECVFROM)(SOCKET socket, LPWSABUF buffers, DWORD buffer_count, LPDWORD bytes, LPDWORD flags, struct sockaddr* addr, LPINT addr_len, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine);

#ifndef _NTDEF_
    typedef LONG NTSTATUS;
    typedef NTSTATUS *PNTSTATUS;
#endif

#ifndef RTL_CONDITION_VARIABLE_INIT
    typedef PVOID CONDITION_VARIABLE, *PCONDITION_VARIABLE;
#endif

    typedef struct _AFD_POLL_HANDLE_INFO {
        HANDLE Handle;
        ULONG Events;
        NTSTATUS Status;
    } AFD_POLL_HANDLE_INFO, *PAFD_POLL_HANDLE_INFO;

    typedef struct _AFD_POLL_INFO {
        LARGE_INTEGER Timeout;
        ULONG NumberOfHandles;
        ULONG Exclusive;
        AFD_POLL_HANDLE_INFO Handles[1];
    } AFD_POLL_INFO, *PAFD_POLL_INFO;

#define ASYNC_MSAFD_PROVIDER_COUNT 3


    /**
    * It should be possible to cast async_buf_t[] to WSABUF[]
    * see http://msdn.microsoft.com/en-us/library/ms741542(v=vs.85).aspx
    */
    typedef struct async_buf_t {
        ULONG len;
        char* base;
    } async_buf_t;

    typedef int async_file;
    typedef SOCKET async_os_sock_t;
    typedef HANDLE async_thread_t;
    typedef HANDLE async_sem_t;
    typedef CRITICAL_SECTION mutex_t;

    /* This condition variable implementation is based on the SetEvent solution
    * (section 3.2) at http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
    * We could not use the SignalObjectAndWait solution (section 3.4) because
    * it want the 2nd argument (type mutex_t) of async_cond_wait() and
    * async_cond_timedwait() to be HANDLEs, but we use CRITICAL_SECTIONs.
    */

    typedef union {
        CONDITION_VARIABLE cond_var;
        struct
        {
            uint32_t waiters_count;
            CRITICAL_SECTION waiters_count_lock;
            HANDLE signal_event;
            HANDLE broadcast_event;
        } fallback;
    } async_cond_t;

    typedef union {
        /* srwlock_ has type SRWLOCK, but not all toolchains define this type in */
        /* windows.h. */
        SRWLOCK srwlock_;
        struct
        {
            mutex_t read_mutex_;
            mutex_t write_mutex_;
            uint32_t num_readers_;
        } fallback_;
    } async_rwlock_t;

    typedef struct
    {
        uint32_t n;
        uint32_t count;
        mutex_t mutex;
        async_sem_t turnstile1;
        async_sem_t turnstile2;
    } async_barrier_t;

    typedef struct
    {
        DWORD tls_index;
    } async_key_t;

#define ASYNC_ONCE_INIT { 0, NULL }

    typedef struct async_once_s {
        uint8_t ran;
        HANDLE event;
    } async_once_t;

    /* Platform-specific definitions for async_spawn support. */
    typedef uint8_t async_uid_t;
    typedef uint8_t async_gid_t;

    RB_HEAD(async_timer_tree_s, async_timer_s);

#define async_stream_connection_fields                                           \
  uint32_t write_reqs_pending;                                            \
  async_shutdown_t* shutdown_req;

#define async_stream_server_fields                                               \
  async_connection_cb connection_cb;

#define async_tcp_server_fields                                                  \
  async_tcp_accept_t* accept_reqs;                                               \
  uint32_t processed_accepts;                                             \
  async_tcp_accept_t* pending_accepts;                                           \
  LPFN_ACCEPTEX func_acceptex;

#define async_tcp_connection_fields                                              \
  async_buf_t read_buffer;                                                       \
  LPFN_CONNECTEX func_connectex;


#define async_pipe_server_fields                                                 \
  int pending_instances;                                                      \
  async_pipe_accept_t* accept_reqs;                                              \
  async_pipe_accept_t* pending_accepts;

#define async_pipe_connection_fields                                             \
  async_timer_t* eof_timer;                                                      \
  async_write_t ipc_header_write_req;                                            \
  int ipc_pid;                                                                \
  uint64_t remaining_ipc_rawdata_bytes;                                       \
  struct {                                                                    \
    void* queue[2];                                                           \
    int queue_len;                                                            \
      } pending_ipc_info;                                                         \
  async_write_t* non_overlapped_writes_tail;                                     \
  mutex_t readfile_mutex;                                                  \
  volatile HANDLE readfile_thread;                                            \
  void* reserved;


/* Expand this list if necessary. */
#define ASYNC_ERRNO_MAP(XX)                                                      \
  XX(E2BIG, "argument list too long")                                         \
  XX(EACCES, "permission denied")                                             \
  XX(EADDRINUSE, "address already in use")                                    \
  XX(EADDRNOTAVAIL, "address not available")                                  \
  XX(EAFNOSUPPORT, "address family not supported")                            \
  XX(EAGAIN, "resource temporarily unavailable")                              \
  XX(EAI_ADDRFAMILY, "address family not supported")                          \
  XX(EAI_AGAIN, "temporary failure")                                          \
  XX(EAI_BADFLAGS, "bad ai_flags value")                                      \
  XX(EAI_BADHINTS, "invalid value for hints")                                 \
  XX(EAI_CANCELED, "request canceled")                                        \
  XX(EAI_FAIL, "permanent failure")                                           \
  XX(EAI_FAMILY, "ai_family not supported")                                   \
  XX(EAI_MEMORY, "out of memory")                                             \
  XX(EAI_NODATA, "no address")                                                \
  XX(EAI_NONAME, "unknown node or service")                                   \
  XX(EAI_OVERFLOW, "argument buffer overflow")                                \
  XX(EAI_PROTOCOL, "resolved protocol is unknown")                            \
  XX(EAI_SERVICE, "service not available for socket type")                    \
  XX(EAI_SOCKTYPE, "socket type not supported")                               \
  XX(EALREADY, "connection already in progress")                              \
  XX(EBADF, "bad file descriptor")                                            \
  XX(EBUSY, "resource busy or locked")                                        \
  XX(ECANCELED, "operation canceled")                                         \
  XX(ECHARSET, "invalid Unicode character")                                   \
  XX(ECONNABORTED, "software caused connection abort")                        \
  XX(ECONNREFUSED, "connection refused")                                      \
  XX(ECONNRESET, "connection reset by peer")                                  \
  XX(EDESTADDRREQ, "destination address required")                            \
  XX(EEXIST, "file already exists")                                           \
  XX(EFAULT, "bad address in system call argument")                           \
  XX(EFBIG, "file too large")                                                 \
  XX(EHOSTUNREACH, "host is unreachable")                                     \
  XX(EINTR, "interrupted system call")                                        \
  XX(EINVAL, "invalid argument")                                              \
  XX(EIO, "i/o error")                                                        \
  XX(EISCONN, "socket is already connected")                                  \
  XX(EISDIR, "illegal operation on a directory")                              \
  XX(ELOOP, "too many symbolic links encountered")                            \
  XX(EMFILE, "too many open files")                                           \
  XX(EMSGSIZE, "message too long")                                            \
  XX(ENAMETOOLONG, "name too long")                                           \
  XX(ENETDOWN, "network is down")                                             \
  XX(ENETUNREACH, "network is unreachable")                                   \
  XX(ENFILE, "file table overflow")                                           \
  XX(ENOBUFS, "no buffer space available")                                    \
  XX(ENODEV, "no such device")                                                \
  XX(ENOENT, "no such file or directory")                                     \
  XX(ENOMEM, "not enough memory")                                             \
  XX(ENONET, "machine is not on the network")                                 \
  XX(ENOPROTOOPT, "protocol not available")                                   \
  XX(ENOSPC, "no space left on device")                                       \
  XX(ENOSYS, "function not implemented")                                      \
  XX(ENOTCONN, "socket is not connected")                                     \
  XX(ENOTDIR, "not a directory")                                              \
  XX(ENOTEMPTY, "directory not empty")                                        \
  XX(ENOTSOCK, "socket operation on non-socket")                              \
  XX(ENOTSUP, "operation not supported on socket")                            \
  XX(EPERM, "operation not permitted")                                        \
  XX(EPIPE, "broken pipe")                                                    \
  XX(EPROTO, "protocol error")                                                \
  XX(EPROTONOSUPPORT, "protocol not supported")                               \
  XX(EPROTOTYPE, "protocol wrong type for socket")                            \
  XX(ERANGE, "result too large")                                              \
  XX(EROFS, "read-only file system")                                          \
  XX(ESHUTDOWN, "cannot send after transport endpoint shutdown")              \
  XX(ESPIPE, "invalid seek")                                                  \
  XX(ESRCH, "no such process")                                                \
  XX(ETIMEDOUT, "connection timed out")                                       \
  XX(ETXTBSY, "text file is busy")                                            \
  XX(EXDEV, "cross-device link not permitted")                                \
  XX(UNKNOWN, "unknown error")                                                \
  XX(EOF, "end of file")                                                      \
  XX(ENXIO, "no such device or address")                                      \
  XX(EMLINK, "too many links")                                                \

#define ASYNC_HANDLE_TYPE_MAP(XX)                                                \
  XX(ASYNC, async)                                                            \
  XX(CHECK, check)                                                            \
  XX(FS_EVENT, fs_event)                                                      \
  XX(FS_POLL, fs_poll)                                                        \
  XX(HANDLE, handle)                                                          \
  XX(IDLE, idle)                                                              \
  XX(NAMED_PIPE, pipe)                                                        \
  XX(POLL, poll)                                                              \
  XX(PREPARE, prepare)                                                        \
  XX(STREAM, stream)                                                          \
  XX(TCP, tcp)                                                                \
  XX(TIMER, timer)                                                            \
  XX(UDP, udp)                                                                \

#define ASYNC_REQ_TYPE_MAP(XX)                                                   \
  XX(REQ, req)                                                                \
  XX(CONNECT, connect)                                                        \
  XX(WRITE, write)                                                            \
  XX(SHUTDOWN, shutdown)                                                      \
  XX(UDP_SEND, udp_send)                                                      \
  XX(FS, fs)                                                                  \
  XX(WORK, work)                                                              \
  XX(GETADDRINFO, getaddrinfo)                                                \
  XX(GETNAMEINFO, getnameinfo)                                                \

typedef enum {
#define XX(code, _) ASYNC_ ## code = ASYNC__ ## code,
  ASYNC_ERRNO_MAP(XX)
#undef XX
  ASYNC_ERRNO_MAX = ASYNC__EOF - 1
} async_errno_t;

typedef enum {
  ASYNC_UNKNOWN_HANDLE = 0,
#define XX(uc, lc) ASYNC_##uc,
  ASYNC_HANDLE_TYPE_MAP(XX)
#undef XX
  ASYNC_FILE,
  ASYNC_HANDLE_TYPE_MAX
} async_handle_type;

typedef enum {
  ASYNC_UNKNOWN_REQ = 0,
#define XX(uc, lc) ASYNC_##uc,
  ASYNC_REQ_TYPE_MAP(XX)
#undef XX
  /* TODO: remove the req suffix */
  ASYNC_ACCEPT,
  ASYNC_FS_EVENT_REQ,
  ASYNC_POLL_REQ,
  ASYNC_READ,
  ASYNC_UDP_RECV,
  ASYNC_WAKEUP,
  ASYNC_REQ_TYPE_MAX
} async_req_type;


/* Handle types. */
typedef struct async_loop_s async_loop_t;
typedef struct async_handle_s async_handle_t;
typedef struct async_stream_s async_stream_t;
typedef struct async_tcp_s async_tcp_t;
typedef struct async_udp_s async_udp_t;
typedef struct async_pipe_s async_pipe_t;
typedef struct async_poll_s async_poll_t;
typedef struct async_timer_s async_timer_t;
typedef struct async_prepare_s async_prepare_t;
typedef struct async_check_s async_check_t;
typedef struct async_idle_s async_idle_t;
typedef struct async_async_s async_async_t;
typedef struct async_process_s async_process_t;
typedef struct async_fs_event_s async_fs_event_t;
typedef struct async_fs_poll_s async_fs_poll_t;
typedef struct async_signal_s async_signal_t;

/* Request types. */
typedef struct async_req_s async_req_t;
typedef struct async_getaddrinfo_s async_getaddrinfo_t;
typedef struct async_getnameinfo_s async_getnameinfo_t;
typedef struct async_shutdown_s async_shutdown_t;
typedef struct async_write_s async_write_t;
typedef struct async_connect_s async_connect_t;
typedef struct async_udp_send_s async_udp_send_t;
typedef struct async_fs_s async_fs_t;
typedef struct async_work_s async_work_t;

/* None of the above. */
typedef struct async_interface_address_s async_interface_address_t;


typedef enum {
    ASYNC_RUN_DEFAULT = 0,
    ASYNC_RUN_ONCE,
    ASYNC_RUN_NOWAIT
} async_run_mode;

/*
 * All functions besides async_run() are non-blocking.
 *
 * All callbacks in libuv are made asynchronously. That is they are never
 * made by the function that takes them as a parameter.
 */

/*
 * Returns the default loop.
 */
async_loop_t* async_default_loop(void);

/*
 * Initializes a async_loop_t structure.
 */
void async_loop_init();

/*
 * Closes all internal loop resources.  This function must only be called once
 * the loop has finished it's execution or it will return ASYNC_EBUSY.  After this
 * function returns the user shall memory_free the memory allocated for the loop.
 */
int async_loop_close(async_loop_t* loop);

/*
 * Returns size of the loop struct, useful for dynamic lookup with FFI
 */
size_t async_loop_size(void);

/*
 * This function runs the event loop. It will act differently depending on the
 * specified mode:
 *  - ASYNC_RUN_DEFAULT: Runs the event loop until the reference count drops to
 *    zero. Always returns zero.
 *  - ASYNC_RUN_ONCE: Poll for new events once. Note that this function blocks if
 *    there are no pending events. Returns zero when done (no active handles
 *    or requests left), or non-zero if more events are expected (meaning you
 *    should run the event loop again sometime in the future).
 *  - ASYNC_RUN_NOWAIT: Poll for new events once but don't block if there are no
 *    pending events. Returns zero when done (no active handles
 *    or requests left), or non-zero if more events are expected (meaning you
 *    should run the event loop again sometime in the future).
 */
int async_run(async_loop_t*, async_run_mode mode);

/*
 * This function checks whether the reference count, the number of active
 * handles or requests left in the event loop, is non-zero.
 */
int async_loop_alive(const async_loop_t* loop);

/*
 * This function will stop the event loop by forcing async_run to end
 * as soon as possible, but not sooner than the next loop iteration.
 * If this function was called before blocking for i/o, the loop won't
 * block for i/o on this iteration.
 */
void async_stop(async_loop_t*);

/*
 * Manually modify the event loop's reference count. Useful if the user wants
 * to have a handle or timeout that doesn't keep the loop alive.
 */
void async_ref(async_handle_t*);
void async_unref(async_handle_t*);
int async_has_ref(const async_handle_t*);

/*
 * Update the event loop's concept of "now". Libuv caches the current time
 * at the start of the event loop tick in order to reduce the number of
 * time-related system calls.
 *
 * You won't normally need to call this function unless you have callbacks
 * that block the event loop for longer periods of time, where "longer" is
 * somewhat subjective but probably on the order of a millisecond or more.
 */
void async_update_time(async_loop_t*);

/*
 * Return the current timestamp in milliseconds. The timestamp is cached at
 * the start of the event loop tick, see |async_update_time()| for details and
 * rationale.
 *
 * The timestamp increases monotonically from some arbitrary point in time.
 * Don't make assumptions about the starting point, you will only get
 * disappointed.
 *
 */
uint64_t async_now(const async_loop_t*);

void async_process_endgames(async_loop_t* loop);


/*
 * Should prepare a buffer that libuv can use to read data into.
 *
 * `suggested_size` is a hint. Returning a buffer that is smaller is perfectly
 * okay as long as `buf.len > 0`.
 *
 * If you return a buffer with `buf.len == 0`, libuv skips the read and calls
 * your read or recv callback with nread=ASYNC_ENOBUFS.
 *
 * Note that returning a zero-length buffer does not stop the handle, call
 * async_read_stop() or async_udp_recv_stop() for that.
 */
typedef void (*async_alloc_cb)(async_handle_t* handle, size_t suggested_size, async_buf_t* buf);

/*
 * `nread` is > 0 if there is data available, 0 if libuv is done reading for
 * now, or < 0 on error.
 *
 * The callee is responsible for closing the stream when an error happens.
 * Trying to read from the stream again is undefined.
 *
 * The callee is responsible for freeing the buffer, libuv does not reuse it.
 * The buffer may be a null buffer (where buf->base=NULL and buf->len=0) on
 * EOF or error.
 */
typedef void (*async_read_cb)(async_stream_t* stream, ssize_t nread, const async_buf_t* buf);
typedef void (*async_write_cb)(async_write_t* req, int status);
typedef void (*async_connect_cb)(async_connect_t* req, int status);
typedef void (*async_shutdown_cb)(async_shutdown_t* req, int status);
typedef void (*async_connection_cb)(async_stream_t* server, int status);
typedef void (*async_close_cb)(async_handle_t* handle);
typedef void (*async_poll_cb)(async_poll_t* handle, int status, int events);
typedef void (*async_timer_cb)(async_timer_t* handle);
typedef void (*async_async_cb)(async_async_t* handle);
typedef void (*async_prepare_cb)(async_prepare_t* handle);
typedef void (*async_check_cb)(async_check_t* handle);
typedef void (*async_idle_cb)(async_idle_t* handle);
typedef void (*async_exit_cb)(async_process_t*, int64_t exit_status, int term_signal);
typedef void (*async_walk_cb)(async_handle_t* handle, void* arg);
typedef void (*async_fs_cb)(async_fs_t* req);
typedef void (*async_work_cb)(async_work_t* req);
typedef void (*async_after_work_cb)(async_work_t* req, int status);
typedef void (*async_getaddrinfo_cb)(async_getaddrinfo_t* req, int status, struct addrinfo* res);
typedef void (*async_getnameinfo_cb)(async_getnameinfo_t* req, int status, const char* hostname, const char* service);

typedef struct
{
    long tv_sec;
    long tv_nsec;
} async_timespec_t;


typedef struct
{
    uint64_t st_dev;
    uint64_t st_mode;
    uint64_t st_nlink;
    uint64_t st_uid;
    uint64_t st_gid;
    uint64_t st_rdev;
    uint64_t st_ino;
    uint64_t st_size;
    uint64_t st_blksize;
    uint64_t st_blocks;
    uint64_t st_flags;
    uint64_t st_gen;
    async_timespec_t st_atim;
    async_timespec_t st_mtim;
    async_timespec_t st_ctim;
    async_timespec_t st_birthtim;
} async_stat_t;


/*
* This will be called repeatedly after the async_fs_event_t is initialized.
* If async_fs_event_t was initialized with a directory the filename parameter
* will be a relative path to a file contained in the directory.
* The events parameter is an ORed mask of enum async_fs_event elements.
*/
typedef void (*async_fs_event_cb)(async_fs_event_t* handle, const char* filename, int events, int status);

typedef void (*async_fs_poll_cb)(async_fs_poll_t* handle, int status, const async_stat_t* prev, const async_stat_t* curr);

typedef void (*async_signal_cb)(async_signal_t* handle, int signum);


typedef enum {
  ASYNC_LEAVE_GROUP = 0,
  ASYNC_JOIN_GROUP
} async_membership;


/*
 * Most functions return 0 on success or an error code < 0 on failure.
 */
const char* async_strerror(int err);
const char* async_err_name(int err);


#define ASYNC_REQ_FIELDS                   \
    /* public */                        \
    void* data;                         \
    /* read-only */                     \
    async_req_type type;                   \
    void* active_queue[2];              \
    union {                             \
        /* Used by I/O operations */    \
        struct {                        \
            OVERLAPPED overlapped;      \
            size_t queued_bytes;        \
        };                              \
    };                                  \
    struct async_req_s* next_req;


/* Abstract base class of all requests. */
struct async_req_s
{
    ASYNC_REQ_FIELDS
};


/* Platform-specific request types */
typedef struct async_pipe_accept_s
{
    ASYNC_REQ_FIELDS
    HANDLE pipeHandle;
    struct async_pipe_accept_s* next_pending;
} async_pipe_accept_t;

typedef struct async_tcp_accept_s {
    ASYNC_REQ_FIELDS
    SOCKET accept_socket;
    char accept_buffer[sizeof(struct sockaddr_storage) * 2 + 32];
    HANDLE event_handle;
    HANDLE wait_handle;
    struct async_tcp_accept_s* next_pending;
} async_tcp_accept_t;

typedef struct async_read_s
{
    ASYNC_REQ_FIELDS
    HANDLE event_handle;
    HANDLE wait_handle;
} async_read_t;


/*
 * async_shutdown_t is a subclass of async_req_t
 *
 * Shutdown the outgoing (write) side of a duplex stream. It waits for
 * pending write requests to complete. The handle should refer to a
 * initialized stream. req should be an uninitialized shutdown request
 * struct. The cb is called after shutdown is complete.
 */
int async_shutdown(async_shutdown_t* req, async_stream_t* handle, async_shutdown_cb cb);

struct async_shutdown_s
{
  ASYNC_REQ_FIELDS
  async_stream_t* handle;
  async_shutdown_cb cb;
};


#define ASYNC_HANDLE_FIELDS                                                      \
    /* public */                                                              \
    void* data;                                                               \
    /* read-only */                                                           \
    async_loop_t* loop;                                                          \
    async_handle_type type;                                                      \
    /* private */                                                             \
    async_close_cb close_cb;                                                     \
    void* handle_queue[2];                                                    \
    async_handle_t* endgame_next;                                                \
    uint32_t flags;

/* The abstract base class of all handles.  */
struct async_handle_s
{
    ASYNC_HANDLE_FIELDS
};

/*
 * Returns size of various handle types, useful for FFI
 * bindings to allocate correct memory without copying struct
 * definitions
 */
size_t async_handle_size(async_handle_type type);

/*
 * Returns size of request types, useful for dynamic lookup with FFI
 */
size_t async_req_size(async_req_type type);

/*
 * Returns non-zero if the handle is active, zero if it's inactive.
 *
 * What "active" means depends on the type of handle:
 *
 *  - A async_async_t handle is always active and cannot be deactivated, except
 *    by closing it with async_close().
 *
 *  - A async_pipe_t, async_tcp_t, async_udp_t, etc. handle - basically any handle that
 *    deals with I/O - is active when it is doing something that involves I/O,
 *    like reading, writing, connecting, accepting new connections, etc.
 *
 *  - A async_check_t, async_idle_t, async_timer_t, etc. handle is active when it has
 *    been started with a call to async_check_start(), async_idle_start(), etc.
 *
 *      Rule of thumb: if a handle of type async_foo_t has a async_foo_start()
 *      function, then it's active from the moment that function is called.
 *      Likewise, async_foo_stop() deactivates the handle again.
 *
 */
int async_is_active(const async_handle_t* handle);

/*
 * Walk the list of open handles.
 */
void async_walk(async_loop_t* loop, async_walk_cb walk_cb, void* arg);


/*
 * Request handle to be closed. close_cb will be called asynchronously after
 * this call. This MUST be called on each handle before memory is released.
 *
 * Note that handles that wrap file descriptors are closed immediately but
 * close_cb will still be deferred to the next iteration of the event loop.
 * It gives you a chance to memory_free up any resources associated with the handle.
 *
 * In-progress requests, like async_connect_t or async_write_t, are cancelled and
 * have their callbacks called asynchronously with status=ASYNC_ECANCELED.
 */
void async_close(async_handle_t* handle, async_close_cb close_cb);

/*
* Returns or sets the size of the receive buffer that the operating
* system uses for the socket.
*
* If *value == 0, it will return the current receive buffer size,
* otherwise it will use *value to set the new receive buffer size.
*
* NOTE: linux will set double the size and return double the size
*       of the original set value.
*/
int async_recv_buffer_size(async_handle_t* handle, int* value);

/*
* Returns or sets the size of the send buffer that the operating
* system uses for the socket.
*
* If *value == 0, it will return the current send buffer size,
* otherwise it will use *value to set the new send buffer size.
*
* NOTE: linux will set double the size and return double the size
*       of the original set value.
*/
int async_send_buffer_size(async_handle_t* handle, int* value);

/*
 * Constructor for async_buf_t.
 * Due to platform differences the user cannot rely on the ordering of the
 * base and len members of the async_buf_t struct. The user is responsible for
 * freeing base after the async_buf_t is done. Return struct passed by value.
 */
async_buf_t async_buf_init(char* base, uint32_t len);


#define ASYNC_STREAM_FIELDS                                                      \
    /* number of bytes queued for writing */                                    \
    size_t write_queue_size;                                                    \
    async_alloc_cb alloc_cb;                                                       \
    async_read_cb read_cb;                                                         \
    /* private */                                                               \
    uint32_t reqs_pending;                                                  \
    int activecnt;                                                              \
    async_read_t read_req;                                                         \
    union {                                                                     \
        struct { async_stream_connection_fields };                                   \
        struct { async_stream_server_fields     };                                   \
    };


/*
 * async_stream_t is a subclass of async_handle_t
 *
 * async_stream is an abstract class.
 *
 * async_stream_t is the parent class of async_tcp_t, async_pipe_t.
 */
struct async_stream_s
{
  ASYNC_HANDLE_FIELDS
  ASYNC_STREAM_FIELDS
};

int async_listen(async_stream_t* stream, int backlog, async_connection_cb cb);

/*
 * This call is used in conjunction with async_listen() to accept incoming
 * connections. Call async_accept after receiving a async_connection_cb to accept
 * the connection. Before calling async_accept use async_*_init() must be
 * called on the client. Non-zero return value indicates an error.
 *
 * When the async_connection_cb is called it is guaranteed that async_accept will
 * complete successfully the first time. If you attempt to use it more than
 * once, it may fail. It is suggested to only call async_accept once per
 * async_connection_cb call.
 */
int async_accept(async_stream_t* server, async_stream_t* client);

/*
 * Read data from an incoming stream. The callback will be made several
 * times until there is no more data to read or async_read_stop is called.
 * When we've reached EOF nread will be set to ASYNC_EOF.
 *
 * When nread < 0, the buf parameter might not point to a valid buffer;
 * in that case buf.len and buf.base are both set to 0.
 *
 * Note that nread might also be 0, which does *not* indicate an error or
 * eof; it happens when libuv requested a buffer through the alloc callback
 * but then decided that it didn't need that buffer.
 */
int async_read_start(async_stream_t*, async_alloc_cb alloc_cb, async_read_cb read_cb);

int async_read_stop(async_stream_t*);


/*
 * Write data to stream. Buffers are written in order. Example:
 *
 *   async_buf_t a[] = {
 *     { .base = "1", .len = 1 },
 *     { .base = "2", .len = 1 }
 *   };
 *
 *   async_buf_t b[] = {
 *     { .base = "3", .len = 1 },
 *     { .base = "4", .len = 1 }
 *   };
 *
 *   async_write_t req1;
 *   async_write_t req2;
 *
 *   // writes "1234"
 *   async_write(&req1, stream, a, 2);
 *   async_write(&req2, stream, b, 2);
 *
 */
int async_write(async_write_t* req, async_stream_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb);

/*
 * Extended write function for sending handles over a pipe. The pipe must be
 * initialized with ipc == 1.
 * send_handle must be a TCP socket or pipe, which is a server or a connection
 * (listening or connected state).  Bound sockets or pipes will be assumed to
 * be servers.
 */
int async_write2(async_write_t* req, async_stream_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_stream_t* send_handle, async_write_cb cb);

/*
 * Same as `async_write()`, but won't queue write request if it can't be completed
 * immediately.
 * Will return either:
 * - >= 0: number of bytes written (can be less than the supplied buffer size)
 * - < 0: negative error code
 */
int async_try_write(async_stream_t* handle, const async_buf_t bufs[], uint32_t nbufs);

/* async_write_t is a subclass of async_req_t */
struct async_write_s
{
    ASYNC_REQ_FIELDS
    async_write_cb cb;
    async_stream_t* send_handle;
    async_stream_t* handle;
    int ipc_header;
    async_buf_t write_buffer;
    HANDLE event_handle;
    HANDLE wait_handle;
};


/*
 * Used to determine whether a stream is readable or writable.
 */
int async_is_readable(const async_stream_t* handle);
int async_is_writable(const async_stream_t* handle);


/*
 * Enable or disable blocking mode for a stream.
 *
 * When blocking mode is enabled all writes complete synchronously. The
 * interface remains unchanged otherwise, e.g. completion or failure of the
 * operation will still be reported through a callback which is made
 * asychronously.
 *
 * Relying too much on this API is not recommended. It is likely to change
 * significantly in the future.
 *
 * Currently this only works on Windows and only for async_pipe_t handles.
 *
 * Also libuv currently makes no ordering guarantee when the blocking mode
 * is changed after write requests have already been submitted. Therefore it is
 * recommended to set the blocking mode immediately after opening or creating
 * the stream.
 */
int async_stream_set_blocking(async_stream_t* handle, int blocking);


/*
 * Used to determine whether a stream is closing or closed.
 *
 * N.B. is only valid between the initialization of the handle
 *      and the arrival of the close callback, and cannot be used
 *      to validate the handle.
 */
int async_is_closing(const async_handle_t* handle);


/*
 * async_tcp_t is a subclass of async_stream_t
 *
 * Represents a TCP stream or TCP server.
 */
struct async_tcp_s
{
    ASYNC_HANDLE_FIELDS
    ASYNC_STREAM_FIELDS
    SOCKET socket;
    int delayed_error;
    union {
        struct { async_tcp_server_fields };
        struct { async_tcp_connection_fields };
    };
};

int async_tcp_init(async_loop_t*, async_tcp_t* handle);

/*
 * Opens an existing file descriptor or SOCKET as a tcp handle.
 */
int async_tcp_open(async_tcp_t* handle, async_os_sock_t sock);

/* Enable/disable Nagle's algorithm. */
int async_tcp_nodelay(async_tcp_t* handle, int enable);

/*
 * Enable/disable TCP keep-alive.
 *
 * `delay` is the initial delay in seconds, ignored when `enable` is zero.
 */
int async_tcp_keepalive(async_tcp_t* handle, int enable, uint32_t delay);

/*
 * Enable/disable simultaneous asynchronous accept requests that are
 * queued by the operating system when listening for new tcp connections.
 * This setting is used to tune a tcp server for the desired performance.
 * Having simultaneous accepts can significantly improve the rate of
 * accepting connections (which is why it is enabled by default) but
 * may lead to uneven load distribution in multi-process setups.
 */
int async_tcp_simultaneous_accepts(async_tcp_t* handle, int enable);

enum async_tcp_flags
{
  /* Used with async_tcp_bind, when an IPv6 address is used */
  ASYNC_TCP_IPV6ONLY = 1
};

/*
 * Bind the handle to an address and port.  `addr` should point to an
 * initialized struct sockaddr_in or struct sockaddr_in6.
 *
 * When the port is already taken, you can expect to see an ASYNC_EADDRINUSE
 * error from either async_tcp_bind(), async_listen() or async_tcp_connect().
 *
 * That is, a successful call to async_tcp_bind() does not guarantee that
 * the call to async_listen() or async_tcp_connect() will succeed as well.
 */
int async_tcp_bind(async_tcp_t* handle, const struct sockaddr* addr, uint32_t flags);
int async_tcp_getsockname(const async_tcp_t* handle, struct sockaddr* name, int* namelen);
int async_tcp_getpeername(const async_tcp_t* handle, struct sockaddr* name, int* namelen);

/*
 * Establish an IPv4 or IPv6 TCP connection.  Provide an initialized TCP handle
 * and an uninitialized async_connect_t*.  `addr` should point to an initialized
 * struct sockaddr_in or struct sockaddr_in6.
 *
 * The callback is made when the connection has been established or when a
 * connection error happened.
 */
int async_tcp_connect(async_connect_t* req, async_tcp_t* handle, const struct sockaddr* addr, async_connect_cb cb);

/* async_connect_t is a subclass of async_req_t */
struct async_connect_s
{
    ASYNC_REQ_FIELDS
    async_connect_cb cb;
    async_stream_t* handle;
};


/*
 * UDP support.
 */

enum async_udp_flags
{
  /* Disables dual stack mode. */
  ASYNC_UDP_IPV6ONLY = 1,
  /*
   * Indicates message was truncated because read buffer was too small. The
   * remainder was discarded by the OS. Used in async_udp_recv_cb.
   */
  ASYNC_UDP_PARTIAL = 2,
  /* Indicates if SO_REUSEADDR will be set when binding the handle.
   * This sets the SO_REUSEPORT socket flag on the BSDs and OS X. On other
   * UNIX platforms, it sets the SO_REUSEADDR flag.  What that means is that
   * multiple threads or processes can bind to the same address without error
   * (provided they all set the flag) but only the last one to bind will receive
   * any traffic, in effect "stealing" the port from the previous listener.
   */
  ASYNC_UDP_REUSEADDR = 4
};

/*
 * Called after async_udp_send(). status 0 indicates
 * success otherwise error.
 */
typedef void (*async_udp_send_cb)(async_udp_send_t* req, int status);

/*
 * Callback that is invoked when a new UDP datagram is received.
 *
 *  handle  UDP handle.
 *  nread   Number of bytes that have been received.
 *          0 if there is no more data to read. You may
 *          discard or repurpose the read buffer.
 *          < 0 if a transmission error was detected.
 *  buf     async_buf_t with the received data.
 *  addr    struct sockaddr* containing the address of the sender.
 *          Can be NULL. Valid for the duration of the callback only.
 *  flags   One or more OR'ed ASYNC_UDP_* constants.
 *          Right now only ASYNC_UDP_PARTIAL is used.
 */
typedef void (*async_udp_recv_cb)(async_udp_t* handle, ssize_t nread, const async_buf_t* buf, const struct sockaddr* addr, unsigned flags);

/* async_udp_t is a subclass of async_handle_t */
struct async_udp_s
{
    ASYNC_HANDLE_FIELDS
    /* read-only */
    /*
    * Number of bytes queued for sending. This field strictly shows how much
    * information is currently queued.
    */
    size_t send_queue_size;
    /*
    * Number of send requests currently in the queue awaiting to be processed.
    */
    size_t send_queue_count;
    SOCKET socket;
    uint32_t reqs_pending;
    int activecnt;
    async_req_t recv_req;
    async_buf_t recv_buffer;
    struct sockaddr_storage recv_from;
    int recv_from_len;
    async_udp_recv_cb recv_cb;
    async_alloc_cb alloc_cb;
    LPFN_WSARECV func_wsarecv;
    LPFN_WSARECVFROM func_wsarecvfrom;
};

/* async_udp_send_t is a subclass of async_req_t */
struct async_udp_send_s
{
    ASYNC_REQ_FIELDS
    async_udp_t* handle;
    async_udp_send_cb cb;
};

/*
 * Initialize a new UDP handle. The actual socket is created lazily.
 * Returns 0 on success.
 */
int async_udp_init(async_loop_t*, async_udp_t* handle);

/*
 * Opens an existing file descriptor or SOCKET as a udp handle.
 *
 * Unix only:
 *  The only requirement of the sock argument is that it follows the
 *  datagram contract (works in unconnected mode, supports sendmsg()/recvmsg(),
 *  etc.). In other words, other datagram-type sockets like raw sockets or
 *  netlink sockets can also be passed to this function.
 *
 * This sets the SO_REUSEPORT socket flag on the BSDs and OS X. On other
 * UNIX platforms, it sets the SO_REUSEADDR flag.  What that means is that
 * multiple threads or processes can bind to the same address without error
 * (provided they all set the flag) but only the last one to bind will receive
 * any traffic, in effect "stealing" the port from the previous listener.
 * This behavior is something of an anomaly and may be replaced by an explicit
 * opt-in mechanism in future versions of libuv.
 */
int async_udp_open(async_udp_t* handle, async_os_sock_t sock);

/*
 * Bind to an IP address and port.
 *
 * Arguments:
 *  handle    UDP handle. Should have been initialized with `async_udp_init`.
 *  addr      struct sockaddr_in or struct sockaddr_in6 with the address and
 *            port to bind to.
 *  flags     Indicate how the socket will be bound, ASYNC_UDP_IPV6ONLY and
 *            ASYNC_UDP_REUSEADDR are supported.
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_bind(async_udp_t* handle, const struct sockaddr* addr, uint32_t flags);

int async_udp_getsockname(const async_udp_t* handle, struct sockaddr* name, int* namelen);

/*
 * Set membership for a multicast address
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  multicast_addr      multicast address to set membership for
 *  interface_addr      interface address
 *  membership          Should be ASYNC_JOIN_GROUP or ASYNC_LEAVE_GROUP
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_membership(async_udp_t* handle, const char* multicast_addr, const char* interface_addr, async_membership membership);

/*
 * Set IP multicast loop flag. Makes multicast packets loop back to
 * local sockets.
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  on                  1 for on, 0 for off
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_multicast_loop(async_udp_t* handle, int on);

/*
 * Set the multicast ttl
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  ttl                 1 through 255
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_multicast_ttl(async_udp_t* handle, int ttl);


/*
 * Set the multicast interface to send on
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  interface_addr      interface address
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_multicast_interface(async_udp_t* handle, const char* interface_addr);

/*
 * Set broadcast on or off
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  on                  1 for on, 0 for off
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_broadcast(async_udp_t* handle, int on);

/*
 * Set the time to live
 *
 * Arguments:
 *  handle              UDP handle. Should have been initialized with
 *                      `async_udp_init`.
 *  ttl                 1 through 255
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_set_ttl(async_udp_t* handle, int ttl);

/*
 * Send data. If the socket has not previously been bound with `async_udp_bind,`
 * it is bound to 0.0.0.0 (the "all interfaces" address) and a random
 * port number.
 *
 * Arguments:
 *  req       UDP request handle. Need not be initialized.
 *  handle    UDP handle. Should have been initialized with `async_udp_init`.
 *  bufs      List of buffers to send.
 *  nbufs     Number of buffers in `bufs`.
 *  addr      struct sockaddr_in or struct sockaddr_in6 with the address and
 *            port of the remote peer.
 *  send_cb   Callback to invoke when the data has been sent out.
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_send(async_udp_send_t* req, async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr, async_udp_send_cb send_cb);

/*
* Same as `uv_udp_send()`, but won't queue a send request if it can't be completed
* immediately.
* Will return either:
* - >= 0: number of bytes written (can be less than the supplied buffer size if the
*         packet is truncated)
* - < 0: negative error code (UV_EAGAIN is returned when the message can't be sent
*        immediately)
*/
int async_udp_try_send(async_udp_t* handle, const async_buf_t bufs[], uint32_t nbufs, const struct sockaddr* addr);

/*
 * Receive data. If the socket has not previously been bound with `async_udp_bind`
 * it is bound to 0.0.0.0 (the "all interfaces" address) and a random
 * port number.
 *
 * Arguments:
 *  handle    UDP handle. Should have been initialized with `async_udp_init`.
 *  alloc_cb  Callback to invoke when temporary storage is needed.
 *  recv_cb   Callback to invoke with received data.
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 *
 * Note: The receive callback will be called with nread == 0
 *       and addr == NULL when the there was nothing to read and
 *       with nread == 0 and addr != NULL when an empty udp
 *       packet is received.
 */
int async_udp_recv_start(async_udp_t* handle, async_alloc_cb alloc_cb, async_udp_recv_cb recv_cb);

/*
 * Stop listening for incoming datagrams.
 *
 * Arguments:
 *  handle    UDP handle. Should have been initialized with `async_udp_init`.
 *
 * Returns:
 *  0 on success, or an error code < 0 on failure.
 */
int async_udp_recv_stop(async_udp_t* handle);

/*
 * async_pipe_t is a subclass of async_stream_t
 *
 * Representing a pipe stream or pipe server. On Windows this is a Named
 * Pipe. On Unix this is a UNIX domain socket.
 */
struct async_pipe_s
{
    ASYNC_HANDLE_FIELDS
    ASYNC_STREAM_FIELDS
    int ipc; /* non-zero if this pipe is used for passing handles */
    HANDLE handle;
    wchar_t* name;
    union {
        struct { async_pipe_server_fields };
        struct { async_pipe_connection_fields };
    };
};

// Initialize a pipe. The last argument is a boolean to indicate if this pipe will be used for handle passing between processes.
int async_pipe_init(async_loop_t*, async_pipe_t* handle, int ipc);

/*
 * Opens an existing file descriptor or HANDLE as a pipe.
 */
int async_pipe_open(async_pipe_t*, HANDLE hFile);

/*
 * Bind the pipe to a file path (UNIX) or a name (Windows.)
 *
 * Paths on UNIX get truncated to `sizeof(sockaddr_un.sun_path)` bytes,
 * typically between 92 and 108 bytes.
 */
int async_pipe_bind(async_pipe_t* handle, const char* name);

/*
 * Connect to the UNIX domain socket or the named pipe.
 *
 * Paths on UNIX get truncated to `sizeof(sockaddr_un.sun_path)` bytes,
 * typically between 92 and 108 bytes.
 */
void async_pipe_connect(async_connect_t* req, async_pipe_t* handle, const char* name, async_connect_cb cb);

/*
 * Get the name of the UNIX domain socket or the named pipe.
 *
 * A preallocated buffer must be provided. The len parameter holds the
 * length of the buffer and it's set to the number of bytes written to the
 * buffer on output. If the buffer is not big enough ASYNC_ENOBUFS will be
 * returned and len will contain the required size.
 */
int async_pipe_getsockname(const async_pipe_t* handle, char* buf, size_t* len);

/*
 * This setting applies to Windows only.
 * Set the number of pending pipe instance handles when the pipe server
 * is waiting for connections.
 */
void async_pipe_pending_instances(async_pipe_t* handle, int count);

/*
 * Used to receive handles over ipc pipes.
 *
 * First - call `async_pipe_pending_count`, if it is > 0 - initialize handle
 * using type, returned by `async_pipe_pending_type` and call
 * `async_accept(pipe, handle)`.
 */
int async_pipe_pending_count(async_pipe_t* handle);
async_handle_type async_pipe_pending_type(async_pipe_t* handle);

/*
 * async_poll_t is a subclass of async_handle_t.
 *
 * The async_poll watcher is used to watch file descriptors for readability and
 * writability, similar to the purpose of poll(2).
 *
 * The purpose of async_poll is to enable integrating external libraries that
 * rely on the event loop to signal it about the socket status changes, like
 * c-ares or libssh2. Using async_poll_t for any other purpose is not recommended;
 * async_tcp_t, async_udp_t, etc. provide an implementation that is much faster and
 * more scalable than what can be achieved with async_poll_t, especially on
 * Windows.
 *
 * It is possible that async_poll occasionally signals that a file descriptor is
 * readable or writable even when it isn't. The user should therefore always
 * be prepared to handle EAGAIN or equivalent when it attempts to read from or
 * write to the fd.
 *
 * It is not okay to have multiple active async_poll watchers for the same socket.
 * This can cause libuv to busyloop or otherwise malfunction.
 *
 * The user should not close a file descriptor while it is being polled by an
 * active async_poll watcher. This can cause the poll watcher to report an error,
 * but it might also start polling another socket. However the fd can be safely
 * closed immediately after a call to async_poll_stop() or async_close().
 *
 * On windows only sockets can be polled with async_poll. On unix any file
 * descriptor that would be accepted by poll(2) can be used with async_poll.
 */
struct async_poll_s
{
    ASYNC_HANDLE_FIELDS
    async_poll_cb poll_cb;
    SOCKET socket;
    /* Used in fast mode */
    SOCKET peer_socket;
    AFD_POLL_INFO afd_poll_info_1;
    AFD_POLL_INFO afd_poll_info_2;
    /* Used in fast and slow mode. */
    async_req_t poll_req_1;
    async_req_t poll_req_2;
    uint8_t submitted_events_1;
    uint8_t submitted_events_2;
    uint8_t mask_events_1;
    uint8_t mask_events_2;
    uint8_t events;
};

enum async_poll_event
{
    ASYNC_READABLE = 1,
    ASYNC_WRITABLE = 2
};

/* Initialize the poll watcher using a file descriptor. */
int async_poll_init(async_loop_t* loop, async_poll_t* handle, HANDLE hFile);

/* Initialize the poll watcher using a socket descriptor. On unix this is */
/* identical to async_poll_init. On windows it takes a SOCKET handle. */
int async_poll_init_socket(async_loop_t* loop, async_poll_t* handle, async_os_sock_t socket);

/*
 * Starts polling the file descriptor. `events` is a bitmask consisting made up
 * of ASYNC_READABLE and ASYNC_WRITABLE. As soon as an event is detected the callback
 * will be called with `status` set to 0, and the detected events set en the
 * `events` field.
 *
 * If an error happens while polling status, `status` < 0 and corresponds
 * with one of the ASYNC_E* error codes. The user should not close the socket
 * while async_poll is active. If the user does that anyway, the callback *may*
 * be called reporting an error status, but this is not guaranteed.
 *
 * Calling async_poll_start on an async_poll watcher that is already active is fine.
 * Doing so will update the events mask that is being watched for.
 */
int async_poll_start(async_poll_t* handle, int events, async_poll_cb cb);

/* Stops polling the file descriptor. */
int async_poll_stop(async_poll_t* handle);


/*
 * async_prepare_t is a subclass of async_handle_t.
 *
 * Every active prepare handle gets its callback called exactly once per loop
 * iteration, just before the system blocks to wait for completed i/o.
 */
struct async_prepare_s
{
    ASYNC_HANDLE_FIELDS
    async_prepare_t* prepare_prev;
    async_prepare_t* prepare_next;
    async_prepare_cb prepare_cb;

};

int async_prepare_init(async_loop_t*, async_prepare_t* prepare);

int async_prepare_start(async_prepare_t* prepare, async_prepare_cb cb);

int async_prepare_stop(async_prepare_t* prepare);


/*
 * async_check_t is a subclass of async_handle_t.
 *
 * Every active check handle gets its callback called exactly once per loop
 * iteration, just after the system returns from blocking.
 */
struct async_check_s
{
    ASYNC_HANDLE_FIELDS
    async_check_t* check_prev;
    async_check_t* check_next;
    async_check_cb check_cb;

};

int async_check_init(async_loop_t*, async_check_t* check);

int async_check_start(async_check_t* check, async_check_cb cb);

int async_check_stop(async_check_t* check);


/*
 * async_idle_t is a subclass of async_handle_t.
 *
 * Every active idle handle gets its callback called repeatedly until it is
 * stopped. This happens after all other types of callbacks are processed.
 * When there are multiple "idle" handles active, their callbacks are called
 * in turn.
 */
struct async_idle_s
{
    ASYNC_HANDLE_FIELDS
    async_idle_t* idle_prev;
    async_idle_t* idle_next;
    async_idle_cb idle_cb;

};

int async_idle_init(async_loop_t*, async_idle_t* idle);

int async_idle_start(async_idle_t* idle, async_idle_cb cb);

int async_idle_stop(async_idle_t* idle);


/*
 * async_async_t is a subclass of async_handle_t.
 *
 * async_async_send wakes up the event loop and calls the async handle's callback.
 * There is no guarantee that every async_async_send call leads to exactly one
 * invocation of the callback; the only guarantee is that the callback function
 * is called at least once after the call to async_send. Unlike all other
 * libuv functions, async_async_send can be called from another thread.
 */
struct async_async_s
{
    ASYNC_HANDLE_FIELDS
    struct async_req_s async_req;
    async_async_cb async_cb;
    /* char to avoid alignment issues */
    char volatile async_sent;
};

/*
 * Initialize the async_async_t handle. A NULL callback is allowed.
 *
 * Note that async_async_init(), unlike other libuv functions, immediately
 * starts the handle. To stop the handle again, close it with async_close().
 */
void async_async_init(async_loop_t*, async_async_t* async, async_async_cb async_cb);

/*
 * This can be called from other threads to wake up a libuv thread.
 */
int async_async_send(async_async_t* async);


/*
 * async_timer_t is a subclass of async_handle_t.
 *
 * Used to get woken up at a specified time in the future.
 */
struct async_timer_s
{
    ASYNC_HANDLE_FIELDS
    RB_ENTRY(async_timer_s) tree_entry;
    uint64_t due;
    uint64_t repeat;
    uint64_t start_id;
    async_timer_cb timer_cb;
};

void async_timer_init(async_loop_t*, async_timer_t* handle);

/*
 * Start the timer. `timeout` and `repeat` are in milliseconds.
 *
 * If timeout is zero, the callback fires on the next tick of the event loop.
 *
 * If repeat is non-zero, the callback fires first after timeout milliseconds
 * and then repeatedly after repeat milliseconds.
 */
void async_timer_start(async_timer_t* handle, async_timer_cb cb, uint64_t timeout, uint64_t repeat);

int async_timer_stop(async_timer_t* handle);

/*
 * Stop the timer, and if it is repeating restart it using the repeat value
 * as the timeout. If the timer has never been started before it returns
 * ASYNC_EINVAL.
 */
int async_timer_again(async_timer_t* handle);

/*
 * Set the repeat value in milliseconds. Note that if the repeat value is set
 * from a timer callback it does not immediately take effect. If the timer was
 * non-repeating before, it will have been stopped. If it was repeating, then
 * the old repeat value will have been used to schedule the next timeout.
 */
void async_timer_set_repeat(async_timer_t* handle, uint64_t repeat);

uint64_t async_timer_get_repeat(const async_timer_t* handle);


/*
 * async_getaddrinfo_t is a subclass of async_req_t
 *
 * Request object for async_getaddrinfo.
 */
struct async_getaddrinfo_s
{
    ASYNC_REQ_FIELDS
    /* read-only */
    async_loop_t* loop;
    struct async__work work_req;
    async_getaddrinfo_cb getaddrinfo_cb;
    void* alloc;
    wchar_t* node;
    wchar_t* service;
    struct addrinfoW* hints;
    struct addrinfoW* res;
    int retcode;
};


/*
 * Asynchronous getaddrinfo(3).
 *
 * Either node or service may be NULL but not both.
 *
 * hints is a pointer to a struct addrinfo with additional address type
 * constraints, or NULL. Consult `man -s 3 getaddrinfo` for details.
 *
 * Returns 0 on success or an error code < 0 on failure.
 *
 * If successful, your callback gets called sometime in the future with the
 * lookup result, which is either:
 *
 *  a) err == 0, the res argument points to a valid struct addrinfo, or
 *  b) err < 0, the res argument is NULL. See the ASYNC_EAI_* constants.
 *
 * Call async_freeaddrinfo() to memory_free the addrinfo structure.
 */
int async_getaddrinfo(async_loop_t* loop, async_getaddrinfo_t* req, async_getaddrinfo_cb getaddrinfo_cb, const char* node, const char* service, const struct addrinfo* hints);

/*
 * Free the struct addrinfo. Passing NULL is allowed and is a no-op.
 */
void async_freeaddrinfo(struct addrinfo* ai);


/*
* async_getnameinfo_t is a subclass of async_req_t
*
* Request object for async_getnameinfo.
*/
struct async_getnameinfo_s
{
    ASYNC_REQ_FIELDS
    /* read-only */
    async_loop_t* loop;
    struct async__work work_req;
    async_getnameinfo_cb getnameinfo_cb;
    struct sockaddr_storage storage;
    int flags;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int retcode;
};

/*
 * Asynchronous getnameinfo.
 *
 * Returns 0 on success or an error code < 0 on failure.
 *
 * If successful, your callback gets called sometime in the future with the
 * lookup result.
 */
int async_getnameinfo(async_loop_t* loop, async_getnameinfo_t* req, async_getnameinfo_cb getnameinfo_cb, const struct sockaddr* addr, int flags);

/*
 * async_work_t is a subclass of async_req_t
 */
struct async_work_s
{
    ASYNC_REQ_FIELDS
    async_loop_t* loop;
    async_work_cb work_cb;
    async_after_work_cb after_work_cb;
    struct async__work work_req;
};

/* Queues a work request to execute asynchronously on the thread pool. */
int async_queue_work(async_loop_t* loop, async_work_t* req, async_work_cb work_cb, async_after_work_cb after_work_cb);

/* Cancel a pending request. Fails if the request is executing or has finished
 * executing.
 *
 * Returns 0 on success, or an error code < 0 on failure.
 *
 * Only cancellation of async_fs_t, async_getaddrinfo_t and async_work_t requests is
 * currently supported.
 *
 * Cancelled requests have their callbacks invoked some time in the future.
 * It's _not_ safe to memory_free the memory associated with the request until your
 * callback is called.
 *
 * Here is how cancellation is reported to your callback:
 *
 * - A async_fs_t request has its req->result field set to ASYNC_ECANCELED.
 *
 * - A async_work_t or async_getaddrinfo_t request has its callback invoked with
 *   status == ASYNC_ECANCELED.
 *
 * This function is currently only implemented on UNIX platforms. On Windows,
 * it always returns ASYNC_ENOSYS.
 */
int async_cancel(async_req_t* req);

struct async_interface_address_s
{
    char* name;
    char phys_addr[6];
    int is_internal;
    union {
        struct sockaddr_in address4;
        struct sockaddr_in6 address6;
    } address;
    union {
        struct sockaddr_in netmask4;
        struct sockaddr_in6 netmask6;
    } netmask;
};

char** async_setup_args(int argc, char** argv);
int async_resident_set_memory(size_t* rss);

typedef struct
{
    long tv_sec;
    long tv_usec;
} async_timeval_t;

typedef struct {
    async_timeval_t ru_utime; /* user CPU time used */
    async_timeval_t ru_stime; /* system CPU time used */
    uint64_t ru_maxrss;    /* maximum resident set size */
    uint64_t ru_ixrss;     /* integral shared memory size */
    uint64_t ru_idrss;     /* integral unshared data size */
    uint64_t ru_isrss;     /* integral unshared stack size */
    uint64_t ru_minflt;    /* page reclaims (soft page faults) */
    uint64_t ru_majflt;    /* page faults (hard page faults) */
    uint64_t ru_nswap;     /* swaps */
    uint64_t ru_inblock;   /* block input operations */
    uint64_t ru_oublock;   /* block output operations */
    uint64_t ru_msgsnd;    /* IPC messages sent */
    uint64_t ru_msgrcv;    /* IPC messages received */
    uint64_t ru_nsignals;  /* signals received */
    uint64_t ru_nvcsw;     /* voluntary context switches */
    uint64_t ru_nivcsw;    /* involuntary context switches */
} async_rusage_t;

/*
 * Get information about OS resource utilization for the current process.
 * Please note that not all async_rusage_t struct fields will be filled on Windows.
 */
int async_getrusage(async_rusage_t* rusage);

/*
 * This allocates addresses array, and sets count.  The array
 * is freed using async_free_interface_addresses().
 */
int async_interface_addresses(async_interface_address_t** addresses, int* count);
void async_free_interface_addresses(async_interface_address_t* addresses, int count);


/*
 * File System Methods.
 *
 * The async_fs_* functions execute a blocking system call asynchronously (in a
 * thread pool) and call the specified callback in the specified loop after
 * completion. If the user gives NULL as the callback the blocking system
 * call will be called synchronously. req should be a pointer to an
 * uninitialized async_fs_t object.
 *
 * async_fs_req_cleanup() must be called after completion of the async_fs_
 * function to memory_free any internal memory allocations associated with the
 * request.
 */

typedef enum {
  ASYNC_FS_UNKNOWN = -1,
  ASYNC_FS_CUSTOM,
  ASYNC_FS_OPEN,
  ASYNC_FS_CLOSE,
  ASYNC_FS_READ,
  ASYNC_FS_WRITE,
  ASYNC_FS_STAT,
  ASYNC_FS_LSTAT,
  ASYNC_FS_FSTAT,
  ASYNC_FS_FTRUNCATE,
  ASYNC_FS_UTIME,
  ASYNC_FS_FUTIME,
  ASYNC_FS_FSYNC,
  ASYNC_FS_UNLINK,
  ASYNC_FS_RMDIR,
  ASYNC_FS_MKDIR,
  ASYNC_FS_RENAME,
  ASYNC_FS_READDIR,
  ASYNC_FS_LINK,
  ASYNC_FS_SYMLINK,
  ASYNC_FS_READLINK,
} async_fs_type;

/* async_fs_t is a subclass of async_req_t */
struct async_fs_s
{
    ASYNC_REQ_FIELDS
    async_fs_type fs_type;
    async_loop_t* loop;
    async_fs_cb cb;
    HANDLE hFile;
    ssize_t result;
    void* ptr;
    const wchar_t* path;
    async_stat_t statbuf;  /* Stores the result of async_fs_stat and async_fs_fstat. */

    struct async__work work_req;
    DWORD flags;
    DWORD sys_errno_;
    union {
        int fd;
    };
    union {
        struct {
            DWORD access;
            DWORD disposition;
            DWORD attributes;
            wchar_t* new_pathw;
            int fd_out;
            uint32_t nbufs;
            async_buf_t* bufs;
            int64_t offset;
            async_buf_t bufsml[4];
        };
        struct {
            double atime;
            double mtime;
        };
    };
};

void async_fs_req_cleanup(async_fs_t* req);
int async_fs_close(async_loop_t* loop, async_fs_t* req, HANDLE hFile, async_fs_cb cb);
int async_fs_open(async_loop_t* loop, async_fs_t* req, const wchar_t* path, DWORD access, DWORD disposition, DWORD attributes, async_fs_cb cb);
int async_fs_read(async_loop_t* loop, async_fs_t* req, HANDLE hFile, const async_buf_t bufs[], uint32_t nbufs, int64_t offset, async_fs_cb cb);
int async_fs_unlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_write(async_loop_t* loop, async_fs_t* req, HANDLE hFile, const async_buf_t bufs[], uint32_t nbufs, int64_t offset, async_fs_cb cb);
int async_fs_mkdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_rmdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_readdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_stat(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_fstat(async_loop_t* loop, async_fs_t* req, async_file file, async_fs_cb cb);
int async_fs_rename(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, async_fs_cb cb);
int async_fs_fsync(async_loop_t* loop, async_fs_t* req, HANDLE hFile, async_fs_cb cb);
int async_fs_ftruncate(async_loop_t* loop, async_fs_t* req, HANDLE hFile, int64_t offset, async_fs_cb cb);
int async_fs_utime(async_loop_t* loop, async_fs_t* req, const wchar_t* path, double atime, double mtime, async_fs_cb cb);
int async_fs_futime(async_loop_t* loop, async_fs_t* req, HANDLE hFile, double atime, double mtime, async_fs_cb cb);
int async_fs_lstat(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);
int async_fs_link(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, async_fs_cb cb);

/*
 * This flag can be used with async_fs_symlink on Windows
 * to specify whether path argument points to a directory.
 */
#define ASYNC_FS_SYMLINK_DIR          0x0001

/*
 * This flag can be used with async_fs_symlink on Windows
 * to specify whether the symlink is to be created using junction points.
 */
#define ASYNC_FS_SYMLINK_JUNCTION     0x0002

int async_fs_symlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, int flags, async_fs_cb cb);
int async_fs_readlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb);

enum async_fs_event {
  ASYNC_RENAME = 1,
  ASYNC_CHANGE = 2
};


struct async_fs_event_s
{
    ASYNC_HANDLE_FIELDS
    /* private */
    wchar_t* path;

    struct async_fs_event_req_s {
        ASYNC_REQ_FIELDS
    } req;
    HANDLE dir_handle;
    int req_pending;
    async_fs_event_cb cb;
    wchar_t* filew;
    wchar_t* short_filew;
    wchar_t* dirw;
    char* buffer;
};


/*
 * async_fs_stat() based polling file watcher.
 */
struct async_fs_poll_s
{
    ASYNC_HANDLE_FIELDS
    /* Private, don't touch. */
    void* poll_ctx;
};

int async_fs_poll_init(async_loop_t* loop, async_fs_poll_t* handle);

/*
 * Check the file at `path` for changes every `interval` milliseconds.
 *
 * Your callback is invoked with `status < 0` if `path` does not exist
 * or is inaccessible. The watcher is *not* stopped but your callback is
 * not called again until something changes (e.g. when the file is created
 * or the error reason changes).
 *
 * When `status == 0`, your callback receives pointers to the old and new
 * `async_stat_t` structs. They are valid for the duration of the callback
 * only!
 *
 * For maximum portability, use multi-second intervals. Sub-second intervals
 * will not detect all changes on many file systems.
 */
int async_fs_poll_start(async_fs_poll_t* handle, async_fs_poll_cb poll_cb, const char* path, uint32_t interval);
int async_fs_poll_stop(async_fs_poll_t* handle);

/*
 * Get the path being monitored by the handle. The buffer must be preallocated
 * by the user. Returns 0 on success or an error code < 0 in case of failure.
 * On sucess, `buf` will contain the path and `len` its length. If the buffer
 * is not big enough ASYNC_ENOBUFS will be returned and len will be set to the
 * required size.
 */
int async_fs_poll_getpath(async_fs_poll_t* handle, wchar_t* buf, size_t* len);




/*
 * Gets load average.
 * See: http://en.wikipedia.org/wiki/Load_(computing)
 * Returns [0,0,0] on Windows.
 */
void async_loadavg(double avg[3]);


/*
 * Flags to be passed to async_fs_event_start.
 */
enum async_fs_event_flags {
  /*
   * By default, if the fs event watcher is given a directory name, we will
   * watch for all events in that directory. This flags overrides this behavior
   * and makes fs_event report only changes to the directory entry itself. This
   * flag does not affect individual files watched.
   * This flag is currently not implemented yet on any backend.
   */
  ASYNC_FS_EVENT_WATCH_ENTRY = 1,

  /*
   * By default async_fs_event will try to use a kernel interface such as inotify
   * or kqueue to detect events. This may not work on remote filesystems such
   * as NFS mounts. This flag makes fs_event fall back to calling stat() on a
   * regular interval.
   * This flag is currently not implemented yet on any backend.
   */
  ASYNC_FS_EVENT_STAT = 2,

  /*
   * By default, event watcher, when watching directory, is not registering
   * (is ignoring) changes in it's subdirectories.
   * This flag will override this behaviour on platforms that support it.
   */
  ASYNC_FS_EVENT_RECURSIVE = 4
};


int async_fs_event_init(async_loop_t* loop, async_fs_event_t* handle);

int async_fs_event_start(async_fs_event_t* handle, async_fs_event_cb cb, const wchar_t* path, uint32_t flags);

int async_fs_event_stop(async_fs_event_t* handle);

/*
 * Get the path being monitored by the handle. The buffer must be preallocated
 * by the user. Returns 0 on success or an error code < 0 in case of failure.
 * On sucess, `buf` will contain the path and `len` its length. If the buffer
 * is not big enough ASYNC_ENOBUFS will be returned and len will be set to the
 * required size.
 */
int async_fs_event_getpath(async_fs_event_t* handle, wchar_t* buf, size_t* len);


/* Utility */

/* Convert string ip addresses to binary structures */
int async_ip4_addr(const char* ip, int port, struct sockaddr_in* addr);
int async_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr);

/* Convert binary addresses to strings */
int async_ip4_name(const struct sockaddr_in* src, char* dst, size_t size);
int async_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size);

/* Cross-platform IPv6-capable implementation of the 'standard' inet_ntop */
/* and inet_pton functions. On success they return 0. If an error */
/* the target of the `dst` pointer is unmodified. */
int async_inet_ntop(int af, const void* src, char* dst, size_t size);
int async_inet_pton(int af, const char* src, void* dst);

/* Gets the executable path */
int async_exepath(char* buffer, size_t* size);

/* Gets the current working directory */
int async_cwd(char* buffer, size_t* size);

/* Changes the current working directory */
int async_chdir(const char* dir);

/* Gets memory info in bytes */
uint64_t async_get_free_memory(void);
uint64_t async_get_total_memory(void);

/*
 * Disables inheritance for file descriptors / handles that this process
 * inherited from its parent. The effect is that child processes spawned by
 * this process don't accidentally inherit these handles.
 *
 * It is recommended to call this function as early in your program as possible,
 * before the inherited file descriptors can be closed or duplicated.
 *
 * Note that this function works on a best-effort basis: there is no guarantee
 * that libuv can discover all file descriptors that were inherited. In general
 * it does a better job on Windows than it does on unix.
 */
void async_disable_stdio_inheritance(void);

/*
 * The mutex functions return 0 on success or an error code < 0 (unless the return type is void, of course).
 */
void mutex_init(mutex_t* handle);
void mutex_destroy(mutex_t* handle);
void mutex_lock(mutex_t* handle);
int mutex_trylock(mutex_t* handle);
void mutex_unlock(mutex_t* handle);

/*
 * Same goes for the read/write lock functions.
 */
void async_rwlock_init(async_rwlock_t* rwlock);
void async_rwlock_destroy(async_rwlock_t* rwlock);
void async_rwlock_rdlock(async_rwlock_t* rwlock);
int async_rwlock_tryrdlock(async_rwlock_t* rwlock);
void async_rwlock_rdunlock(async_rwlock_t* rwlock);
void async_rwlock_wrlock(async_rwlock_t* rwlock);
int async_rwlock_trywrlock(async_rwlock_t* rwlock);
void async_rwlock_wrunlock(async_rwlock_t* rwlock);

/*
 * Same goes for the semaphore functions.
 */
int async_sem_init(async_sem_t* sem, uint32_t value);
void async_sem_destroy(async_sem_t* sem);
void async_sem_post(async_sem_t* sem);
void async_sem_wait(async_sem_t* sem);
int async_sem_trywait(async_sem_t* sem);

/*
 * Same goes for the condition variable functions.
 */
void async_cond_init(async_cond_t* cond);
void async_cond_destroy(async_cond_t* cond);
void async_cond_signal(async_cond_t* cond);
void async_cond_broadcast(async_cond_t* cond);

/*
 * Same goes for the barrier functions.  Note that async_barrier_wait() returns
 * a value > 0 to an arbitrarily chosen "serializer" thread to facilitate
 * cleanup, i.e.:
 *
 *   if (async_barrier_wait(&barrier) > 0)
 *     async_barrier_destroy(&barrier);
 */
int async_barrier_init(async_barrier_t* barrier, uint32_t count);
void async_barrier_destroy(async_barrier_t* barrier);
int async_barrier_wait(async_barrier_t* barrier);

/* Waits on a condition variable without a timeout.
 *
 * Note:
 * 1. callers should be prepared to deal with spurious wakeups.
 */
void async_cond_wait(async_cond_t* cond, mutex_t* mutex);
/* Waits on a condition variable with a timeout in nano seconds.
 * Returns 0 for success or ASYNC_ETIMEDOUT on timeout, It aborts when other
 * errors happen.
 *
 * Note:
 * 1. callers should be prepared to deal with spurious wakeups.
 * 2. the granularity of timeout on Windows is never less than one millisecond.
 * 3. async_cond_timedwait takes a relative timeout, not an absolute time.
 */
int async_cond_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout);

/* Runs a function once and only once. Concurrent calls to async_once() with the
 * same guard will block all callers except one (it's unspecified which one).
 * The guard should be initialized statically with the ASYNC_ONCE_INIT macro.
 */
void async_once(async_once_t* guard, void (*callback)(void));

/* Thread-local storage.  These functions largely follow the semantics of
 * pthread_key_create(), pthread_key_delete(), pthread_getspecific() and
 * pthread_setspecific().
 *
 * Note that the total thread-local storage size may be limited.
 * That is, it may not be possible to create many TLS keys.
 */
int async_key_create(async_key_t* key);
void async_key_delete(async_key_t* key);
void* async_key_get(async_key_t* key);
void async_key_set(async_key_t* key, void* value);

/*
 * Callback that is invoked to initialize thread execution.
 *
 * `arg` is the same value that was passed to async_thread_create().
 */
typedef void (*async_thread_cb)(void* arg);

int async_thread_create(async_thread_t* tid, async_thread_cb entry, void* arg);
unsigned long async_thread_self(void);
int async_thread_join(async_thread_t *tid);

/* The presence of these unions force similar struct layout. */
#define XX(_, name) async_ ## name ## _t name;
union async_any_handle {
  ASYNC_HANDLE_TYPE_MAP(XX)
};

union async_any_req {
  ASYNC_REQ_TYPE_MAP(XX)
};
#undef XX


struct async_loop_s
{
    /* User data - use this for whatever. */
    void* data;
    /* Loop reference counting */
    uint32_t active_handles;
    void* handle_queue[2];
    void* active_reqs[2];
    /* Internal flag to signal loop stop */
    uint32_t stop_flag;
    /* The loop's I/O completion port */
    HANDLE iocp;
    /* The current time according to the event loop. in msecs. */
    uint64_t time;
    /* GetTickCount() result when the event loop time was last updated. */
    DWORD last_tick_count;
    /* Tail of a single-linked circular queue of pending reqs. If the queue */
    /* is empty, tail_ is NULL. If there is only one item, */
    /* tail_->next_req == tail_ */
    async_req_t* pending_reqs_tail;
    /* Head of a single-linked list of closed handles */
    async_handle_t* endgame_handles;
    /* The head of the timers tree */
    struct async_timer_tree_s timers;
    /* Lists of active loop (prepare / check / idle) watchers */
    async_prepare_t* prepare_handles;
    async_check_t* check_handles;
    async_idle_t* idle_handles;
    /* This pointer will refer to the prepare/check/idle handle whose */
    /* callback is scheduled to be called next. This is needed to allow */
    /* safe removal from one of the lists above while that list being */
    /* iterated over. */
    async_prepare_t* next_prepare_handle;
    async_check_t* next_check_handle;
    async_idle_t* next_idle_handle;
    /* This handle holds the peer sockets for the fast variant of async_poll_t */
    SOCKET poll_peer_sockets[ASYNC_MSAFD_PROVIDER_COUNT];
    /* Counter to keep track of active tcp streams */
    uint32_t active_tcp_streams;
    /* Counter to keep track of active udp streams */
    uint32_t active_udp_streams;
    /* Counter to started timer */
    uint64_t timer_counter;
    /* Threadpool */
    void* wq[2];
    mutex_t wq_mutex;
    async_async_t wq_async;
};

#ifdef __cplusplus
}
#endif

#endif // __0LIB_ASYNC_H_
