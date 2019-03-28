#include "zmodule.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

typedef struct async__ipc_queue_item_s async__ipc_queue_item_t;

struct async__ipc_queue_item_s
{
    /*
    * NOTE: It is important for socket_info_ex to be the first field,
    * because we will we assigning it to the pending_ipc_info.socket_info
    */
    async__ipc_socket_info_ex socket_info_ex;
    QUEUE member;
    int tcp_connection;
};

/* A zero-size buffer for use by async_pipe_read */
char async_zero_[] = "";

/* Null async_buf_t */
const async_buf_t async_null_buf_ = { 0, NULL };

/* The timeout that the pipe will wait for the remote end to write data */
/* when the local ends wants to shut it down. */
const int64_t eof_timeout = 50; /* ms */

const int default_pending_pipe_instances = 4;

/* Pipe prefix */
char pipe_prefix[] = "\\\\?\\pipe";
const int pipe_prefix_len = sizeof(pipe_prefix) - 1;

/* IPC protocol flags. */
#define ASYNC_IPC_RAW_DATA       0x0001
#define ASYNC_IPC_TCP_SERVER     0x0002
#define ASYNC_IPC_TCP_CONNECTION 0x0004

/* IPC frame header. */
typedef struct
{
    int flags;
    uint64_t raw_data_length;
} async_ipc_frame_header_t;

/* IPC frame, which contains an imported TCP socket stream. */
typedef struct
{
    async_ipc_frame_header_t header;
    async__ipc_socket_info_ex socket_info_ex;
} async_ipc_frame_async_stream;

void eof_timer_init(async_pipe_t* pipe);
void eof_timer_start(async_pipe_t* pipe);
void eof_timer_stop(async_pipe_t* pipe);
void eof_timer_cb(async_timer_t* timer);
void eof_timer_destroy(async_pipe_t* pipe);
void eof_timer_close_cb(async_handle_t* handle);

void async_unique_pipe_name(char* ptr, char* name, size_t size)
{
    _snprintf(name, size, "\\\\?\\pipe\\uv\\%p-%u", ptr, fn_GetCurrentProcessId());
}

int async_pipe_init(async_loop_t* loop, async_pipe_t* handle, int ipc)
{
    async_stream_init(loop, (async_stream_t*)handle, ASYNC_NAMED_PIPE);

    handle->reqs_pending = 0;
    handle->handle = INVALID_HANDLE_VALUE;
    handle->name = NULL;
    handle->ipc_pid = 0;
    handle->remaining_ipc_rawdata_bytes = 0;
    queue_init(&handle->pending_ipc_info.queue);
    handle->pending_ipc_info.queue_len = 0;
    handle->ipc = ipc;
    handle->non_overlapped_writes_tail = NULL;
    handle->readfile_thread = NULL;

    async_req_init(loop, (async_req_t*) &handle->ipc_header_write_req);

    return 0;
}

void async_pipe_connection_init(async_pipe_t* handle)
{
    async_connection_init((async_stream_t*) handle);
    handle->read_req.data = handle;
    handle->eof_timer = NULL;
    if (fn_CancelSynchronousIo && handle->flags & ASYNC_HANDLE_NON_OVERLAPPED_PIPE) {
        mutex_init(&handle->readfile_mutex);
        handle->flags |= ASYNC_HANDLE_PIPE_READ_CANCELABLE;
    }
}

HANDLE open_named_pipe(const wchar_t* name, DWORD* duplex_flags)
{
    HANDLE pipeHandle;

    /*
    * Assume that we have a duplex pipe first, so attempt to
    * connect with GENERIC_READ | GENERIC_WRITE.
    */
    pipeHandle = fn_CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (pipeHandle != INVALID_HANDLE_VALUE) {
        *duplex_flags = ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE;
        return pipeHandle;
    }

    /*
    * If the pipe is not duplex CreateFileW fails with
    * ERROR_ACCESS_DENIED.  In that case try to connect
    * as a read-only or write-only.
    */
    if (fn_GetLastError() == ERROR_ACCESS_DENIED) {
        pipeHandle = fn_CreateFileW(name, GENERIC_READ | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

        if (pipeHandle != INVALID_HANDLE_VALUE) {
            *duplex_flags = ASYNC_HANDLE_READABLE;
            return pipeHandle;
        }
    }

    if (fn_GetLastError() == ERROR_ACCESS_DENIED) {
        pipeHandle = fn_CreateFileW(name, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

        if (pipeHandle != INVALID_HANDLE_VALUE) {
            *duplex_flags = ASYNC_HANDLE_WRITABLE;
            return pipeHandle;
        }
    }

    return INVALID_HANDLE_VALUE;
}

int async_stdio_pipe_server(async_loop_t* loop, async_pipe_t* handle, DWORD access, char* name, size_t nameSize)
{
    HANDLE pipeHandle;
    int err;
    char* ptr = (char*)handle;

    for (;;) {
        async_unique_pipe_name(ptr, name, nameSize);

        pipeHandle = fn_CreateNamedPipeA(name, access | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, NULL);

        if (pipeHandle != INVALID_HANDLE_VALUE) {
            /* No name collisions.  We're done. */
            break;
        }

        err = fn_GetLastError();
        if (err != ERROR_PIPE_BUSY && err != ERROR_ACCESS_DENIED) {
        goto error;
        }

        /* Pipe name collision.  Increment the pointer and try again. */
        ++ptr;
    }

    if (fn_CreateIoCompletionPort(pipeHandle, loop->iocp, (ULONG_PTR)handle, 0) == NULL) {
        err = fn_GetLastError();
        goto error;
    }

    async_pipe_connection_init(handle);
    handle->handle = pipeHandle;

    return 0;

 error:
    if (pipeHandle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(pipeHandle);
    }

    return err;
}


int async_set_pipe_handle(async_loop_t* loop, async_pipe_t* handle, HANDLE pipeHandle, DWORD duplex_flags)
{
    NTSTATUS nt_status;
    IO_STATUS_BLOCK io_status;
    FILE_MODE_INFORMATION mode_info;
    DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    DWORD current_mode = 0;
    DWORD err = 0;

    if (!fn_SetNamedPipeHandleState(pipeHandle, &mode, NULL, NULL)) {
        err = fn_GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            /*
            * SetNamedPipeHandleState can fail if the handle doesn't have either
            * GENERIC_WRITE  or FILE_WRITE_ATTRIBUTES.
            * But if the handle already has the desired wait and blocking modes
            * we can continue.
            */
            if (!fn_GetNamedPipeHandleStateW(pipeHandle, &current_mode, NULL, NULL, NULL, NULL, 0)) {
                return -1;
            }
            else if (current_mode & PIPE_NOWAIT) {
                fn_SetLastError(ERROR_ACCESS_DENIED);
                return -1;
            }
        }
        else {
            /* If this returns ERROR_INVALID_PARAMETER we probably opened
            * something that is not a pipe. */
            if (err == ERROR_INVALID_PARAMETER) {
                fn_SetLastError(WSAENOTSOCK);
            }
            return -1;
        }
    }

    /* Check if the pipe was created with FILE_FLAG_OVERLAPPED. */
    nt_status = fn_NtQueryInformationFile(pipeHandle, &io_status, &mode_info, sizeof(mode_info), FileModeInformation);
    if (nt_status != STATUS_SUCCESS) {
        return -1;
    }

    if (mode_info.Mode & FILE_SYNCHRONOUS_IO_ALERT || mode_info.Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
        /* Non-overlapped pipe. */
        handle->flags |= ASYNC_HANDLE_NON_OVERLAPPED_PIPE;
    }
    else {
        /* Overlapped pipe.  Try to associate with IOCP. */
        if (fn_CreateIoCompletionPort(pipeHandle, loop->iocp, (ULONG_PTR)handle, 0) == NULL) {
            handle->flags |= ASYNC_HANDLE_EMULATE_IOCP;
        }
    }

    handle->handle = pipeHandle;
    handle->flags |= duplex_flags;

    return 0;
}

DWORD WINAPI pipe_shutdown_thread_proc(void* parameter)
{
    async_loop_t* loop;
    async_pipe_t* handle;
    async_shutdown_t* req;

    req = (async_shutdown_t*) parameter;
    handle = (async_pipe_t*) req->handle;
    loop = handle->loop;

    fn_FlushFileBuffers(handle->handle);

    /* Post completed */
    POST_COMPLETION_FOR_REQ(loop, req);

    return 0;
}

void async_pipe_endgame(async_loop_t* loop, async_pipe_t* handle)
{
    int err;
    DWORD result;
    async_shutdown_t* req;
    NTSTATUS nt_status;
    IO_STATUS_BLOCK io_status;
    FILE_PIPE_LOCAL_INFORMATION pipe_info;
    async__ipc_queue_item_t* item;

    if (handle->flags & ASYNC_HANDLE_PIPE_READ_CANCELABLE) {
        handle->flags &= ~ASYNC_HANDLE_PIPE_READ_CANCELABLE;
        mutex_destroy(&handle->readfile_mutex);
    }

    if ((handle->flags & ASYNC_HANDLE_CONNECTION) && handle->shutdown_req != NULL && handle->write_reqs_pending == 0) {
        req = handle->shutdown_req;

        /* Clear the shutdown_req field so we don't go here again. */
        handle->shutdown_req = NULL;

        if (handle->flags & ASYNC__HANDLE_CLOSING) {
            UNREGISTER_HANDLE_REQ(loop, handle, req);

            /* Already closing. Cancel the shutdown. */
            if (req->cb) {
                req->cb(req, ASYNC_ECANCELED);
            }

            DECREASE_PENDING_REQ_COUNT(handle);
            return;
        }

        /* Try to avoid flushing the pipe buffer in the thread pool. */
        nt_status = fn_NtQueryInformationFile(handle->handle, &io_status, &pipe_info, sizeof pipe_info, FilePipeLocalInformation);

        if (nt_status != STATUS_SUCCESS) {
            /* Failure */
            UNREGISTER_HANDLE_REQ(loop, handle, req);

            handle->flags |= ASYNC_HANDLE_WRITABLE; /* Questionable */
            if (req->cb) {
                err = fn_RtlNtStatusToDosError(nt_status);
                req->cb(req, async_translate_sys_error(err));
            }

            DECREASE_PENDING_REQ_COUNT(handle);
            return;
        }

        if (pipe_info.OutboundQuota == pipe_info.WriteQuotaAvailable) {
            /* Short-circuit, no need to call FlushFileBuffers. */
            async_insert_pending_req(loop, (async_req_t*) req);
            return;
        }

        /* Run FlushFileBuffers in the thread pool. */
        result = fn_QueueUserWorkItem(pipe_shutdown_thread_proc, req, WT_EXECUTELONGFUNCTION);
        if (result) {
            return;
        }
        else {
            /* Failure. */
            UNREGISTER_HANDLE_REQ(loop, handle, req);

            handle->flags |= ASYNC_HANDLE_WRITABLE; /* Questionable */
            if (req->cb) {
                err = fn_GetLastError();
                req->cb(req, async_translate_sys_error(err));
            }

            DECREASE_PENDING_REQ_COUNT(handle);
            return;
        }
    }

    if (handle->flags & ASYNC__HANDLE_CLOSING && handle->reqs_pending == 0) {
        if (handle->flags & ASYNC_HANDLE_CONNECTION) {
            /* Free pending sockets */
            while (!queue_empty(&handle->pending_ipc_info.queue)) {
                QUEUE* q;
                SOCKET socket;

                q = queue_head(&handle->pending_ipc_info.queue);
                queue_remove(q);
                item = QUEUE_DATA(q, async__ipc_queue_item_t, member);

                /* Materialize socket and close it */
                socket = fn_WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &item->socket_info_ex.socket_info, 0, WSA_FLAG_OVERLAPPED);
                memory_free(item);

                if (socket != INVALID_SOCKET) {
                    fn_closesocket(socket);
                }
            }
            handle->pending_ipc_info.queue_len = 0;

            if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
                if (handle->read_req.wait_handle != INVALID_HANDLE_VALUE) {
                    fn_UnregisterWait(handle->read_req.wait_handle);
                    handle->read_req.wait_handle = INVALID_HANDLE_VALUE;
                }
                if (handle->read_req.event_handle) {
                    fn_CloseHandle(handle->read_req.event_handle);
                    handle->read_req.event_handle = NULL;
                }
            }
        }

        if (handle->flags & ASYNC_HANDLE_PIPESERVER) {
            memory_free(handle->accept_reqs);
            handle->accept_reqs = NULL;
        }

        async__handle_close(handle);
    }
}

void async_pipe_pending_instances(async_pipe_t* handle, int count)
{
    handle->pending_instances = count;
    handle->flags |= ASYNC_HANDLE_PIPESERVER;
}


/* Creates a pipe server. */
int async_pipe_bind(async_pipe_t* handle, const char* name)
{
    async_loop_t* loop = handle->loop;
    int i, err;
    async_pipe_accept_t* req;

    if (handle->flags & ASYNC_HANDLE_BOUND) {
        return ASYNC_EINVAL;
    }

    if (name == NULL) {
        return ASYNC_EINVAL;
    }

    if (!(handle->flags & ASYNC_HANDLE_PIPESERVER)) {
        handle->pending_instances = default_pending_pipe_instances;
    }

    handle->accept_reqs = (async_pipe_accept_t*)memory_alloc(sizeof(async_pipe_accept_t) * handle->pending_instances);

    for (i = 0; i < handle->pending_instances; ++i) {
        req = &handle->accept_reqs[i];
        async_req_init(loop, (async_req_t*) req);
        req->type = ASYNC_ACCEPT;
        req->data = handle;
        req->pipeHandle = INVALID_HANDLE_VALUE;
        req->next_pending = NULL;
    }

    /* Convert name to UTF16. */
    handle->name = utils_utf16(name);

    if (handle->name == NULL) {
        err = fn_GetLastError();
        goto error;
    }

    /*
    * Attempt to create the first pipe with FILE_FLAG_FIRST_PIPE_INSTANCE.
    * If this fails then there's already a pipe server for the given pipe name.
    */
    handle->accept_reqs[0].pipeHandle = fn_CreateNamedPipeW(handle->name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);

    if (handle->accept_reqs[0].pipeHandle == INVALID_HANDLE_VALUE) {
        err = fn_GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            err = WSAEADDRINUSE;  /* Translates to ASYNC_EADDRINUSE. */
        }
        else if (err == ERROR_PATH_NOT_FOUND || err == ERROR_INVALID_NAME) {
            err = WSAEACCES;  /* Translates to ASYNC_EACCES. */
        }
        goto error;
    }

    if (async_set_pipe_handle(loop, handle, handle->accept_reqs[0].pipeHandle, 0)) {
        err = fn_GetLastError();
        goto error;
    }

    handle->pending_accepts = NULL;
    handle->flags |= ASYNC_HANDLE_PIPESERVER;
    handle->flags |= ASYNC_HANDLE_BOUND;

    return 0;

error:
    if (handle->name != NULL) {
        memory_free(handle->name);
        handle->name = NULL;
    }

    if (handle->accept_reqs[0].pipeHandle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(handle->accept_reqs[0].pipeHandle);
        handle->accept_reqs[0].pipeHandle = INVALID_HANDLE_VALUE;
    }

    return async_translate_sys_error(err);
}

DWORD WINAPI pipe_connect_thread_proc(void* parameter)
{
    async_loop_t* loop;
    async_pipe_t* handle;
    async_connect_t* req;
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    DWORD duplex_flags;

    req = (async_connect_t*) parameter;
    handle = (async_pipe_t*) req->handle;
    loop = handle->loop;

    /* We're here because CreateFile on a pipe returned ERROR_PIPE_BUSY. */
    /* We wait for the pipe to become available with WaitNamedPipe. */
    while (fn_WaitNamedPipeW(handle->name, 30000)) {
        /* The pipe is now available, try to connect. */
        pipeHandle = open_named_pipe(handle->name, &duplex_flags);
        if (pipeHandle != INVALID_HANDLE_VALUE) {
            break;
        }

        fn_SwitchToThread();
    }

    if (pipeHandle != INVALID_HANDLE_VALUE && !async_set_pipe_handle(loop, handle, pipeHandle, duplex_flags)) {
        SET_REQ_SUCCESS(req);
    }
    else {
        SET_REQ_ERROR(req, fn_GetLastError());
    }

    /* Post completed */
    POST_COMPLETION_FOR_REQ(loop, req);

    return 0;
}


void async_pipe_connect(async_connect_t* req, async_pipe_t* handle, const char* name, async_connect_cb cb)
{
    async_loop_t* loop = handle->loop;
    int err, nameSize;
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;
    DWORD duplex_flags;

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_CONNECT;
    req->handle = (async_stream_t*) handle;
    req->cb = cb;

    /* Convert name to UTF16. */
    handle->name = utils_utf16(name);

    if (handle->name == NULL) {
        err = fn_GetLastError();
        goto error;
    }

    pipeHandle = open_named_pipe(handle->name, &duplex_flags);
    if (pipeHandle == INVALID_HANDLE_VALUE) {
        if (fn_GetLastError() == ERROR_PIPE_BUSY) {
            /* Wait for the server to make a pipe instance available. */
            if (!fn_QueueUserWorkItem(&pipe_connect_thread_proc, req, WT_EXECUTELONGFUNCTION)) {
                err = fn_GetLastError();
                goto error;
            }

            REGISTER_HANDLE_REQ(loop, handle, req);
            ++handle->reqs_pending;
            return;
        }

        err = fn_GetLastError();
        goto error;
    }

    if (async_set_pipe_handle(loop, (async_pipe_t*) req->handle, pipeHandle, duplex_flags)) {
        err = fn_GetLastError();
        goto error;
    }

    SET_REQ_SUCCESS(req);
    async_insert_pending_req(loop, (async_req_t*) req);
    handle->reqs_pending++;
    REGISTER_HANDLE_REQ(loop, handle, req);
    return;

error:
    if (handle->name != NULL) {
        memory_free(handle->name);
        handle->name = NULL;
    }

    if (pipeHandle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(pipeHandle);
    }
    
    /* Make this req pending reporting an error. */
    SET_REQ_ERROR(req, err);
    async_insert_pending_req(loop, (async_req_t*) req);
    ++handle->reqs_pending;
    REGISTER_HANDLE_REQ(loop, handle, req);
    return;
}

void async__pipe_pause_read(async_pipe_t* handle)
{
    if (handle->flags & ASYNC_HANDLE_PIPE_READ_CANCELABLE) {
        /* Pause the ReadFile task briefly, to work
        around the Windows kernel bug that causes
        any access to a NamedPipe to deadlock if
        any process has called ReadFile */
        HANDLE h;
        mutex_lock(&handle->readfile_mutex);
        h = handle->readfile_thread;
        while (h) {
            /* spinlock: we expect this to finish quickly,
            or we are probably about to deadlock anyways
            (in the kernel), so it doesn't matter */
            fn_CancelSynchronousIo(h);
            fn_SwitchToThread(); /* yield thread control briefly */
            h = handle->readfile_thread;
        }
    }
}

void async__pipe_unpause_read(async_pipe_t* handle)
{
    if (handle->flags & ASYNC_HANDLE_PIPE_READ_CANCELABLE) {
        mutex_unlock(&handle->readfile_mutex);
    }
}

void async__pipe_stop_read(async_pipe_t* handle)
{
    handle->flags &= ~ASYNC_HANDLE_READING;
    async__pipe_pause_read((async_pipe_t*)handle);
    async__pipe_unpause_read((async_pipe_t*)handle);
}

// Cleans up async_pipe_t (server or connection) and all resources associated with it.
void async_pipe_cleanup(async_loop_t* loop, async_pipe_t* handle)
{
    int i;
    HANDLE pipeHandle;

    async__pipe_stop_read(handle);

    if (handle->name) {
        memory_free(handle->name);
        handle->name = NULL;
    }

    if (handle->flags & ASYNC_HANDLE_PIPESERVER) {
        for (i = 0; i < handle->pending_instances; i++) {
            pipeHandle = handle->accept_reqs[i].pipeHandle;
            if (pipeHandle != INVALID_HANDLE_VALUE) {
                fn_CloseHandle(pipeHandle);
                handle->accept_reqs[i].pipeHandle = INVALID_HANDLE_VALUE;
            }
        }
    }

    if (handle->flags & ASYNC_HANDLE_CONNECTION) {
        handle->flags &= ~ASYNC_HANDLE_WRITABLE;
        eof_timer_destroy(handle);
    }

    if ((handle->flags & ASYNC_HANDLE_CONNECTION) && handle->handle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(handle->handle);
        handle->handle = INVALID_HANDLE_VALUE;
    }
}

void async_pipe_close(async_loop_t* loop, async_pipe_t* handle)
{
    if (handle->flags & ASYNC_HANDLE_READING) {
        handle->flags &= ~ASYNC_HANDLE_READING;
        DECREASE_ACTIVE_COUNT(loop, handle);
    }

    if (handle->flags & ASYNC_HANDLE_LISTENING) {
        handle->flags &= ~ASYNC_HANDLE_LISTENING;
        DECREASE_ACTIVE_COUNT(loop, handle);
    }

    async_pipe_cleanup(loop, handle);

    if (handle->reqs_pending == 0) {
        async_want_endgame(loop, (async_handle_t*) handle);
    }

    handle->flags &= ~(ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE);
    async__handle_closing(handle);
}

void async_pipe_queue_accept(async_loop_t* loop, async_pipe_t* handle, async_pipe_accept_t* req, BOOL firstInstance)
{
    if (!firstInstance) {
        req->pipeHandle = fn_CreateNamedPipeW(handle->name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);

        if (req->pipeHandle == INVALID_HANDLE_VALUE) {
            SET_REQ_ERROR(req, fn_GetLastError());
            async_insert_pending_req(loop, (async_req_t*) req);
            handle->reqs_pending++;
            return;
        }

        if (async_set_pipe_handle(loop, handle, req->pipeHandle, 0)) {
            fn_CloseHandle(req->pipeHandle);
            req->pipeHandle = INVALID_HANDLE_VALUE;
            SET_REQ_ERROR(req, fn_GetLastError());
            async_insert_pending_req(loop, (async_req_t*) req);
            handle->reqs_pending++;
            return;
        }
    }

  // Prepare the overlapped structure.
    __stosb((uint8_t*)&(req->overlapped), 0, sizeof(req->overlapped));

    if (!fn_ConnectNamedPipe(req->pipeHandle, &req->overlapped) && fn_GetLastError() != ERROR_IO_PENDING) {
        if (fn_GetLastError() == ERROR_PIPE_CONNECTED) {
            SET_REQ_SUCCESS(req);
        }
        else {
            fn_CloseHandle(req->pipeHandle);
            req->pipeHandle = INVALID_HANDLE_VALUE;
            /* Make this req pending reporting an error. */
            SET_REQ_ERROR(req, fn_GetLastError());
        }
        async_insert_pending_req(loop, (async_req_t*) req);
        handle->reqs_pending++;
        return;
    }

    ++handle->reqs_pending;
}

int async_pipe_accept(async_pipe_t* server, async_stream_t* client)
{
    async_loop_t* loop = server->loop;
    async_pipe_t* pipe_client;
    async_pipe_accept_t* req;
    QUEUE* q;
    async__ipc_queue_item_t* item;
    int err;

    if (server->ipc) {
        if (queue_empty(&server->pending_ipc_info.queue)) {
            /* No valid pending sockets. */
            return WSAEWOULDBLOCK;
        }

        q = queue_head(&server->pending_ipc_info.queue);
        queue_remove(q);
        server->pending_ipc_info.queue_len--;
        item = QUEUE_DATA(q, async__ipc_queue_item_t, member);

        err = async_tcp_import((async_tcp_t*)client, &item->socket_info_ex, item->tcp_connection);
        if (err != 0) {
            return err;
        }

        memory_free(item);
    }
    else {
        pipe_client = (async_pipe_t*)client;

        // Find a connection instance that has been connected, but not yet accepted.
        req = server->pending_accepts;

        if (!req) {
            /* No valid connections found, so we error out. */
            return WSAEWOULDBLOCK;
        }

        /* Initialize the client handle and copy the pipeHandle to the client */
        async_pipe_connection_init(pipe_client);
        pipe_client->handle = req->pipeHandle;
        pipe_client->flags |= ASYNC_HANDLE_READABLE | ASYNC_HANDLE_WRITABLE;

        /* Prepare the req to pick up a new connection */
        server->pending_accepts = req->next_pending;
        req->next_pending = NULL;
        req->pipeHandle = INVALID_HANDLE_VALUE;

        if (!(server->flags & ASYNC__HANDLE_CLOSING)) {
            async_pipe_queue_accept(loop, server, req, FALSE);
        }
    }

    return 0;
}

/* Starts listening for connections for the given pipe. */
int async_pipe_listen(async_pipe_t* handle, int backlog, async_connection_cb cb)
{
    async_loop_t* loop = handle->loop;
    int i;

    if (handle->flags & ASYNC_HANDLE_LISTENING) {
        handle->connection_cb = cb;
    }

    if (!(handle->flags & ASYNC_HANDLE_BOUND)) {
        return WSAEINVAL;
    }

    if (handle->flags & ASYNC_HANDLE_READING) {
        return WSAEISCONN;
    }

    if (!(handle->flags & ASYNC_HANDLE_PIPESERVER)) {
        return ERROR_NOT_SUPPORTED;
    }

    handle->flags |= ASYNC_HANDLE_LISTENING;
    INCREASE_ACTIVE_COUNT(loop, handle);
    handle->connection_cb = cb;

    /* First pipe handle should have already been created in async_pipe_bind */

    for (i = 0; i < handle->pending_instances; i++) {
        async_pipe_queue_accept(loop, handle, &handle->accept_reqs[i], i == 0);
    }

    return 0;
}

DWORD WINAPI async_pipe_zero_readfile_thread_proc(void* parameter)
{
    int result;
    DWORD bytes;
    async_read_t* req = (async_read_t*) parameter;
    async_pipe_t* handle = (async_pipe_t*) req->data;
    async_loop_t* loop = handle->loop;
    HANDLE hThread = NULL;
    DWORD err;
    mutex_t* m = &handle->readfile_mutex;

    if (handle->flags & ASYNC_HANDLE_PIPE_READ_CANCELABLE) {
        mutex_lock(m); /* mutex controls *setting* of readfile_thread */
        if (fn_DuplicateHandle(fn_GetCurrentProcess(), fn_GetCurrentThread(), fn_GetCurrentProcess(), &hThread, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            handle->readfile_thread = hThread;
        }
        else {
            hThread = NULL;
        }
        mutex_unlock(m);
    }
restart_readfile:
    result = fn_ReadFile(handle->handle, &async_zero_, 0, &bytes, NULL);

    if (!result) {
        err = fn_GetLastError();
        if (err == ERROR_OPERATION_ABORTED &&
            handle->flags & ASYNC_HANDLE_PIPE_READ_CANCELABLE) {
            if (handle->flags & ASYNC_HANDLE_READING) {
                /* just a brief break to do something else */
                handle->readfile_thread = NULL;
                /* resume after it is finished */
                mutex_lock(m);
                handle->readfile_thread = hThread;
                mutex_unlock(m);
                goto restart_readfile;
            }
            else {
                result = 1; /* successfully stopped reading */
            }
        }
    }
    if (hThread) {
        /* mutex does not control clearing readfile_thread */
        handle->readfile_thread = NULL;
        mutex_lock(m);
        /* only when we hold the mutex lock is it safe to
        open or close the handle */
        fn_CloseHandle(hThread);
        mutex_unlock(m);
    }

    if (!result) {
        SET_REQ_ERROR(req, err);
    }

    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
}

DWORD WINAPI async_pipe_writefile_thread_proc(void* parameter)
{
    int result;
    DWORD bytes;
    async_write_t* req = (async_write_t*) parameter;
    async_pipe_t* handle = (async_pipe_t*) req->handle;
    async_loop_t* loop = handle->loop;

    result = fn_WriteFile(handle->handle, req->write_buffer.base, req->write_buffer.len, &bytes, NULL);

    if (!result) {
        SET_REQ_ERROR(req, fn_GetLastError());
    }

    POST_COMPLETION_FOR_REQ(loop, req);
    return 0;
}

void CALLBACK post_completion_read_wait(void* context, BOOLEAN timed_out)
{
    async_read_t* req;
    async_tcp_t* handle;

    req = (async_read_t*) context;
    handle = (async_tcp_t*)req->data;

    if (!fn_PostQueuedCompletionStatus(handle->loop->iocp, req->overlapped.InternalHigh, 0, &req->overlapped)) {
        LOG("PostQueuedCompletionStatus failed with error 0x%08X", fn_GetLastError());
    }
}

void CALLBACK post_completion_write_wait(void* context, BOOLEAN timed_out)
{
    async_write_t* req;
    async_tcp_t* handle;

    req = (async_write_t*) context;
    handle = (async_tcp_t*)req->handle;

    if (!fn_PostQueuedCompletionStatus(handle->loop->iocp, req->overlapped.InternalHigh, 0, &req->overlapped)) {
        LOG("PostQueuedCompletionStatus failed with error 0x%08X", fn_GetLastError());
    }
}

void async_pipe_queue_read(async_loop_t* loop, async_pipe_t* handle)
{
    async_read_t* req;
    int result;

    req = &handle->read_req;

    if (handle->flags & ASYNC_HANDLE_NON_OVERLAPPED_PIPE) {
        if (!fn_QueueUserWorkItem(&async_pipe_zero_readfile_thread_proc, req, WT_EXECUTELONGFUNCTION)) {
            /* Make this req pending reporting an error. */
            SET_REQ_ERROR(req, fn_GetLastError());
            goto error;
        }
    }
    else {
        __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));
        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
            req->overlapped.hEvent = (HANDLE) ((uintptr_t) req->event_handle | 1);
        }

        /* Do 0-read */
        result = fn_ReadFile(handle->handle, &async_zero_, 0, NULL, &req->overlapped);

        if (!result && fn_GetLastError() != ERROR_IO_PENDING) {
            /* Make this req pending reporting an error. */
            SET_REQ_ERROR(req, fn_GetLastError());
            goto error;
        }

        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
            if (!req->event_handle) {
                req->event_handle = fn_CreateEventW(NULL, 0, 0, NULL);
                if (!req->event_handle) {
                    SET_REQ_ERROR(req, fn_GetLastError());
                    goto error;
                }
            }
            if (req->wait_handle == INVALID_HANDLE_VALUE) {
                if (!fn_RegisterWaitForSingleObject(&req->wait_handle, req->overlapped.hEvent, post_completion_read_wait, (void*) req, INFINITE, WT_EXECUTEINWAITTHREAD)) {
                    SET_REQ_ERROR(req, fn_GetLastError());
                    goto error;
                }
            }
        }
    }

    /* Start the eof timer if there is one */
    eof_timer_start(handle);
    handle->flags |= ASYNC_HANDLE_READ_PENDING;
    handle->reqs_pending++;
    return;

error:
    async_insert_pending_req(loop, (async_req_t*)req);
    handle->flags |= ASYNC_HANDLE_READ_PENDING;
    handle->reqs_pending++;
}


int async_pipe_read_start(async_pipe_t* handle, async_alloc_cb alloc_cb, async_read_cb read_cb)
{
    async_loop_t* loop = handle->loop;

    handle->flags |= ASYNC_HANDLE_READING;
    INCREASE_ACTIVE_COUNT(loop, handle);
    handle->read_cb = read_cb;
    handle->alloc_cb = alloc_cb;

    /* If reading was stopped and then started again, there could still be a */
    /* read request pending. */
    if (!(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
        async_pipe_queue_read(loop, handle);
    }

    return 0;
}

void async_insert_non_overlapped_write_req(async_pipe_t* handle, async_write_t* req)
{
    req->next_req = NULL;
    if (handle->non_overlapped_writes_tail) {
        req->next_req = handle->non_overlapped_writes_tail->next_req;
        handle->non_overlapped_writes_tail->next_req = (async_req_t*)req;
        handle->non_overlapped_writes_tail = req;
    }
    else {
        req->next_req = (async_req_t*)req;
        handle->non_overlapped_writes_tail = req;
    }
}

async_write_t* async_remove_non_overlapped_write_req(async_pipe_t* handle)
{
    async_write_t* req;

    if (handle->non_overlapped_writes_tail) {
        req = (async_write_t*)handle->non_overlapped_writes_tail->next_req;

        if (req == handle->non_overlapped_writes_tail) {
            handle->non_overlapped_writes_tail = NULL;
        }
        else {
            handle->non_overlapped_writes_tail->next_req = req->next_req;
        }

        return req;
    }
    else {
        /* queue empty */
        return NULL;
    }
}

void async_queue_non_overlapped_write(async_pipe_t* handle)
{
    async_write_t* req = async_remove_non_overlapped_write_req(handle);
    if (req) {
        if (!fn_QueueUserWorkItem(&async_pipe_writefile_thread_proc, req, WT_EXECUTELONGFUNCTION)) {
            LOG("QueueUserWorkItem failed with error 0x%08X", fn_GetLastError());
        }
    }
}

int async_pipe_write_impl(async_loop_t* loop, async_write_t* req, async_pipe_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_stream_t* send_handle, async_write_cb cb)
{
    int err;
    int result;
    async_tcp_t* tcp_send_handle;
    async_write_t* ipc_header_req = NULL;
    async_ipc_frame_async_stream ipc_frame;

    if (nbufs != 1 && (nbufs != 0 || !send_handle)) {
        return ERROR_NOT_SUPPORTED;
    }

    /* Only TCP handles are supported for sharing. */
    if (send_handle && ((send_handle->type != ASYNC_TCP) || (!(send_handle->flags & ASYNC_HANDLE_BOUND) && !(send_handle->flags & ASYNC_HANDLE_CONNECTION)))) {
        return ERROR_NOT_SUPPORTED;
    }

    async_req_init(loop, (async_req_t*) req);
    req->type = ASYNC_WRITE;
    req->handle = (async_stream_t*) handle;
    req->cb = cb;
    req->ipc_header = 0;
    req->event_handle = NULL;
    req->wait_handle = INVALID_HANDLE_VALUE;
    __stosb((uint8_t*)&req->overlapped, 0, sizeof(req->overlapped));

    if (handle->ipc) {
        ipc_frame.header.flags = 0;

        /* Use the IPC framing protocol. */
        if (send_handle) {
            tcp_send_handle = (async_tcp_t*)send_handle;

            err = async_tcp_duplicate_socket(tcp_send_handle, handle->ipc_pid, &ipc_frame.socket_info_ex.socket_info);
            if (err) {
                return err;
            }

            ipc_frame.socket_info_ex.delayed_error = tcp_send_handle->delayed_error;

            ipc_frame.header.flags |= ASYNC_IPC_TCP_SERVER;

            if (tcp_send_handle->flags & ASYNC_HANDLE_CONNECTION) {
                ipc_frame.header.flags |= ASYNC_IPC_TCP_CONNECTION;
            }
        }

        if (nbufs == 1) {
            ipc_frame.header.flags |= ASYNC_IPC_RAW_DATA;
            ipc_frame.header.raw_data_length = bufs[0].len;
        }

        /*
         * Use the provided req if we're only doing a single write.
         * If we're doing multiple writes, use ipc_header_write_req to do
         * the first write, and then use the provided req for the second write.
         */
        if (!(ipc_frame.header.flags & ASYNC_IPC_RAW_DATA)) {
            ipc_header_req = req;
        }
        else {
            /*
            * Try to use the preallocated write req if it's available.
            * Otherwise allocate a new one.
            */
            if (handle->ipc_header_write_req.type != ASYNC_WRITE) {
                ipc_header_req = (async_write_t*)&handle->ipc_header_write_req;
            }
            else {
                ipc_header_req = (async_write_t*)memory_alloc(sizeof(async_write_t));
            }

            async_req_init(loop, (async_req_t*) ipc_header_req);
            ipc_header_req->type = ASYNC_WRITE;
            ipc_header_req->handle = (async_stream_t*) handle;
            ipc_header_req->cb = NULL;
            ipc_header_req->ipc_header = 1;
        }

        /* Write the header or the whole frame. */
        __stosb((uint8_t*)&ipc_header_req->overlapped, 0, sizeof(ipc_header_req->overlapped));

        // Using overlapped IO, but wait for completion before returning. This write is blocking because ipc_frame is on stack.
        ipc_header_req->overlapped.hEvent = fn_CreateEventW(NULL, 1, 0, NULL);
        if (!ipc_header_req->overlapped.hEvent) {
            err = fn_GetLastError();
            return err;
        }

        result = fn_WriteFile(handle->handle, &ipc_frame, ipc_frame.header.flags & ASYNC_IPC_TCP_SERVER ? sizeof(ipc_frame) : sizeof(ipc_frame.header), NULL, &ipc_header_req->overlapped);
        if (!result && fn_GetLastError() != ERROR_IO_PENDING) {
            err = fn_GetLastError();
            fn_CloseHandle(ipc_header_req->overlapped.hEvent);
            return err;
        }

        if (!result) {
            /* Request not completed immediately. Wait for it.*/
            if (fn_WaitForSingleObject(ipc_header_req->overlapped.hEvent, INFINITE) != WAIT_OBJECT_0) {
                err = fn_GetLastError();
                fn_CloseHandle(ipc_header_req->overlapped.hEvent);
                return err;
            }
        }
        ipc_header_req->queued_bytes = 0;
        fn_CloseHandle(ipc_header_req->overlapped.hEvent);
        ipc_header_req->overlapped.hEvent = NULL;

        REGISTER_HANDLE_REQ(loop, handle, ipc_header_req);
        handle->reqs_pending++;
        handle->write_reqs_pending++;

        /* If we don't have any raw data to write - we're done. */
        if (!(ipc_frame.header.flags & ASYNC_IPC_RAW_DATA)) {
            return 0;
        }
    }

    if ((handle->flags & (ASYNC_HANDLE_BLOCKING_WRITES | ASYNC_HANDLE_NON_OVERLAPPED_PIPE)) == (ASYNC_HANDLE_BLOCKING_WRITES | ASYNC_HANDLE_NON_OVERLAPPED_PIPE)) {
        DWORD bytes;
        result = fn_WriteFile(handle->handle, bufs[0].base, bufs[0].len, &bytes, NULL);

        if (!result) {
            err = fn_GetLastError();
            return err;
        }
        else {
            /* Request completed immediately. */
            req->queued_bytes = 0;
        }

        REGISTER_HANDLE_REQ(loop, handle, req);
        handle->reqs_pending++;
        handle->write_reqs_pending++;
        POST_COMPLETION_FOR_REQ(loop, req);
        return 0;
    }
    else if (handle->flags & ASYNC_HANDLE_NON_OVERLAPPED_PIPE) {
        req->write_buffer = bufs[0];
        async_insert_non_overlapped_write_req(handle, req);
        if (handle->write_reqs_pending == 0) {
            async_queue_non_overlapped_write(handle);
        }

        /* Request queued by the kernel. */
        req->queued_bytes = async__count_bufs(bufs, nbufs);
        handle->write_queue_size += req->queued_bytes;
    }
    else if (handle->flags & ASYNC_HANDLE_BLOCKING_WRITES) {
        /* Using overlapped IO, but wait for completion before returning */
        req->overlapped.hEvent = fn_CreateEventW(NULL, 1, 0, NULL);
        if (!req->overlapped.hEvent) {
            err = fn_GetLastError();
            return err;
        }

        result = fn_WriteFile(handle->handle, bufs[0].base, bufs[0].len, NULL, &req->overlapped);

        if (!result && fn_GetLastError() != ERROR_IO_PENDING) {
            err = fn_GetLastError();
            fn_CloseHandle(req->overlapped.hEvent);
            return err;
        }

        if (result) {
            /* Request completed immediately. */
            req->queued_bytes = 0;
        }
        else {
            /* Request queued by the kernel. */
            if (fn_WaitForSingleObject(ipc_header_req->overlapped.hEvent, INFINITE) != WAIT_OBJECT_0) {
                err = fn_GetLastError();
                fn_CloseHandle(ipc_header_req->overlapped.hEvent);
                return async_translate_sys_error(err);
            }
        }
        fn_CloseHandle(req->overlapped.hEvent);

        REGISTER_HANDLE_REQ(loop, handle, req);
        handle->reqs_pending++;
        handle->write_reqs_pending++;
        POST_COMPLETION_FOR_REQ(loop, req);
        return 0;
    }
    else {
        result = fn_WriteFile(handle->handle, bufs[0].base, bufs[0].len, NULL, &req->overlapped);

        if (!result && fn_GetLastError() != ERROR_IO_PENDING) {
            return fn_GetLastError();
        }

        if (result) {
            /* Request completed immediately. */
            req->queued_bytes = 0;
        }
        else {
            /* Request queued by the kernel. */
            req->queued_bytes = async__count_bufs(bufs, nbufs);
            handle->write_queue_size += req->queued_bytes;
        }

        if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
            req->event_handle = fn_CreateEventW(NULL, 0, 0, NULL);
            if (!req->event_handle) {
                return fn_GetLastError();
            }
            if (!fn_RegisterWaitForSingleObject(&req->wait_handle, req->overlapped.hEvent, post_completion_write_wait, (void*) req, INFINITE, WT_EXECUTEINWAITTHREAD)) {
                return fn_GetLastError();
            }
        }
    }

    REGISTER_HANDLE_REQ(loop, handle, req);
    ++handle->reqs_pending;
    ++handle->write_reqs_pending;

    return 0;
}

int async_pipe_write(async_loop_t* loop, async_write_t* req, async_pipe_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_write_cb cb)
{
    return async_pipe_write_impl(loop, req, handle, bufs, nbufs, NULL, cb);
}

int async_pipe_write2(async_loop_t* loop, async_write_t* req, async_pipe_t* handle, const async_buf_t bufs[], uint32_t nbufs, async_stream_t* send_handle, async_write_cb cb)
{
    if (!handle->ipc) {
        return WSAEINVAL;
    }

    return async_pipe_write_impl(loop, req, handle, bufs, nbufs, send_handle, cb);
}

void async_pipe_read_eof(async_loop_t* loop, async_pipe_t* handle, async_buf_t buf)
{
    /* If there is an eof timer running, we don't need it any more, */
    /* so discard it. */
    eof_timer_destroy(handle);

    handle->flags &= ~ASYNC_HANDLE_READABLE;
    async_read_stop((async_stream_t*) handle);

    handle->read_cb((async_stream_t*) handle, ASYNC_EOF, &buf);
}

void async_pipe_read_error(async_loop_t* loop, async_pipe_t* handle, int error, async_buf_t buf)
{
    /* If there is an eof timer running, we don't need it any more, */
    /* so discard it. */
    eof_timer_destroy(handle);

    async_read_stop((async_stream_t*) handle);

    handle->read_cb((async_stream_t*)handle, async_translate_sys_error(error), &buf);
}

void async_pipe_read_error_or_eof(async_loop_t* loop, async_pipe_t* handle, int error, async_buf_t buf)
{
    if (error == ERROR_BROKEN_PIPE) {
        async_pipe_read_eof(loop, handle, buf);
    }
    else {
        async_pipe_read_error(loop, handle, error, buf);
    }
}

void async__pipe_insert_pending_socket(async_pipe_t* handle, async__ipc_socket_info_ex* info, int tcp_connection)
{
    async__ipc_queue_item_t* item;

    item = (async__ipc_queue_item_t*)memory_alloc(sizeof(*item));
    __movsb((uint8_t*)&item->socket_info_ex, (const uint8_t*)info, sizeof(item->socket_info_ex));
    item->tcp_connection = tcp_connection;
    queue_insert_tail(&handle->pending_ipc_info.queue, &item->member);
    ++handle->pending_ipc_info.queue_len;
}

void async_process_pipe_read_req(async_loop_t* loop, async_pipe_t* handle, async_req_t* req)
{
    DWORD bytes, avail;
    async_buf_t buf;
    async_ipc_frame_async_stream ipc_frame;

    handle->flags &= ~ASYNC_HANDLE_READ_PENDING;
    eof_timer_stop(handle);

    if (!REQ_SUCCESS(req)) {
        /* An error occurred doing the 0-read. */
        if (handle->flags & ASYNC_HANDLE_READING) {
            async_pipe_read_error_or_eof(loop, handle, GET_REQ_ERROR(req), async_null_buf_);
        }
    }
    else {
        /* Do non-blocking reads until the buffer is empty */
        while (handle->flags & ASYNC_HANDLE_READING) {
            if (!fn_PeekNamedPipe(handle->handle, NULL, 0, NULL, &avail, NULL)) {
                async_pipe_read_error_or_eof(loop, handle, fn_GetLastError(), async_null_buf_);
                break;
            }

            if (avail == 0) {
                /* There is nothing to read after all. */
                break;
            }

            if (handle->ipc) {
                /* Use the IPC framing protocol to read the incoming data. */
                if (handle->remaining_ipc_rawdata_bytes == 0) {
                    /* We're reading a new frame.  First, read the header. */

                    if (!fn_ReadFile(handle->handle, &ipc_frame.header, sizeof(ipc_frame.header), &bytes, NULL)) {
                        async_pipe_read_error_or_eof(loop, handle, fn_GetLastError(), async_null_buf_);
                        break;
                    }

                    if (ipc_frame.header.flags & ASYNC_IPC_TCP_SERVER) {
                        /* Read the TCP socket info. */
                        if (!fn_ReadFile(handle->handle, &ipc_frame.socket_info_ex, sizeof(ipc_frame) - sizeof(ipc_frame.header), &bytes, NULL)) {
                            async_pipe_read_error_or_eof(loop, handle, fn_GetLastError(), async_null_buf_);
                            break;
                        }

                        /* Store the pending socket info. */
                        async__pipe_insert_pending_socket(handle, &ipc_frame.socket_info_ex, ipc_frame.header.flags & ASYNC_IPC_TCP_CONNECTION);
                    }

                    if (ipc_frame.header.flags & ASYNC_IPC_RAW_DATA) {
                        handle->remaining_ipc_rawdata_bytes = ipc_frame.header.raw_data_length;
                        continue;
                    }
                }
                else {
                    avail = min(avail, (DWORD)handle->remaining_ipc_rawdata_bytes);
                }
            }

            handle->alloc_cb((async_handle_t*) handle, avail, &buf);
            if (buf.len == 0) {
                handle->read_cb((async_stream_t*) handle, ASYNC_ENOBUFS, &buf);
                break;
            }

            if (fn_ReadFile(handle->handle, buf.base, buf.len, &bytes, NULL)) {
                /* Successful read */
                if (handle->ipc) {
                    handle->remaining_ipc_rawdata_bytes = handle->remaining_ipc_rawdata_bytes - bytes;
                }
                handle->read_cb((async_stream_t*)handle, bytes, &buf);

                /* Read again only if bytes == buf.len */
                if (bytes <= buf.len) {
                    break;
                }
            }
            else {
                async_pipe_read_error_or_eof(loop, handle, fn_GetLastError(), buf);
                break;
            }
        }

        /* Post another 0-read if still reading and not closing. */
        if ((handle->flags & ASYNC_HANDLE_READING) && !(handle->flags & ASYNC_HANDLE_READ_PENDING)) {
            async_pipe_queue_read(loop, handle);
        }
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_pipe_write_req(async_loop_t* loop, async_pipe_t* handle, async_write_t* req)
{
    int err;

    handle->write_queue_size -= req->queued_bytes;

    UNREGISTER_HANDLE_REQ(loop, handle, req);

    if (handle->flags & ASYNC_HANDLE_EMULATE_IOCP) {
        if (req->wait_handle != INVALID_HANDLE_VALUE) {
            fn_UnregisterWait(req->wait_handle);
            req->wait_handle = INVALID_HANDLE_VALUE;
        }
        if (req->event_handle) {
            fn_CloseHandle(req->event_handle);
            req->event_handle = NULL;
        }
    }

     if (req->ipc_header) {
        if (req == &handle->ipc_header_write_req) {
            req->type = ASYNC_UNKNOWN_REQ;
        }
        else {
            memory_free(req);
        }
    }
     else {
        if (req->cb) {
            err = GET_REQ_ERROR(req);
            req->cb(req, async_translate_sys_error(err));
        }
    }

     --handle->write_reqs_pending;

    if (handle->flags & ASYNC_HANDLE_NON_OVERLAPPED_PIPE && handle->non_overlapped_writes_tail) {
        async_queue_non_overlapped_write(handle);
    }

    if (handle->shutdown_req != NULL && handle->write_reqs_pending == 0) {
        async_want_endgame(loop, (async_handle_t*)handle);
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}


void async_process_pipe_accept_req(async_loop_t* loop, async_pipe_t* handle, async_req_t* raw_req)
{
    async_pipe_accept_t* req = (async_pipe_accept_t*) raw_req;

    if (handle->flags & ASYNC__HANDLE_CLOSING) {
        /* The req->pipeHandle should be freed already in async_pipe_cleanup(). */
        DECREASE_PENDING_REQ_COUNT(handle);
        return;
    }

    if (REQ_SUCCESS(req)) {
        req->next_pending = handle->pending_accepts;
        handle->pending_accepts = req;

        if (handle->connection_cb) {
            handle->connection_cb((async_stream_t*)handle, 0);
        }
    }
    else {
        if (req->pipeHandle != INVALID_HANDLE_VALUE) {
            fn_CloseHandle(req->pipeHandle);
            req->pipeHandle = INVALID_HANDLE_VALUE;
        }
        if (!(handle->flags & ASYNC__HANDLE_CLOSING)) {
            async_pipe_queue_accept(loop, handle, req, FALSE);
        }
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_pipe_connect_req(async_loop_t* loop, async_pipe_t* handle, async_connect_t* req)
{
    int err;

    UNREGISTER_HANDLE_REQ(loop, handle, req);

    if (req->cb) {
        err = 0;
        if (REQ_SUCCESS(req)) {
            async_pipe_connection_init(handle);
        }
        else {
            err = GET_REQ_ERROR(req);
        }
        req->cb(req, async_translate_sys_error(err));
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void async_process_pipe_shutdown_req(async_loop_t* loop, async_pipe_t* handle, async_shutdown_t* req)
{
    UNREGISTER_HANDLE_REQ(loop, handle, req);

    if (handle->flags & ASYNC_HANDLE_READABLE) {
        /* Initialize and optionally start the eof timer. Only do this if the */
        /* pipe is readable and we haven't seen EOF come in ourselves. */
        eof_timer_init(handle);

        /* If reading start the timer right now. */
        /* Otherwise async_pipe_queue_read will start it. */
        if (handle->flags & ASYNC_HANDLE_READ_PENDING) {
            eof_timer_start(handle);
        }
    }
    else {
        /* This pipe is not readable. We can just close it to let the other end */
        /* know that we're done writing. */
        fn_CloseHandle(handle->handle);
        handle->handle = INVALID_HANDLE_VALUE;
    }

    if (req->cb) {
        req->cb(req, 0);
    }

    DECREASE_PENDING_REQ_COUNT(handle);
}

void eof_timer_init(async_pipe_t* pipe)
{
    pipe->eof_timer = (async_timer_t*)memory_alloc(sizeof *pipe->eof_timer);

    async_timer_init(pipe->loop, pipe->eof_timer);
    pipe->eof_timer->data = pipe;
    async_unref((async_handle_t*) pipe->eof_timer);
}

void eof_timer_start(async_pipe_t* pipe)
{
    if (pipe->eof_timer != NULL) {
        async_timer_start(pipe->eof_timer, eof_timer_cb, eof_timeout, 0);
    }
}

void eof_timer_stop(async_pipe_t* pipe)
{
    if (pipe->eof_timer != NULL) {
        async_timer_stop(pipe->eof_timer);
    }
}

void eof_timer_cb(async_timer_t* timer)
{
    async_pipe_t* pipe = (async_pipe_t*) timer->data;
    async_loop_t* loop = timer->loop;

    /* This should always be true, since we start the timer only */
    /* in async_pipe_queue_read after successfully calling ReadFile, */
    /* or in async_process_pipe_shutdown_req if a read is pending, */
    /* and we always immediately stop the timer in */
    /* async_process_pipe_read_req. */

    /* If there are many packets coming off the iocp then the timer callback */
    /* may be called before the read request is coming off the queue. */
    /* Therefore we check here if the read request has completed but will */
    /* be processed later. */
    if ((pipe->flags & ASYNC_HANDLE_READ_PENDING) && HasOverlappedIoCompleted(&pipe->read_req.overlapped)) {
        return;
    }

    /* Force both ends off the pipe. */
    fn_CloseHandle(pipe->handle);
    pipe->handle = INVALID_HANDLE_VALUE;

    /* Stop reading, so the pending read that is going to fail will */
    /* not be reported to the user. */
    async_read_stop((async_stream_t*) pipe);

    /* Report the eof and update flags. This will get reported even if the */
    /* user stopped reading in the meantime. TODO: is that okay? */
    async_pipe_read_eof(loop, pipe, async_null_buf_);
}

void eof_timer_destroy(async_pipe_t* pipe)
{
    if (pipe->eof_timer) {
        async_close((async_handle_t*) pipe->eof_timer, eof_timer_close_cb);
        pipe->eof_timer = NULL;
    }
}

void eof_timer_close_cb(async_handle_t* handle)
{
    memory_free(handle);
}

int async_pipe_open(async_pipe_t* pipe, HANDLE hFile)
{
    NTSTATUS nt_status;
    IO_STATUS_BLOCK io_status;
    FILE_ACCESS_INFORMATION access;
    DWORD duplex_flags = 0;

    /* Determine what kind of permissions we have on this handle.
    * Cygwin opens the pipe in message mode, but we can support it,
    * just query the access flags and set the stream flags accordingly.
    */
    nt_status = fn_NtQueryInformationFile(hFile, &io_status, &access, sizeof(access), FileAccessInformation);
    if (nt_status != STATUS_SUCCESS)
        return ASYNC_EINVAL;

    if (pipe->ipc) {
        if (!(access.AccessFlags & FILE_WRITE_DATA) || !(access.AccessFlags & FILE_READ_DATA)) {
            return ASYNC_EINVAL;
        }
    }

    if (access.AccessFlags & FILE_WRITE_DATA)
        duplex_flags |= ASYNC_HANDLE_WRITABLE;
    if (access.AccessFlags & FILE_READ_DATA)
        duplex_flags |= ASYNC_HANDLE_READABLE;

    if (hFile == INVALID_HANDLE_VALUE || async_set_pipe_handle(pipe->loop, pipe, hFile, duplex_flags) == -1) {
        return ASYNC_EINVAL;
    }

    async_pipe_connection_init(pipe);

    if (pipe->ipc) {
        pipe->ipc_pid = async_parent_pid();
    }
    return 0;
}

int async_pipe_getsockname(const async_pipe_t* handle, char* buf, size_t* len)
{
    NTSTATUS nt_status;
    IO_STATUS_BLOCK io_status;
    FILE_NAME_INFORMATION tmp_name_info;
    FILE_NAME_INFORMATION* name_info;
    wchar_t* name_buf;
    uint32_t addrlen;
    uint32_t name_size;
    uint32_t name_len;
    int err;

    name_info = NULL;

    if (handle->handle == INVALID_HANDLE_VALUE) {
        *len = 0;
        return ASYNC_EINVAL;
    }

    async__pipe_pause_read((async_pipe_t*)handle); /* cast away const warning */

    nt_status = fn_NtQueryInformationFile(handle->handle, &io_status, &tmp_name_info, sizeof(tmp_name_info), FileNameInformation);
    if (nt_status == STATUS_BUFFER_OVERFLOW) {
        name_size = sizeof(*name_info) + tmp_name_info.FileNameLength;
        name_info = memory_alloc(name_size);

        nt_status = fn_NtQueryInformationFile(handle->handle, &io_status, name_info, name_size, FileNameInformation);
    }

    if (nt_status != STATUS_SUCCESS) {
        *len = 0;
        err = async_translate_sys_error(fn_RtlNtStatusToDosError(nt_status));
        goto error;
    }

    if (!name_info) {
        /* the struct on stack was used */
        name_buf = tmp_name_info.FileName;
        name_len = tmp_name_info.FileNameLength;
    }
    else {
        name_buf = name_info->FileName;
        name_len = name_info->FileNameLength;
    }

    if (name_len == 0) {
        *len = 0;
        err = 0;
        goto error;
    }

    name_len /= sizeof(wchar_t);

    /* check how much space we need */
    addrlen = fn_WideCharToMultiByte(CP_UTF8, 0, name_buf, name_len, NULL, 0, NULL, NULL);
    if (!addrlen) {
        *len = 0;
        err = async_translate_sys_error(fn_GetLastError());
        goto error;
    }
    else if (pipe_prefix_len + addrlen + 1 > *len) {
        /* "\\\\.\\pipe" + name + '\0' */
        *len = pipe_prefix_len + addrlen + 1;
        err = ASYNC_ENOBUFS;
        goto error;
    }

    __movsb((uint8_t*)buf, (const uint8_t*)pipe_prefix, pipe_prefix_len);
    addrlen = fn_WideCharToMultiByte(CP_UTF8, 0, name_buf, name_len, buf+pipe_prefix_len, *len-pipe_prefix_len, NULL, NULL);
    if (!addrlen) {
        *len = 0;
        err = async_translate_sys_error(fn_GetLastError());
        goto error;
    }

    addrlen += pipe_prefix_len;
    buf[addrlen++] = '\0';
    *len = addrlen;

    return 0;
    
    err = 0;
    goto cleanup;

error:
    memory_free(name_info);

cleanup:
    async__pipe_unpause_read((async_pipe_t*)handle); /* cast away const warning */
    return err;
}

int async_pipe_pending_count(async_pipe_t* handle)
{
    if (!handle->ipc) {
        return 0;
    }
    return handle->pending_ipc_info.queue_len;
}


async_handle_type async_pipe_pending_type(async_pipe_t* handle)
{
    if (!handle->ipc) {
        return ASYNC_UNKNOWN_HANDLE;
    }
    if (handle->pending_ipc_info.queue_len == 0) {
        return ASYNC_UNKNOWN_HANDLE;
    }
    else {
        return ASYNC_TCP;
    }
}
