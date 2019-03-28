#include "zmodule.h"
#include "async.h"
#include "internal.h"

/* Whether there are any non-IFS LSPs stacked on TCP */
int async_tcp_non_ifs_lsp_ipv4;
int async_tcp_non_ifs_lsp_ipv6;

/* Ip address used to bind to any port at any interface */
struct sockaddr_in async_addr_ip4_any_;
struct sockaddr_in6 async_addr_ip6_any_;


/*
 * Retrieves the pointer to a winsock extension function.
 */
BOOL async_get_extension_function(SOCKET socket, GUID guid, void **target)
{
    int result;
    DWORD bytes;

    result = fn_WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), (void*)target, sizeof(*target), &bytes, NULL, NULL);
    if (result == SOCKET_ERROR) {
        *target = NULL;
        return FALSE;
    }
    else {
        return TRUE;
    }
}

BOOL async_get_acceptex_function(SOCKET socket, LPFN_ACCEPTEX* target)
{
    const GUID wsaid_acceptex = WSAID_ACCEPTEX;
    return async_get_extension_function(socket, wsaid_acceptex, (void**)target);
}

BOOL async_get_connectex_function(SOCKET socket, LPFN_CONNECTEX* target)
{
    const GUID wsaid_connectex = WSAID_CONNECTEX;
    return async_get_extension_function(socket, wsaid_connectex, (void**)target);
}

int error_means_no_support(DWORD error)
{
    return error == WSAEPROTONOSUPPORT || error == WSAESOCKTNOSUPPORT || error == WSAEPFNOSUPPORT || error == WSAEAFNOSUPPORT;
}

int async_winsock_init()
{
    int ret = -1;
    WSADATA wsa_data;
    int errorno;
    SOCKET dummy;
    WSAPROTOCOL_INFOW protocol_info;
    int opt_len;

    do {
        /* Initialize winsock */
        errorno = fn_WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (errorno != 0) {
            LOG("WSAStartup failed with error 0x%08X", errorno);
            break;
        }

        /* Set implicit binding address used by connectEx */
        if (async_ip4_addr("0.0.0.0", 0, &async_addr_ip4_any_)) {
            LOG("async_ip4_addr failed");
            break;
        }

        if (async_ip6_addr("::", 0, &async_addr_ip6_any_)) {
            LOG("async_ip6_addr failed");
            break;
        }

        /* Detect non-IFS LSPs */
        dummy = fn_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        if (dummy != INVALID_SOCKET) {
            opt_len = (int) sizeof protocol_info;
            if (fn_getsockopt(dummy, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocol_info, &opt_len) == SOCKET_ERROR) {
                LOG("getsockopt failed with error 0x%08X", fn_WSAGetLastError());
                break;
            }

            if (!(protocol_info.dwServiceFlags1 & XP1_IFS_HANDLES)) {
                async_tcp_non_ifs_lsp_ipv4 = 1;
            }

            if (fn_closesocket(dummy) == SOCKET_ERROR) {
                LOG("closesocket failed with error 0x%08X", fn_WSAGetLastError());
                break;
            }
        }
        else if (!error_means_no_support(fn_WSAGetLastError())) {
            /* Any error other than "socket type not supported" is fatal. */
            LOG("socket failed with error 0x%08X", fn_WSAGetLastError());
            break;
        }

        /* Detect IPV6 support and non-IFS LSPs */
        dummy = fn_socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);

        if (dummy != INVALID_SOCKET) {
            opt_len = (int) sizeof protocol_info;
            if (fn_getsockopt(dummy, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocol_info, &opt_len) == SOCKET_ERROR) {
                LOG("getsockopt failed with error 0x%08X", fn_WSAGetLastError());
                break;
            }

            if (!(protocol_info.dwServiceFlags1 & XP1_IFS_HANDLES)) {
                async_tcp_non_ifs_lsp_ipv6 = 1;
            }

            if (fn_closesocket(dummy) == SOCKET_ERROR) {
                LOG("closesocket failed with error 0x%08X", fn_WSAGetLastError());
                break;
            }
        }
        else if (!error_means_no_support(fn_WSAGetLastError())) {
            /* Any error other than "socket type not supported" is fatal. */
            LOG("socket failed with error 0x%08X", fn_WSAGetLastError());
            break;
        }

        ret = 0;
    } while (0);

    return ret;
}


int async_ntstatus_to_winsock_error(NTSTATUS status)
{
  switch (status) {
    case STATUS_SUCCESS:
      return ERROR_SUCCESS;

    case STATUS_PENDING:
      return ERROR_IO_PENDING;

    case STATUS_INVALID_HANDLE:
    case STATUS_OBJECT_TYPE_MISMATCH:
      return WSAENOTSOCK;

    case STATUS_INSUFFICIENT_RESOURCES:
    case STATUS_PAGEFILE_QUOTA:
    case STATUS_COMMITMENT_LIMIT:
    case STATUS_WORKING_SET_QUOTA:
    case STATUS_NO_MEMORY:
    case STATUS_QUOTA_EXCEEDED:
    case STATUS_TOO_MANY_PAGING_FILES:
    case STATUS_REMOTE_RESOURCES:
      return WSAENOBUFS;

    case STATUS_TOO_MANY_ADDRESSES:
    case STATUS_SHARING_VIOLATION:
    case STATUS_ADDRESS_ALREADY_EXISTS:
      return WSAEADDRINUSE;

    case STATUS_LINK_TIMEOUT:
    case STATUS_IO_TIMEOUT:
    case STATUS_TIMEOUT:
      return WSAETIMEDOUT;

    case STATUS_GRACEFUL_DISCONNECT:
      return WSAEDISCON;

    case STATUS_REMOTE_DISCONNECT:
    case STATUS_CONNECTION_RESET:
    case STATUS_LINK_FAILED:
    case STATUS_CONNECTION_DISCONNECTED:
    case STATUS_PORT_UNREACHABLE:
    case STATUS_HOPLIMIT_EXCEEDED:
      return WSAECONNRESET;

    case STATUS_LOCAL_DISCONNECT:
    case STATUS_TRANSACTION_ABORTED:
    case STATUS_CONNECTION_ABORTED:
      return WSAECONNABORTED;

    case STATUS_BAD_NETWORK_PATH:
    case STATUS_NETWORK_UNREACHABLE:
    case STATUS_PROTOCOL_UNREACHABLE:
      return WSAENETUNREACH;

    case STATUS_HOST_UNREACHABLE:
      return WSAEHOSTUNREACH;

    case STATUS_CANCELLED:
    case STATUS_REQUEST_ABORTED:
      return WSAEINTR;

    case STATUS_BUFFER_OVERFLOW:
    case STATUS_INVALID_BUFFER_SIZE:
      return WSAEMSGSIZE;

    case STATUS_BUFFER_TOO_SMALL:
    case STATUS_ACCESS_VIOLATION:
      return WSAEFAULT;

    case STATUS_DEVICE_NOT_READY:
    case STATUS_REQUEST_NOT_ACCEPTED:
      return WSAEWOULDBLOCK;

    case STATUS_INVALID_NETWORK_RESPONSE:
    case STATUS_NETWORK_BUSY:
    case STATUS_NO_SUCH_DEVICE:
    case STATUS_NO_SUCH_FILE:
    case STATUS_OBJECT_PATH_NOT_FOUND:
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_UNEXPECTED_NETWORK_ERROR:
      return WSAENETDOWN;

    case STATUS_INVALID_CONNECTION:
      return WSAENOTCONN;

    case STATUS_REMOTE_NOT_LISTENING:
    case STATUS_CONNECTION_REFUSED:
      return WSAECONNREFUSED;

    case STATUS_PIPE_DISCONNECTED:
      return WSAESHUTDOWN;

    case STATUS_CONFLICTING_ADDRESSES:
    case STATUS_INVALID_ADDRESS:
    case STATUS_INVALID_ADDRESS_COMPONENT:
      return WSAEADDRNOTAVAIL;

    case STATUS_NOT_SUPPORTED:
    case STATUS_NOT_IMPLEMENTED:
      return WSAEOPNOTSUPP;

    case STATUS_ACCESS_DENIED:
      return WSAEACCES;

    default:
      if ((status & (FACILITY_NTWIN32 << 16)) == (FACILITY_NTWIN32 << 16) &&
          (status & (ERROR_SEVERITY_ERROR | ERROR_SEVERITY_WARNING))) {
        /* It's a windows error that has been previously mapped to an */
        /* ntstatus code. */
        return (DWORD) (status & 0xffff);
      } else {
        /* The default fallback for unmappable ntstatus codes. */
        return WSAEINVAL;
      }
  }
}


/*
 * This function provides a workaround for a bug in the winsock implementation
 * of WSARecv. The problem is that when SetFileCompletionNotificationModes is
 * used to avoid IOCP notifications of completed reads, WSARecv does not
 * reliably indicate whether we can expect a completion package to be posted
 * when the receive buffer is smaller than the received datagram.
 *
 * However it is desirable to use SetFileCompletionNotificationModes because
 * it yields a massive performance increase.
 *
 * This function provides a workaround for that bug, but it only works for the
 * specific case that we need it for. E.g. it assumes that the "avoid iocp"
 * bit has been set, and supports only overlapped operation. It also requires
 * the user to use the default msafd driver, doesn't work when other LSPs are
 * stacked on top of it.
 */
int WSAAPI async_wsarecv_workaround(SOCKET socket, WSABUF* buffers, DWORD buffer_count, DWORD* bytes, DWORD* flags, WSAOVERLAPPED *overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine)
{
    NTSTATUS status;
    void* apc_context;
    IO_STATUS_BLOCK* iosb = (IO_STATUS_BLOCK*) &overlapped->Internal;
    AFD_RECV_INFO info;
    DWORD error;

    if (overlapped == NULL || completion_routine != NULL) {
        fn_WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    info.BufferArray = buffers;
    info.BufferCount = buffer_count;
    info.AfdFlags = AFD_OVERLAPPED;
    info.TdiFlags = TDI_RECEIVE_NORMAL;

    if (*flags & MSG_PEEK) {
        info.TdiFlags |= TDI_RECEIVE_PEEK;
    }

    if (*flags & MSG_PARTIAL) {
        info.TdiFlags |= TDI_RECEIVE_PARTIAL;
    }

    if (!((intptr_t) overlapped->hEvent & 1)) {
        apc_context = (void*) overlapped;
    }
    else {
        apc_context = NULL;
    }

    iosb->Pointer = 0;

    status = fn_NtDeviceIoControlFile((HANDLE)socket, overlapped->hEvent, NULL, apc_context, iosb, IOCTL_AFD_RECEIVE, &info, sizeof(info), NULL, 0);

    *flags = 0;
    *bytes = (DWORD) iosb->Information;

    switch (status) {
        case STATUS_SUCCESS:
            error = ERROR_SUCCESS;
            break;
        case STATUS_PENDING:
            error = WSA_IO_PENDING;
            break;
        case STATUS_BUFFER_OVERFLOW:
            error = WSAEMSGSIZE;
            break;
        case STATUS_RECEIVE_EXPEDITED:
            error = ERROR_SUCCESS;
            *flags = MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL_EXPEDITED:
            error = ERROR_SUCCESS;
            *flags = MSG_PARTIAL | MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL:
            error = ERROR_SUCCESS;
            *flags = MSG_PARTIAL;
            break;
        default:
            error = async_ntstatus_to_winsock_error(status);
            break;
    }

    fn_WSASetLastError(error);

    if (error == ERROR_SUCCESS) {
        return 0;
    }
    else {
        return SOCKET_ERROR;
    }
}

/* See description of async_wsarecv_workaround. */
int WSAAPI async_wsarecvfrom_workaround(SOCKET socket, WSABUF* buffers, DWORD buffer_count, DWORD* bytes, DWORD* flags, struct sockaddr* addr, int* addr_len, WSAOVERLAPPED *overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine)
{
    NTSTATUS status;
    void* apc_context;
    IO_STATUS_BLOCK* iosb = (IO_STATUS_BLOCK*) &overlapped->Internal;
    AFD_RECV_DATAGRAM_INFO info;
    DWORD error;

    if (overlapped == NULL || addr == NULL || addr_len == NULL || completion_routine != NULL) {
        fn_WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    info.BufferArray = buffers;
    info.BufferCount = buffer_count;
    info.AfdFlags = AFD_OVERLAPPED;
    info.TdiFlags = TDI_RECEIVE_NORMAL;
    info.Address = addr;
    info.AddressLength = addr_len;

    if (*flags & MSG_PEEK) {
        info.TdiFlags |= TDI_RECEIVE_PEEK;
    }

    if (*flags & MSG_PARTIAL) {
        info.TdiFlags |= TDI_RECEIVE_PARTIAL;
    }

    if (!((intptr_t) overlapped->hEvent & 1)) {
        apc_context = (void*) overlapped;
    }
    else {
        apc_context = NULL;
    }

    iosb->Status = STATUS_PENDING;
    iosb->Pointer = 0;

    status = fn_NtDeviceIoControlFile((HANDLE) socket, overlapped->hEvent, NULL, apc_context, iosb, IOCTL_AFD_RECEIVE_DATAGRAM, &info, sizeof(info), NULL, 0);

    *flags = 0;
    *bytes = (DWORD) iosb->Information;

    switch (status) {
        case STATUS_SUCCESS:
            error = ERROR_SUCCESS;
            break;
        case STATUS_PENDING:
            error = WSA_IO_PENDING;
            break;
        case STATUS_BUFFER_OVERFLOW:
            error = WSAEMSGSIZE;
            break;
        case STATUS_RECEIVE_EXPEDITED:
            error = ERROR_SUCCESS;
            *flags = MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL_EXPEDITED:
            error = ERROR_SUCCESS;
            *flags = MSG_PARTIAL | MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL:
            error = ERROR_SUCCESS;
            *flags = MSG_PARTIAL;
            break;
        default:
            error = async_ntstatus_to_winsock_error(status);
            break;
    }
    fn_WSASetLastError(error);

    if (error == ERROR_SUCCESS) {
        return 0;
    }
    else {
        return SOCKET_ERROR;
    }
}

int WSAAPI async_msafd_poll(SOCKET socket, AFD_POLL_INFO* info, OVERLAPPED* overlapped)
{
    IO_STATUS_BLOCK iosb;
    IO_STATUS_BLOCK* iosb_ptr;
    HANDLE event = NULL;
    void* apc_context;
    NTSTATUS status;
    DWORD error;

    if (overlapped != NULL) {
        /* Overlapped operation. */
        iosb_ptr = (IO_STATUS_BLOCK*) &overlapped->Internal;
        event = overlapped->hEvent;

        /* Do not report iocp completion if hEvent is tagged. */
        if ((uintptr_t) event & 1) {
            event = (HANDLE)((uintptr_t) event & ~(uintptr_t) 1);
            apc_context = NULL;
        }
        else {
            apc_context = overlapped;
        }
    }
    else {
        /* Blocking operation. */
        iosb_ptr = &iosb;
        event = fn_CreateEventW(NULL, FALSE, FALSE, NULL);
        if (event == NULL) {
            return SOCKET_ERROR;
        }
        apc_context = NULL;
    }

    iosb_ptr->Status = STATUS_PENDING;
    status = fn_NtDeviceIoControlFile((HANDLE) socket, event, NULL, apc_context, iosb_ptr, IOCTL_AFD_POLL, info, sizeof(*info), info, sizeof(*info));

    if (overlapped == NULL) {
        /* If this is a blocking operation, wait for the event to become */
        /* signaled, and then grab the real status from the io status block. */
        if (status == STATUS_PENDING) {
            DWORD r = fn_WaitForSingleObject(event, INFINITE);

            if (r == WAIT_FAILED) {
                DWORD saved_error = fn_GetLastError();
                fn_CloseHandle(event);
                fn_WSASetLastError(saved_error);
                return SOCKET_ERROR;
            }
            status = iosb.Status;
        }
        fn_CloseHandle(event);
    }

    switch (status) {
        case STATUS_SUCCESS:
            error = ERROR_SUCCESS;
            break;
        case STATUS_PENDING:
            error = WSA_IO_PENDING;
            break;
        default:
            error = async_ntstatus_to_winsock_error(status);
            break;
    }

    fn_WSASetLastError(error);

    if (error == ERROR_SUCCESS) {
        return 0;
    }
    else {
        return SOCKET_ERROR;
    }
}
