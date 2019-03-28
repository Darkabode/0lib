#include "zmodule.h"
#include "async.h"
#include "internal.h"

int async_translate_sys_error(int sys_errno)
{
    if (sys_errno <= 0) {
        return sys_errno;  /* If < 0 then it's already a libuv error. */
    }

  switch (sys_errno) {
    case ERROR_NOACCESS:                    return ASYNC_EACCES;
    case WSAEACCES:                         return ASYNC_EACCES;
    case ERROR_ADDRESS_ALREADY_ASSOCIATED:  return ASYNC_EADDRINUSE;
    case WSAEADDRINUSE:                     return ASYNC_EADDRINUSE;
    case WSAEADDRNOTAVAIL:                  return ASYNC_EADDRNOTAVAIL;
    case WSAEAFNOSUPPORT:                   return ASYNC_EAFNOSUPPORT;
    case WSAEWOULDBLOCK:                    return ASYNC_EAGAIN;
    case WSAEALREADY:                       return ASYNC_EALREADY;
    case ERROR_INVALID_FLAGS:               return ASYNC_EBADF;
    case ERROR_INVALID_HANDLE:              return ASYNC_EBADF;
    case ERROR_LOCK_VIOLATION:              return ASYNC_EBUSY;
    case ERROR_PIPE_BUSY:                   return ASYNC_EBUSY;
    case ERROR_SHARING_VIOLATION:           return ASYNC_EBUSY;
    case ERROR_OPERATION_ABORTED:           return ASYNC_ECANCELED;
    case WSAEINTR:                          return ASYNC_ECANCELED;
    case ERROR_NO_UNICODE_TRANSLATION:      return ASYNC_ECHARSET;
    case ERROR_CONNECTION_ABORTED:          return ASYNC_ECONNABORTED;
    case WSAECONNABORTED:                   return ASYNC_ECONNABORTED;
    case ERROR_CONNECTION_REFUSED:          return ASYNC_ECONNREFUSED;
    case WSAECONNREFUSED:                   return ASYNC_ECONNREFUSED;
    case ERROR_NETNAME_DELETED:             return ASYNC_ECONNRESET;
    case WSAECONNRESET:                     return ASYNC_ECONNRESET;
    case ERROR_ALREADY_EXISTS:              return ASYNC_EEXIST;
    case ERROR_FILE_EXISTS:                 return ASYNC_EEXIST;
    case ERROR_BUFFER_OVERFLOW:             return ASYNC_EFAULT;
    case WSAEFAULT:                         return ASYNC_EFAULT;
    case ERROR_HOST_UNREACHABLE:            return ASYNC_EHOSTUNREACH;
    case WSAEHOSTUNREACH:                   return ASYNC_EHOSTUNREACH;
    case ERROR_INSUFFICIENT_BUFFER:         return ASYNC_EINVAL;
    case ERROR_INVALID_DATA:                return ASYNC_EINVAL;
    case ERROR_INVALID_PARAMETER:           return ASYNC_EINVAL;
    case ERROR_SYMLINK_NOT_SUPPORTED:       return ASYNC_EINVAL;
    case WSAEINVAL:                         return ASYNC_EINVAL;
    case WSAEPFNOSUPPORT:                   return ASYNC_EINVAL;
    case WSAESOCKTNOSUPPORT:                return ASYNC_EINVAL;
    case ERROR_BEGINNING_OF_MEDIA:          return ASYNC_EIO;
    case ERROR_BUS_RESET:                   return ASYNC_EIO;
    case ERROR_CRC:                         return ASYNC_EIO;
    case ERROR_DEVICE_DOOR_OPEN:            return ASYNC_EIO;
    case ERROR_DEVICE_REQUIRES_CLEANING:    return ASYNC_EIO;
    case ERROR_DISK_CORRUPT:                return ASYNC_EIO;
    case ERROR_EOM_OVERFLOW:                return ASYNC_EIO;
    case ERROR_FILEMARK_DETECTED:           return ASYNC_EIO;
    case ERROR_GEN_FAILURE:                 return ASYNC_EIO;
    case ERROR_INVALID_BLOCK_LENGTH:        return ASYNC_EIO;
    case ERROR_IO_DEVICE:                   return ASYNC_EIO;
    case ERROR_NO_DATA_DETECTED:            return ASYNC_EIO;
    case ERROR_NO_SIGNAL_SENT:              return ASYNC_EIO;
    case ERROR_OPEN_FAILED:                 return ASYNC_EIO;
    case ERROR_SETMARK_DETECTED:            return ASYNC_EIO;
    case ERROR_SIGNAL_REFUSED:              return ASYNC_EIO;
    case WSAEISCONN:                        return ASYNC_EISCONN;
    case ERROR_CANT_RESOLVE_FILENAME:       return ASYNC_ELOOP;
    case ERROR_TOO_MANY_OPEN_FILES:         return ASYNC_EMFILE;
    case WSAEMFILE:                         return ASYNC_EMFILE;
    case WSAEMSGSIZE:                       return ASYNC_EMSGSIZE;
    case ERROR_FILENAME_EXCED_RANGE:        return ASYNC_ENAMETOOLONG;
    case ERROR_NETWORK_UNREACHABLE:         return ASYNC_ENETUNREACH;
    case WSAENETUNREACH:                    return ASYNC_ENETUNREACH;
    case WSAENOBUFS:                        return ASYNC_ENOBUFS;
    case ERROR_DIRECTORY:                   return ASYNC_ENOENT;
    case ERROR_FILE_NOT_FOUND:              return ASYNC_ENOENT;
    case ERROR_INVALID_NAME:                return ASYNC_ENOENT;
    case ERROR_INVALID_DRIVE:               return ASYNC_ENOENT;
    case ERROR_INVALID_REPARSE_DATA:        return ASYNC_ENOENT;
    case ERROR_MOD_NOT_FOUND:               return ASYNC_ENOENT;
    case ERROR_PATH_NOT_FOUND:              return ASYNC_ENOENT;
    case WSAHOST_NOT_FOUND:                 return ASYNC_ENOENT;
    case WSANO_DATA:                        return ASYNC_ENOENT;
    case ERROR_NOT_ENOUGH_MEMORY:           return ASYNC_ENOMEM;
    case ERROR_OUTOFMEMORY:                 return ASYNC_ENOMEM;
    case ERROR_CANNOT_MAKE:                 return ASYNC_ENOSPC;
    case ERROR_DISK_FULL:                   return ASYNC_ENOSPC;
    case ERROR_EA_TABLE_FULL:               return ASYNC_ENOSPC;
    case ERROR_END_OF_MEDIA:                return ASYNC_ENOSPC;
    case ERROR_HANDLE_DISK_FULL:            return ASYNC_ENOSPC;
    case ERROR_NOT_CONNECTED:               return ASYNC_ENOTCONN;
    case WSAENOTCONN:                       return ASYNC_ENOTCONN;
    case ERROR_DIR_NOT_EMPTY:               return ASYNC_ENOTEMPTY;
    case WSAENOTSOCK:                       return ASYNC_ENOTSOCK;
    case ERROR_NOT_SUPPORTED:               return ASYNC_ENOTSUP;
    case ERROR_BROKEN_PIPE:                 return ASYNC_EOF;
    case ERROR_ACCESS_DENIED:               return ASYNC_EPERM;
    case ERROR_PRIVILEGE_NOT_HELD:          return ASYNC_EPERM;
    case ERROR_BAD_PIPE:                    return ASYNC_EPIPE;
    case ERROR_NO_DATA:                     return ASYNC_EPIPE;
    case ERROR_PIPE_NOT_CONNECTED:          return ASYNC_EPIPE;
    case WSAESHUTDOWN:                      return ASYNC_EPIPE;
    case WSAEPROTONOSUPPORT:                return ASYNC_EPROTONOSUPPORT;
    case ERROR_WRITE_PROTECT:               return ASYNC_EROFS;
    case ERROR_SEM_TIMEOUT:                 return ASYNC_ETIMEDOUT;
    case WSAETIMEDOUT:                      return ASYNC_ETIMEDOUT;
    case ERROR_NOT_SAME_DEVICE:             return ASYNC_EXDEV;
    case ERROR_INVALID_FUNCTION:            return ASYNC_EISDIR;
    case ERROR_META_EXPANSION_TOO_LONG:     return ASYNC_E2BIG;
    default:                                return ASYNC_UNKNOWN;
  }
}
