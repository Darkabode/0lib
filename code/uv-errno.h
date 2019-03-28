#ifndef ASYNC_ERRNO_H_
#define ASYNC_ERRNO_H_

#include <errno.h>

#define ASYNC__EOF     (-4095)
#define ASYNC__UNKNOWN (-4094)

#define ASYNC__EAI_ADDRFAMILY  (-3000)
#define ASYNC__EAI_AGAIN       (-3001)
#define ASYNC__EAI_BADFLAGS    (-3002)
#define ASYNC__EAI_CANCELED    (-3003)
#define ASYNC__EAI_FAIL        (-3004)
#define ASYNC__EAI_FAMILY      (-3005)
#define ASYNC__EAI_MEMORY      (-3006)
#define ASYNC__EAI_NODATA      (-3007)
#define ASYNC__EAI_NONAME      (-3008)
#define ASYNC__EAI_OVERFLOW    (-3009)
#define ASYNC__EAI_SERVICE     (-3010)
#define ASYNC__EAI_SOCKTYPE    (-3011)
#define ASYNC__EAI_BADHINTS    (-3013)
#define ASYNC__EAI_PROTOCOL    (-3014)

/* Only map to the system errno on non-Windows platforms. It's apparently
 * a fairly common practice for Windows programmers to redefine errno codes.
 */
#if defined(E2BIG) && !defined(_WIN32)
# define ASYNC__E2BIG (-E2BIG)
#else
# define ASYNC__E2BIG (-4093)
#endif

#if defined(EACCES) && !defined(_WIN32)
# define ASYNC__EACCES (-EACCES)
#else
# define ASYNC__EACCES (-4092)
#endif

#if defined(EADDRINUSE) && !defined(_WIN32)
# define ASYNC__EADDRINUSE (-EADDRINUSE)
#else
# define ASYNC__EADDRINUSE (-4091)
#endif

#if defined(EADDRNOTAVAIL) && !defined(_WIN32)
# define ASYNC__EADDRNOTAVAIL (-EADDRNOTAVAIL)
#else
# define ASYNC__EADDRNOTAVAIL (-4090)
#endif

#if defined(EAFNOSUPPORT) && !defined(_WIN32)
# define ASYNC__EAFNOSUPPORT (-EAFNOSUPPORT)
#else
# define ASYNC__EAFNOSUPPORT (-4089)
#endif

#if defined(EAGAIN) && !defined(_WIN32)
# define ASYNC__EAGAIN (-EAGAIN)
#else
# define ASYNC__EAGAIN (-4088)
#endif

#if defined(EALREADY) && !defined(_WIN32)
# define ASYNC__EALREADY (-EALREADY)
#else
# define ASYNC__EALREADY (-4084)
#endif

#if defined(EBADF) && !defined(_WIN32)
# define ASYNC__EBADF (-EBADF)
#else
# define ASYNC__EBADF (-4083)
#endif

#if defined(EBUSY) && !defined(_WIN32)
# define ASYNC__EBUSY (-EBUSY)
#else
# define ASYNC__EBUSY (-4082)
#endif

#if defined(ECANCELED) && !defined(_WIN32)
# define ASYNC__ECANCELED (-ECANCELED)
#else
# define ASYNC__ECANCELED (-4081)
#endif

#if defined(ECHARSET) && !defined(_WIN32)
# define ASYNC__ECHARSET (-ECHARSET)
#else
# define ASYNC__ECHARSET (-4080)
#endif

#if defined(ECONNABORTED) && !defined(_WIN32)
# define ASYNC__ECONNABORTED (-ECONNABORTED)
#else
# define ASYNC__ECONNABORTED (-4079)
#endif

#if defined(ECONNREFUSED) && !defined(_WIN32)
# define ASYNC__ECONNREFUSED (-ECONNREFUSED)
#else
# define ASYNC__ECONNREFUSED (-4078)
#endif

#if defined(ECONNRESET) && !defined(_WIN32)
# define ASYNC__ECONNRESET (-ECONNRESET)
#else
# define ASYNC__ECONNRESET (-4077)
#endif

#if defined(EDESTADDRREQ) && !defined(_WIN32)
# define ASYNC__EDESTADDRREQ (-EDESTADDRREQ)
#else
# define ASYNC__EDESTADDRREQ (-4076)
#endif

#if defined(EEXIST) && !defined(_WIN32)
# define ASYNC__EEXIST (-EEXIST)
#else
# define ASYNC__EEXIST (-4075)
#endif

#if defined(EFAULT) && !defined(_WIN32)
# define ASYNC__EFAULT (-EFAULT)
#else
# define ASYNC__EFAULT (-4074)
#endif

#if defined(EHOSTUNREACH) && !defined(_WIN32)
# define ASYNC__EHOSTUNREACH (-EHOSTUNREACH)
#else
# define ASYNC__EHOSTUNREACH (-4073)
#endif

#if defined(EINTR) && !defined(_WIN32)
# define ASYNC__EINTR (-EINTR)
#else
# define ASYNC__EINTR (-4072)
#endif

#if defined(EINVAL) && !defined(_WIN32)
# define ASYNC__EINVAL (-EINVAL)
#else
# define ASYNC__EINVAL (-4071)
#endif

#if defined(EIO) && !defined(_WIN32)
# define ASYNC__EIO (-EIO)
#else
# define ASYNC__EIO (-4070)
#endif

#if defined(EISCONN) && !defined(_WIN32)
# define ASYNC__EISCONN (-EISCONN)
#else
# define ASYNC__EISCONN (-4069)
#endif

#if defined(EISDIR) && !defined(_WIN32)
# define ASYNC__EISDIR (-EISDIR)
#else
# define ASYNC__EISDIR (-4068)
#endif

#if defined(ELOOP) && !defined(_WIN32)
# define ASYNC__ELOOP (-ELOOP)
#else
# define ASYNC__ELOOP (-4067)
#endif

#if defined(EMFILE) && !defined(_WIN32)
# define ASYNC__EMFILE (-EMFILE)
#else
# define ASYNC__EMFILE (-4066)
#endif

#if defined(EMSGSIZE) && !defined(_WIN32)
# define ASYNC__EMSGSIZE (-EMSGSIZE)
#else
# define ASYNC__EMSGSIZE (-4065)
#endif

#if defined(ENAMETOOLONG) && !defined(_WIN32)
# define ASYNC__ENAMETOOLONG (-ENAMETOOLONG)
#else
# define ASYNC__ENAMETOOLONG (-4064)
#endif

#if defined(ENETDOWN) && !defined(_WIN32)
# define ASYNC__ENETDOWN (-ENETDOWN)
#else
# define ASYNC__ENETDOWN (-4063)
#endif

#if defined(ENETUNREACH) && !defined(_WIN32)
# define ASYNC__ENETUNREACH (-ENETUNREACH)
#else
# define ASYNC__ENETUNREACH (-4062)
#endif

#if defined(ENFILE) && !defined(_WIN32)
# define ASYNC__ENFILE (-ENFILE)
#else
# define ASYNC__ENFILE (-4061)
#endif

#if defined(ENOBUFS) && !defined(_WIN32)
# define ASYNC__ENOBUFS (-ENOBUFS)
#else
# define ASYNC__ENOBUFS (-4060)
#endif

#if defined(ENODEV) && !defined(_WIN32)
# define ASYNC__ENODEV (-ENODEV)
#else
# define ASYNC__ENODEV (-4059)
#endif

#if defined(ENOENT) && !defined(_WIN32)
# define ASYNC__ENOENT (-ENOENT)
#else
# define ASYNC__ENOENT (-4058)
#endif

#if defined(ENOMEM) && !defined(_WIN32)
# define ASYNC__ENOMEM (-ENOMEM)
#else
# define ASYNC__ENOMEM (-4057)
#endif

#if defined(ENONET) && !defined(_WIN32)
# define ASYNC__ENONET (-ENONET)
#else
# define ASYNC__ENONET (-4056)
#endif

#if defined(ENOSPC) && !defined(_WIN32)
# define ASYNC__ENOSPC (-ENOSPC)
#else
# define ASYNC__ENOSPC (-4055)
#endif

#if defined(ENOSYS) && !defined(_WIN32)
# define ASYNC__ENOSYS (-ENOSYS)
#else
# define ASYNC__ENOSYS (-4054)
#endif

#if defined(ENOTCONN) && !defined(_WIN32)
# define ASYNC__ENOTCONN (-ENOTCONN)
#else
# define ASYNC__ENOTCONN (-4053)
#endif

#if defined(ENOTDIR) && !defined(_WIN32)
# define ASYNC__ENOTDIR (-ENOTDIR)
#else
# define ASYNC__ENOTDIR (-4052)
#endif

#if defined(ENOTEMPTY) && !defined(_WIN32)
# define ASYNC__ENOTEMPTY (-ENOTEMPTY)
#else
# define ASYNC__ENOTEMPTY (-4051)
#endif

#if defined(ENOTSOCK) && !defined(_WIN32)
# define ASYNC__ENOTSOCK (-ENOTSOCK)
#else
# define ASYNC__ENOTSOCK (-4050)
#endif

#if defined(ENOTSUP) && !defined(_WIN32)
# define ASYNC__ENOTSUP (-ENOTSUP)
#else
# define ASYNC__ENOTSUP (-4049)
#endif

#if defined(EPERM) && !defined(_WIN32)
# define ASYNC__EPERM (-EPERM)
#else
# define ASYNC__EPERM (-4048)
#endif

#if defined(EPIPE) && !defined(_WIN32)
# define ASYNC__EPIPE (-EPIPE)
#else
# define ASYNC__EPIPE (-4047)
#endif

#if defined(EPROTO) && !defined(_WIN32)
# define ASYNC__EPROTO (-EPROTO)
#else
# define ASYNC__EPROTO (-4046)
#endif

#if defined(EPROTONOSUPPORT) && !defined(_WIN32)
# define ASYNC__EPROTONOSUPPORT (-EPROTONOSUPPORT)
#else
# define ASYNC__EPROTONOSUPPORT (-4045)
#endif

#if defined(EPROTOTYPE) && !defined(_WIN32)
# define ASYNC__EPROTOTYPE (-EPROTOTYPE)
#else
# define ASYNC__EPROTOTYPE (-4044)
#endif

#if defined(EROFS) && !defined(_WIN32)
# define ASYNC__EROFS (-EROFS)
#else
# define ASYNC__EROFS (-4043)
#endif

#if defined(ESHUTDOWN) && !defined(_WIN32)
# define ASYNC__ESHUTDOWN (-ESHUTDOWN)
#else
# define ASYNC__ESHUTDOWN (-4042)
#endif

#if defined(ESPIPE) && !defined(_WIN32)
# define ASYNC__ESPIPE (-ESPIPE)
#else
# define ASYNC__ESPIPE (-4041)
#endif

#if defined(ESRCH) && !defined(_WIN32)
# define ASYNC__ESRCH (-ESRCH)
#else
# define ASYNC__ESRCH (-4040)
#endif

#if defined(ETIMEDOUT) && !defined(_WIN32)
# define ASYNC__ETIMEDOUT (-ETIMEDOUT)
#else
# define ASYNC__ETIMEDOUT (-4039)
#endif

#if defined(ETXTBSY) && !defined(_WIN32)
# define ASYNC__ETXTBSY (-ETXTBSY)
#else
# define ASYNC__ETXTBSY (-4038)
#endif

#if defined(EXDEV) && !defined(_WIN32)
# define ASYNC__EXDEV (-EXDEV)
#else
# define ASYNC__EXDEV (-4037)
#endif

#if defined(EFBIG) && !defined(_WIN32)
# define ASYNC__EFBIG (-EFBIG)
#else
# define ASYNC__EFBIG (-4036)
#endif

#if defined(ENOPROTOOPT) && !defined(_WIN32)
# define ASYNC__ENOPROTOOPT (-ENOPROTOOPT)
#else
# define ASYNC__ENOPROTOOPT (-4035)
#endif

#if defined(ERANGE) && !defined(_WIN32)
# define ASYNC__ERANGE (-ERANGE)
#else
# define ASYNC__ERANGE (-4034)
#endif

#if defined(ENXIO) && !defined(_WIN32)
# define ASYNC__ENXIO (-ENXIO)
#else
# define ASYNC__ENXIO (-4033)
#endif

#if defined(EMLINK) && !defined(_WIN32)
# define ASYNC__EMLINK (-EMLINK)
#else
# define ASYNC__EMLINK (-4032)
#endif

#endif /* ASYNC_ERRNO_H_ */
