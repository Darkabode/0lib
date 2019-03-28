#include "zmodule.h"
#include "net.h"
#include "string.h"
#include "logger.h"
#include "async.h"

#define SNTP_MSG_LEN                48
#define SNTP_PORT 123

#define SNTP_LI_NO_WARNING          0x00

#define SNTP_VERSION                (4/* NTP Version 4*/<<3) 

#define SNTP_MODE_MASK              0x07
#define SNTP_MODE_CLIENT            0x03
#define SNTP_MODE_SERVER            0x04
#define SNTP_MODE_BROADCAST         0x05

#define SNTP_STRATUM_KOD            0x00

/* number of seconds between 1900 and 1970 */
#define DIFF_SEC_1900_1970         (2208988800)

typedef struct _sntp_msg
{
    uint8_t li_vn_mode;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_identifier;
    uint32_t reference_timestamp[2];
    uint32_t originate_timestamp[2];
    uint32_t receive_timestamp[2];
    uint32_t transmit_timestamp[2];
} sntp_msg_t;

#define BUFF_SIZE 4096
char _buffer[BUFF_SIZE] = { 0 };

async_udp_t sntpUdp;
async_udp_send_t sntpUdpSend;
/*
void net_close_cb(async_handle_t* handle)
{
    //memory_free(handle);
}
*/
void net_alloc_cb(async_handle_t* handle, size_t suggested_size, async_buf_t* buf)
{
    buf->base = memory_alloc(1024);
    buf->len = 1024;
}

void net_udp_recv_cb(async_udp_t* handle, ssize_t nread, const async_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    if (buf->len >= sizeof(sntp_msg_t)) {
        sntp_msg_t* pSntpResponse = (sntp_msg_t*)buf->base;
        uint8_t mode = pSntpResponse->li_vn_mode;
        mode &= SNTP_MODE_MASK;
        if ((mode == SNTP_MODE_SERVER) || (mode == SNTP_MODE_BROADCAST)) {
            if (pSntpResponse->stratum != SNTP_STRATUM_KOD) {
                *((uint32_t*)handle->data) = fn_ntohl(pSntpResponse->receive_timestamp[0]) - DIFF_SEC_1900_1970;
            }
        }
    }
    memory_free(buf->base);
    async_close((async_handle_t*)handle, NULL/*net_close_cb*/);
}

void net_sntp_send_cb(async_udp_send_t* req, int status)
{
    if (status == 0) {
        async_udp_recv_start(req->handle, net_alloc_cb, net_udp_recv_cb);
    }
}

void net_resolver_cb(async_getaddrinfo_t* req, int status, struct addrinfo* res)
{
    sntp_msg_t sntpmsg;
    async_buf_t sendBuf;

    if (status == -1 || res == NULL) {
        return;
    }

    __stosb((uint8_t*)&sntpmsg, 0, SNTP_MSG_LEN);
    sntpmsg.li_vn_mode = SNTP_LI_NO_WARNING | SNTP_VERSION | SNTP_MODE_CLIENT;

    async_udp_init(async_default_loop(), &sntpUdp);

    sendBuf.base = (char*)&sntpmsg;
    sendBuf.len = sizeof(sntpmsg);
    sntpUdp.data = req->data;
    async_udp_send(&sntpUdpSend, &sntpUdp, &sendBuf, 1, res->ai_addr, net_sntp_send_cb);
 
    async_freeaddrinfo(res);
}

void net_get_ntp_time(uint32_t* pNtpTime)
{
    HANDLE hKey;
    // ѕолучаем им€ серваре используемого по-умолчанию в Windows.
    wchar_t* regNtpServersPath = zs_new(L"Software\\Microsoft\\Windows\\CurrentVersion\\DateTime\\Servers");
    wchar_t* defaultKey = zs_new(L"");
    wchar_t* serverNameW = NULL;
    char* serverName;
    NTSTATUS ntStatus = native_open_key(&hKey, KEY_WOW64_64KEY | KEY_READ, NATIVE_KEY_LOCAL_MACHINE, regNtpServersPath, 0);
    if (!NT_SUCCESS(ntStatus)) {
        ntStatus = native_open_key(&hKey, KEY_WOW64_32KEY | KEY_READ, NATIVE_KEY_LOCAL_MACHINE, regNtpServersPath, 0);
    }
    if (NT_SUCCESS(ntStatus)) {
        wchar_t* servNumKey = native_query_registry_string(hKey, defaultKey);
        if (servNumKey != NULL) {
            serverNameW = native_query_registry_string(hKey, servNumKey);
            zs_free(servNumKey);
        }
        zs_free(defaultKey);
        fn_NtClose(hKey);
    }

    zs_free(regNtpServersPath);

    if (serverNameW == NULL) {
        serverNameW = zs_new(L"time.windows.com");
    }

    serverName = zs_to_str(serverNameW, CP_ACP);
    zs_free(serverNameW);

    struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;

    async_getaddrinfo_t* pResolver = (async_getaddrinfo_t*)memory_alloc(sizeof(async_getaddrinfo_t));
    pResolver->data = pNtpTime;
    async_getaddrinfo(async_default_loop(), pResolver, net_resolver_cb, serverName, "123", &hints);
    memory_free(serverName);
}


//
//#define read(fd,buf,len)        recv(fd,(char*)buf,(int) len,0)
//#define write(fd,buf,len)       send(fd,(char*)buf,(int) len,0)
//#define close(fd)               closesocket(fd)
//
//static int wsa_init_done = 0;
//
///*
//* htons() is not always available.
//* By default go for LITTLE_ENDIAN variant. Otherwise hope for _BYTE_ORDER and
//* __BIG_ENDIAN to help determine endianness.
//*/
//#define POLARSSL_HTONS(n) ((((unsigned short)(n) & 0xFF      ) << 8 ) | \
//                           (((unsigned short)(n) & 0xFF00    ) >> 8 ))
//#define POLARSSL_HTONL(n) ((((unsigned long )(n) & 0xFF      ) << 24) | \
//                           (((unsigned long )(n) & 0xFF00    ) << 8 ) | \
//                           (((unsigned long )(n) & 0xFF0000  ) >> 8 ) | \
//                           (((unsigned long )(n) & 0xFF000000) >> 24))
//
//unsigned short net_htons(unsigned short n);
//unsigned long  net_htonl(unsigned long  n);
//#define net_htons(n) POLARSSL_HTONS(n)
//#define net_htonl(n) POLARSSL_HTONL(n)
//
///*
//* Prepare for using the sockets interface
//*/
//static int net_prepare(void)
//{
//    WSADATA wsaData;
//
//    if (wsa_init_done == 0)
//    {
//        if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
//            return(POLARSSL_ERR_NET_SOCKET_FAILED);
//
//        wsa_init_done = 1;
//    }
//
//    return(0);
//}
//
///*
//* Initiate a TCP connection with host:port
//*/
//int net_connect(int *fd, const char *host, int port)
//{
//    int ret;
//    struct addrinfo hints, *addr_list, *cur;
//    char port_str[6];
//
//    if ((ret = net_prepare()) != 0)
//        return(ret);
//
//    /* getaddrinfo expects port as a string */
//    __stosb(port_str, 0, sizeof(port_str));
//    fn__snprintf(port_str, sizeof(port_str), "%d", port);
//
//    /* Do name resolution with both IPv6 and IPv4, but only TCP */
//    __stosb(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//
//    if (getaddrinfo(host, port_str, &hints, &addr_list) != 0)
//        return(POLARSSL_ERR_NET_UNKNOWN_HOST);
//
//    /* Try the sockaddrs until a connection succeeds */
//    ret = POLARSSL_ERR_NET_UNKNOWN_HOST;
//    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
//    {
//        *fd = (int)socket(cur->ai_family, cur->ai_socktype,
//            cur->ai_protocol);
//        if (*fd < 0)
//        {
//            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
//            continue;
//        }
//
//        if (connect(*fd, cur->ai_addr, cur->ai_addrlen) == 0)
//        {
//            ret = 0;
//            break;
//        }
//
//        close(*fd);
//        ret = POLARSSL_ERR_NET_CONNECT_FAILED;
//    }
//
//    freeaddrinfo(addr_list);
//
//    return ret;
//}
//
///*
//* Create a listening socket on bind_ip:port
//*/
//int net_bind(int *fd, const char *bind_ip, int port)
//{
//    int n, ret;
//    struct addrinfo hints, *addr_list, *cur;
//    char port_str[6];
//
//    if ((ret = net_prepare()) != 0)
//        return(ret);
//
//    /* getaddrinfo expects port as a string */
//    __stosb(port_str, 0, sizeof(port_str));
//    fn__snprintf(port_str, sizeof(port_str), "%d", port);
//
//    /* Bind to IPv6 and/or IPv4, but only in TCP */
//    __stosb(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//    if (bind_ip == NULL)
//        hints.ai_flags = AI_PASSIVE;
//
//    if (getaddrinfo(bind_ip, port_str, &hints, &addr_list) != 0)
//        return(POLARSSL_ERR_NET_UNKNOWN_HOST);
//
//    /* Try the sockaddrs until a binding succeeds */
//    ret = POLARSSL_ERR_NET_UNKNOWN_HOST;
//    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
//    {
//        *fd = (int)socket(cur->ai_family, cur->ai_socktype,
//            cur->ai_protocol);
//        if (*fd < 0)
//        {
//            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
//            continue;
//        }
//
//        n = 1;
//        if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR,
//            (const char *)&n, sizeof(n)) != 0)
//        {
//            close(*fd);
//            ret = POLARSSL_ERR_NET_SOCKET_FAILED;
//            continue;
//        }
//
//        if (bind(*fd, cur->ai_addr, cur->ai_addrlen) != 0)
//        {
//            close(*fd);
//            ret = POLARSSL_ERR_NET_BIND_FAILED;
//            continue;
//        }
//
//        if (listen(*fd, POLARSSL_NET_LISTEN_BACKLOG) != 0)
//        {
//            close(*fd);
//            ret = POLARSSL_ERR_NET_LISTEN_FAILED;
//            continue;
//        }
//
//        /* I we ever get there, it's a success */
//        ret = 0;
//        break;
//    }
//
//    freeaddrinfo(addr_list);
//
//    return(ret);
//}
//
///*
//* Check if the requested operation would be blocking on a non-blocking socket
//* and thus 'failed' with a negative return value.
//*/
//static int net_would_block(int fd)
//{
//    ((void)fd);
//    return(WSAGetLastError() == WSAEWOULDBLOCK);
//}
//
///*
//* Accept a connection from a remote client
//*/
//int net_accept(int bind_fd, int *client_fd, void *client_ip)
//{
//    struct sockaddr_storage client_addr;
//    int n = (int) sizeof(client_addr);
//
//    *client_fd = (int)accept(bind_fd, (struct sockaddr *)&client_addr, &n);
//
//    if (*client_fd < 0)
//    {
//        if (net_would_block(*client_fd) != 0)
//            return(POLARSSL_ERR_NET_WANT_READ);
//
//        return(POLARSSL_ERR_NET_ACCEPT_FAILED);
//    }
//
//    if (client_ip != NULL) {
//        if (client_addr.ss_family == AF_INET) {
//            struct sockaddr_in *addr4 = (struct sockaddr_in *) &client_addr;
//            __movsb(client_ip, &addr4->sin_addr.s_addr, sizeof(addr4->sin_addr.s_addr));
//        }
//        else {
//            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &client_addr;
//            __movsb(client_ip, &addr6->sin6_addr.s6_addr,
//                sizeof(addr6->sin6_addr.s6_addr));
//        }
//    }
//
//    return(0);
//}
//
///*
//* Set the socket blocking or non-blocking
//*/
//int net_set_block(int fd)
//{
//    u_long n = 0;
//    return(ioctlsocket(fd, FIONBIO, &n));
//}
//
//int net_set_nonblock(int fd)
//{
//    u_long n = 1;
//    return(ioctlsocket(fd, FIONBIO, &n));
//}
//
///*
//* Portable usleep helper
//*/
//void net_usleep(unsigned long usec)
//{
//    struct timeval tv;
//    tv.tv_sec = 0;
//    tv.tv_usec = usec;
//    select(0, NULL, NULL, NULL, &tv);
//}
//
///*
//* Read at most 'len' characters
//*/
//int net_recv(void *ctx, uint8_t *buf, size_t len)
//{
//    int fd = *((int *)ctx);
//    int ret = read(fd, buf, len);
//
//    if (ret < 0)
//    {
//        if (net_would_block(fd) != 0)
//            return(POLARSSL_ERR_NET_WANT_READ);
//
//        if (WSAGetLastError() == WSAECONNRESET)
//            return(POLARSSL_ERR_NET_CONN_RESET);
//
//        return(POLARSSL_ERR_NET_RECV_FAILED);
//    }
//
//    return(ret);
//}
//
///*
//* Write at most 'len' characters
//*/
//int net_send(void *ctx, const uint8_t *buf, size_t len)
//{
//    int fd = *((int *)ctx);
//    int ret = write(fd, buf, len);
//
//    if (ret < 0)
//    {
//        if (net_would_block(fd) != 0)
//            return(POLARSSL_ERR_NET_WANT_WRITE);
//
//        if (WSAGetLastError() == WSAECONNRESET)
//            return(POLARSSL_ERR_NET_CONN_RESET);
//
//        return(POLARSSL_ERR_NET_SEND_FAILED);
//    }
//
//    return(ret);
//}
//
///*
//* Gracefully close the connection
//*/
//void net_close(int fd)
//{
//    shutdown(fd, 2);
//    close(fd);
//}
