#ifndef __COMMON_HTTPCLIENT_H_
#define __COMMON_HTTPCLIENT_H_

typedef struct _httpclient
{
    HINTERNET sessionHandle;
    wchar_t* httpMethod;
    wchar_t* httpHost;
    wchar_t* httpUserAgent;
    wchar_t* httpHeaders;
    wchar_t* httpStatusCode;
    wchar_t* httpResponseHeader;
    uint8_t* pResponse;
    uint32_t responseByteCountReceived;   // Up to 4GB.
    uint32_t responseByteCount;
    LPSTREAM pDataStream;
    uint32_t resolveTimeout;
    uint32_t connectTimeout;
    uint32_t sendTimeout;
    uint32_t receiveTimeout;
    uint32_t lastError;
} httpclient_t;

void __stdcall httpclient_init(httpclient_t* pClient, wchar_t* method, LPSTREAM pDataStream);
void __stdcall httpclient_done(httpclient_t* pClient);
int __stdcall httpclient_send_request(httpclient_t* pClient, const wchar_t* url);


#endif // __COMMON_HTTPCLIENT_H_
