#ifndef __COMMON_WIN32SERVICE_H_
#define __COMMON_WIN32SERVICE_H_

typedef struct _win32service
{
    SC_HANDLE scmHandle;
    SC_HANDLE svcHandle;
    wchar_t* name;
} win32service_t, *pwin32service_t;

pwin32service_t __stdcall service_new(const wchar_t* name);
void __stdcall service_destroy(pwin32service_t pService);
int __stdcall service_open(pwin32service_t pService);
void __stdcall service_close(pwin32service_t pService);
SC_HANDLE __stdcall service_register(pwin32service_t pService, const wchar_t* path, const wchar_t* displayName);
BOOL __stdcall service_set_config(pwin32service_t pService, DWORD type, DWORD startType, const wchar_t* binaryPath, const wchar_t* accountName);
BOOL __stdcall service_start(pwin32service_t pService);

#endif // __COMMON_WIN32SERVICE_H_