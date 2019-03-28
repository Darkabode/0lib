#include "zmodule.h"
#include "win32service.h"
#include "memory.h"
#include "string.h"

pwin32service_t __stdcall service_new(const wchar_t* name)
{
    wchar_t* ptr;
    pwin32service_t pService = memory_alloc(sizeof(win32service_t));
    pService->scmHandle = fn_OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    
    if (pService->scmHandle == NULL) {
        memory_free(pService);
        return NULL;
    }
    ptr = pService->name = zs_new(name);
    ptr = fn_StrStrW(pService->name, L".");
    if (ptr != NULL) {
        *ptr = L'\0';
    }
    zs_update_length(pService->name);
    return pService;
}

void __stdcall service_destroy(pwin32service_t pService)
{
    service_close(pService);
    fn_CloseServiceHandle(pService->scmHandle);

    zs_free(pService->name);
    memory_free(pService);
}

int __stdcall service_open(pwin32service_t pService)
{
    if (pService->svcHandle == NULL) {
        pService->svcHandle = fn_OpenServiceW(pService->scmHandle, pService->name, SERVICE_ALL_ACCESS);
    }

    return pService->svcHandle != NULL;
}

void __stdcall service_close(pwin32service_t pService)
{
    if (pService->svcHandle != NULL) {
        fn_CloseServiceHandle(pService->svcHandle);
        pService->svcHandle = NULL;
    }
}

SC_HANDLE __stdcall service_register(pwin32service_t pService, const wchar_t* path, const wchar_t* displayName)
{
    service_close(pService);
    pService->svcHandle = fn_CreateServiceW(pService->scmHandle, pService->name, displayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS/* | SERVICE_INTERACTIVE_PROCESS*/, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
    return pService->svcHandle;
}

BOOL __stdcall service_set_config(pwin32service_t pService, DWORD type, DWORD startType, const wchar_t* binaryPath, const wchar_t* accountName)
{
    service_open(pService);
    return fn_ChangeServiceConfigW(pService->svcHandle, type, startType, SERVICE_NO_CHANGE, binaryPath, NULL, NULL, NULL, accountName, NULL, NULL);
}

BOOL __stdcall service_start(pwin32service_t pService)
{
    SERVICE_STATUS svcStatus;
    long msecs = 0;

    service_open(pService);
    if (!fn_StartServiceW(pService->svcHandle, 0, NULL)) {
        return FALSE;
    }

    while (msecs < 30000) {
        if (!fn_QueryServiceStatus(pService->svcHandle, &svcStatus)) {
            break;
        }
        if (svcStatus.dwCurrentState != SERVICE_START_PENDING) {
            break;
        }
        fn_Sleep(250);
        msecs += 250;
    }

    if (!fn_QueryServiceStatus(pService->svcHandle, &svcStatus)) {
        return FALSE;
    }
    else if (svcStatus.dwCurrentState != SERVICE_RUNNING) {
        return FALSE;
    }

    return TRUE;
}
