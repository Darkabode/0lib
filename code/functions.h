#ifndef __COMMON_FUNCTIONS_H_
#define __COMMON_FUNCTIONS_H_

#define KERNEL32_DLL_HASH   0x555e9a2c
#define NTDLL_DLL_HASH      0x17e2d69c

#define FUNCS_USER32 1
#define FUNCS_GDI32 1
#define FUNCS_COMCTL32 1
#define FUNCS_ADVAPI32 1
#define FUNCS_OLE32 1
#define FUNCS_SHLWAPI 1
#define FUNCS_WINMM 1
#define FUNCS_MSIMG32 1
//#define FUNCS_CRTDLL 1
#define FUNCS_WINHTTP 1
#define FUNCS_URLMON 1
#define FUNCS_SHELL32 1
#define FUNCS_PSAPI 1
#define FUNCS_IMAGEHLP 1
#define FUNCS_OLEAUT32 1
#define FUNCS_CRYPT32 1
#define FUNCS_PSTOREC 1
#define FUNCS_MSI 1
#define FUNCS_WS2_32 1
#define FUNCS_WININET 1
#define FUNCS_IPHLPAPI 1
#define FUNCS_D3D9 1
#define FUNCS_VERSION 1

// ntdll.dll
#define fn_NtCurrentTeb _pZmoduleBlock->fnNtCurrentTeb
#define fn_RtlRandomEx _pZmoduleBlock->fnRtlRandomEx
#define fn_RtlMoveMemory _pZmoduleBlock->fnRtlMoveMemory
#define fn_RtlCompareMemory _pZmoduleBlock->fnRtlCompareMemory
#define fn_ZwMapViewOfSection _pZmoduleBlock->fnZwMapViewOfSection
#define fn_NtQuerySystemInformation _pZmoduleBlock->fnNtQuerySystemInformation
#define fn_ZwUnmapViewOfSection _pZmoduleBlock->fnZwUnmapViewOfSection
#define fn_LdrUnloadDll _pZmoduleBlock->fnLdrUnloadDll
#define fn_LdrLoadDll _pZmoduleBlock->fnLdrLoadDll
#define fn_NtClose _pZmoduleBlock->fnNtClose
#define fn_RtlGetLastWin32Error _pZmoduleBlock->fnRtlGetLastWin32Error
#define fn_RtlImageDirectoryEntryToData _pZmoduleBlock->fnRtlImageDirectoryEntryToData
#define fn_RtlAddVectoredExceptionHandler _pZmoduleBlock->fnRtlAddVectoredExceptionHandler
#define fn_RtlRemoveVectoredExceptionHandler _pZmoduleBlock->fnRtlRemoveVectoredExceptionHandler
#define fn_ZwOpenSection _pZmoduleBlock->fnZwOpenSection
#define fn_RtlCompareMemory _pZmoduleBlock->fnRtlCompareMemory
#define fn_RtlInitUnicodeString _pZmoduleBlock->fnRtlInitUnicodeString
#define fn_RtlRandomEx _pZmoduleBlock->fnRtlRandomEx
#define fn_towlower _pZmoduleBlock->fntowlower
#define fn__allmul _pZmoduleBlock->fn_allmul
#define fn__allshr _pZmoduleBlock->fn_allshr
#define fn__aulldiv _pZmoduleBlock->fn_aulldiv
#define fn__aullrem _pZmoduleBlock->fn_aullrem
#define fn_RtlImageNtHeader _pZmoduleBlock->fnRtlImageNtHeader
#define fn_RtlIpv4AddressToStringW _pZmoduleBlock->fnRtlIpv4AddressToStringW
#define fn_RtlIpv6AddressToStringW _pZmoduleBlock->fnRtlIpv6AddressToStringW
#define fn_ZwOpenSymbolicLinkObject _pZmoduleBlock->fnZwOpenSymbolicLinkObject
#define fn_ZwQuerySymbolicLinkObject _pZmoduleBlock->fnZwQuerySymbolicLinkObject
#define fn_NtCreateKey _pZmoduleBlock->fnNtCreateKey
#define fn_NtOpenKey _pZmoduleBlock->fnNtOpenKey
#define fn_NtQueryValueKey _pZmoduleBlock->fnNtQueryValueKey
#define fn_NtOpenProcessToken _pZmoduleBlock->fnNtOpenProcessToken
#define fn_NtQueryInformationToken _pZmoduleBlock->fnNtQueryInformationToken
#define fn_RtlConvertSidToUnicodeString _pZmoduleBlock->fnRtlConvertSidToUnicodeString
#define fn_ZwOpenProcess _pZmoduleBlock->fnZwOpenProcess
#define fn_NtQueryInformationProcess _pZmoduleBlock->fnNtQueryInformationProcess
#define fn_ZwTerminateProcess _pZmoduleBlock->fnZwTerminateProcess
#define fn_NtEnumerateKey _pZmoduleBlock->fnNtEnumerateKey
#define fn_ZwEnumerateValueKey _pZmoduleBlock->fnZwEnumerateValueKey
#define fn_RtlDosPathNameToNtPathName_U _pZmoduleBlock->fnRtlDosPathNameToNtPathName_U
#define fn_RtlCreateHeap _pZmoduleBlock->fnRtlCreateHeap
#define fn_RtlAllocateHeap _pZmoduleBlock->fnRtlAllocateHeap
#define fn_RtlReAllocateHeap _pZmoduleBlock->fnRtlReAllocateHeap
#define fn_RtlFreeHeap _pZmoduleBlock->fnRtlFreeHeap
#define fn_NtCreateFile _pZmoduleBlock->fnNtCreateFile
#define fn_NtQueryDirectoryFile _pZmoduleBlock->fnNtQueryDirectoryFile
#define fn_NtWaitForSingleObject _pZmoduleBlock->fnNtWaitForSingleObject
#define fn_RtlSubAuthoritySid _pZmoduleBlock->fnRtlSubAuthoritySid
#define fn_NtSetValueKey _pZmoduleBlock->fnNtSetValueKey
#define fn_NtSetInformationFile _pZmoduleBlock->fnNtSetInformationFile
#define fn_NtQueryFullAttributesFile _pZmoduleBlock->fnNtQueryFullAttributesFile
#define fn_NtReadVirtualMemory _pZmoduleBlock->fnNtReadVirtualMemory
#define fn_RtlGetVersion _pZmoduleBlock->fnRtlGetVersion
#define fn_NtDeleteValueKey _pZmoduleBlock->fnNtDeleteValueKey
#define fn_RtlNtStatusToDosError _pZmoduleBlock->fnRtlNtStatusToDosError
#define fn_NtDeviceIoControlFile _pZmoduleBlock->fnNtDeviceIoControlFile
#define fn_NtQueryInformationFile _pZmoduleBlock->fnNtQueryInformationFile
#define fn_NtQueryVolumeInformationFile _pZmoduleBlock->fnNtQueryVolumeInformationFile
#define fn__snprintf _pZmoduleBlock->fn_snprintf

// kernel32.dll
#define fn_VirtualAlloc _pZmoduleBlock->fnVirtualAlloc
#define fn_GetCurrentProcessId _pZmoduleBlock->fnGetCurrentProcessId
#define fn_VirtualProtect _pZmoduleBlock->fnVirtualProtect
#define fn_ExitProcess _pZmoduleBlock->fnExitProcess
#define fn_GetExitCodeProcess _pZmoduleBlock->fnGetExitCodeProcess
#define fn_GetProcAddress _pZmoduleBlock->fnGetProcAddress
#define fn_GetCurrentProcess _pZmoduleBlock->fnGetCurrentProcess
#define fn_CreateThread _pZmoduleBlock->fnCreateThread
#define fn_CloseHandle _pZmoduleBlock->fnCloseHandle
#define fn_CopyFileW _pZmoduleBlock->fnCopyFileW
#define fn_CreateFileW _pZmoduleBlock->fnCreateFileW
#define fn_CreateFileA _pZmoduleBlock->fnCreateFileA
#define fn_GetFileSize _pZmoduleBlock->fnGetFileSize
#define fn_WriteFile _pZmoduleBlock->fnWriteFile
#define fn_CreateFileMappingW _pZmoduleBlock->fnCreateFileMappingW
#define fn_OpenFileMappingA _pZmoduleBlock->fnOpenFileMappingA
#define fn_CreateProcessW _pZmoduleBlock->fnCreateProcessW
#define fn_DeleteFileW _pZmoduleBlock->fnDeleteFileW
#define fn_MoveFileExW _pZmoduleBlock->fnMoveFileExW
#define fn_GetEnvironmentVariableW _pZmoduleBlock->fnGetEnvironmentVariableW
#define fn_GetModuleHandleW _pZmoduleBlock->fnGetModuleHandleW
#define fn_GetThreadContext _pZmoduleBlock->fnGetThreadContext
#define fn_MapViewOfFile _pZmoduleBlock->fnMapViewOfFile
#define fn_ReadFile _pZmoduleBlock->fnReadFile
#define fn_ResumeThread _pZmoduleBlock->fnResumeThread
#define fn_TerminateProcess _pZmoduleBlock->fnTerminateProcess
#define fn_UnmapViewOfFile _pZmoduleBlock->fnUnmapViewOfFile
#define fn_WaitForSingleObject _pZmoduleBlock->fnWaitForSingleObject
#define fn_VirtualQuery _pZmoduleBlock->fnVirtualQuery
#define fn_VirtualFree _pZmoduleBlock->fnVirtualFree
#define fn_IsWow64Process _pZmoduleBlock->fnIsWow64Process
#define fn_Wow64DisableWow64FsRedirection _pZmoduleBlock->fnWow64DisableWow64FsRedirection
#define fn_Wow64RevertWow64FsRedirection _pZmoduleBlock->fnWow64RevertWow64FsRedirection
#define fn_LoadLibraryW _pZmoduleBlock->fnLoadLibraryW
#define fn_LoadLibraryA _pZmoduleBlock->fnLoadLibraryA
#define fn_LoadLibraryExA _pZmoduleBlock->fnLoadLibraryExA
#define fn_SleepEx _pZmoduleBlock->fnSleepEx
#define fn_TerminateThread _pZmoduleBlock->fnTerminateThread
#define fn_CreateEventW _pZmoduleBlock->fnCreateEventW
#define fn_CreateEventA _pZmoduleBlock->fnCreateEventA
#define fn_ResetEvent _pZmoduleBlock->fnResetEvent
#define fn_SetEvent _pZmoduleBlock->fnSetEvent
#define fn_SuspendThread _pZmoduleBlock->fnSuspendThread
#define fn_CreateToolhelp32Snapshot _pZmoduleBlock->fnCreateToolhelp32Snapshot
#define fn_DeviceIoControl _pZmoduleBlock->fnDeviceIoControl
#define fn_FindClose _pZmoduleBlock->fnFindClose
#define fn_FindFirstFileW _pZmoduleBlock->fnFindFirstFileW
#define fn_FindNextFileW _pZmoduleBlock->fnFindNextFileW
#define fn_GetCurrentThreadId _pZmoduleBlock->fnGetCurrentThreadId
#define fn_GetLastError _pZmoduleBlock->fnGetLastError
#define fn_SetLastError _pZmoduleBlock->fnSetLastError
#define fn_GetModuleFileNameA _pZmoduleBlock->fnGetModuleFileNameA
#define fn_Process32FirstW _pZmoduleBlock->fnProcess32FirstW
#define fn_Process32NextW _pZmoduleBlock->fnProcess32NextW
#define fn_lstrlenW _pZmoduleBlock->fnlstrlenW
#define fn_lstrlenA _pZmoduleBlock->fnlstrlenA
#define fn_lstrcatW _pZmoduleBlock->fnlstrcatW
#define fn_lstrcatA _pZmoduleBlock->fnlstrcatA
#define fn_lstrcmpiW _pZmoduleBlock->fnlstrcmpiW
#define fn_lstrcmpiA _pZmoduleBlock->fnlstrcmpiA
#define fn_lstrcpyW _pZmoduleBlock->fnlstrcpyW
#define fn_lstrcpyA _pZmoduleBlock->fnlstrcpyA
#define fn_SetFilePointer _pZmoduleBlock->fnSetFilePointer
#define fn_CreateSemaphoreW _pZmoduleBlock->fnCreateSemaphoreW
#define fn_FreeLibrary _pZmoduleBlock->fnFreeLibrary
#define fn_GetACP _pZmoduleBlock->fnGetACP
#define fn_GetCurrentThread _pZmoduleBlock->fnGetCurrentThread
#define fn_SetThreadAffinityMask _pZmoduleBlock->fnSetThreadAffinityMask
#define fn_SetPriorityClass _pZmoduleBlock->fnSetPriorityClass
#define fn_GetSystemInfo _pZmoduleBlock->fnGetSystemInfo
#define fn_GetTempPathW _pZmoduleBlock->fnGetTempPathW
#define fn_GetLongPathNameW _pZmoduleBlock->fnGetLongPathNameW
#define fn_GetTempFileNameW _pZmoduleBlock->fnGetTempFileNameW
#define fn_Sleep _pZmoduleBlock->fnSleep
#define fn_LoadLibraryExW _pZmoduleBlock->fnLoadLibraryExW
#define fn_DuplicateHandle _pZmoduleBlock->fnDuplicateHandle
#define fn_CreateFileMappingA _pZmoduleBlock->fnCreateFileMappingA
#define fn_GetSystemDirectoryW _pZmoduleBlock->fnGetSystemDirectoryW
#define fn_ExitThread _pZmoduleBlock->fnExitThread
#define fn_GetTickCount _pZmoduleBlock->fnGetTickCount
#define fn_lstrcpynA _pZmoduleBlock->fnlstrcpynA
#define fn_lstrcpynW _pZmoduleBlock->fnlstrcpynW
#define fn_WriteProcessMemory _pZmoduleBlock->fnWriteProcessMemory
#define fn_ReadProcessMemory _pZmoduleBlock->fnReadProcessMemory
#define fn_OpenEventA _pZmoduleBlock->fnOpenEventA
#define fn_RemoveDirectoryW _pZmoduleBlock->fnRemoveDirectoryW
// #define fn_InitializeCriticalSection globalData.fnInitializeCriticalSection
// #define fn_EnterCriticalSection globalData.fnEnterCriticalSection
// #define fn_LeaveCriticalSection globalData.fnLeaveCriticalSection
// #define fn_DeleteCriticalSection globalData.fnDeleteCriticalSection
#define fn_CreateDirectoryW _pZmoduleBlock->fnCreateDirectoryW
#define fn_FlushViewOfFile _pZmoduleBlock->fnFlushViewOfFile
#define fn_GetModuleFileNameW _pZmoduleBlock->fnGetModuleFileNameW
#define fn_GetLocalTime _pZmoduleBlock->fnGetLocalTime
#define fn_SystemTimeToFileTime _pZmoduleBlock->fnSystemTimeToFileTime
#define fn_lstrcmpA _pZmoduleBlock->fnlstrcmpA
#define fn_FlushInstructionCache _pZmoduleBlock->fnFlushInstructionCache
#define fn_GetProcessHeap _pZmoduleBlock->fnGetProcessHeap
#define fn_HeapAlloc _pZmoduleBlock->fnHeapAlloc
#define fn_HeapReAlloc _pZmoduleBlock->fnHeapReAlloc
#define fn_HeapFree _pZmoduleBlock->fnHeapFree
#define fn_SetEndOfFile _pZmoduleBlock->fnSetEndOfFile
#define fn_VirtualQueryEx _pZmoduleBlock->fnVirtualQueryEx
#define fn_OpenProcess _pZmoduleBlock->fnOpenProcess
#define fn_OpenMutexA _pZmoduleBlock->fnOpenMutexA
#define fn_CreateMutexA _pZmoduleBlock->fnCreateMutexA
#define fn_ReleaseMutex _pZmoduleBlock->fnReleaseMutex
#define fn_MultiByteToWideChar _pZmoduleBlock->fnMultiByteToWideChar
#define fn_GetDateFormatA _pZmoduleBlock->fnGetDateFormatA
#define fn_GetTimeFormatA _pZmoduleBlock->fnGetTimeFormatA
#define fn_OutputDebugStringA _pZmoduleBlock->fnOutputDebugStringA
#define fn_GetExitCodeThread _pZmoduleBlock->fnGetExitCodeThread
#define fn_GetWindowsDirectoryW _pZmoduleBlock->fnGetWindowsDirectoryW
#define fn_GetFileAttributesExW _pZmoduleBlock->fnGetFileAttributesExW
#define fn_LockFileEx _pZmoduleBlock->fnLockFileEx
#define fn_UnlockFileEx _pZmoduleBlock->fnUnlockFileEx
#define fn_GlobalFree _pZmoduleBlock->fnGlobalFree
#define fn_GetLocaleInfoW _pZmoduleBlock->fnGetLocaleInfoW
#define fn_GetCurrentDirectoryW _pZmoduleBlock->fnGetCurrentDirectoryW
#define fn_SetCurrentDirectoryW _pZmoduleBlock->fnSetCurrentDirectoryW
#define fn_InitializeCriticalSection _pZmoduleBlock->fnInitializeCriticalSection
#define fn_EnterCriticalSection _pZmoduleBlock->fnEnterCriticalSection
#define fn_TryEnterCriticalSection _pZmoduleBlock->fnTryEnterCriticalSection
#define fn_LeaveCriticalSection _pZmoduleBlock->fnLeaveCriticalSection
#define fn_DeleteCriticalSection _pZmoduleBlock->fnDeleteCriticalSection
#define fn_GetStringTypeW _pZmoduleBlock->fnGetStringTypeW
#define fn_TlsSetValue _pZmoduleBlock->fnTlsSetValue
#define fn_TlsGetValue _pZmoduleBlock->fnTlsGetValue
#define fn_TlsAlloc _pZmoduleBlock->fnTlsAlloc
#define fn_TlsFree _pZmoduleBlock->fnTlsFree
#define fn_SetThreadPriority _pZmoduleBlock->fnSetThreadPriority
#define fn_OutputDebugStringW _pZmoduleBlock->fnOutputDebugStringW
#define fn_lstrcmpW _pZmoduleBlock->fnlstrcmpW
#define fn_IsDebuggerPresent _pZmoduleBlock->fnIsDebuggerPresent
// #define fn_VirtualAlloc fnVirtualAlloc
#ifdef _VIEWER
#define fn_CreateFileW fnCreateFileW
#define fn_GetFileSize fnGetFileSize
#define fn_SetFilePointer fnSetFilePointer
#define fn_ReadFile fnReadFile
#endif // _VIEWER
#define fn_GetLogicalDriveStringsW _pZmoduleBlock->fnGetLogicalDriveStringsW
#define fn_GetDriveTypeW _pZmoduleBlock->fnGetDriveTypeW
#define fn_GetFileAttributesW _pZmoduleBlock->fnGetFileAttributesW
#define fn_HeapSize _pZmoduleBlock->fnHeapSize
#define fn_HeapCreate _pZmoduleBlock->fnHeapCreate
#define fn_HeapDestroy _pZmoduleBlock->fnHeapDestroy
#define fn_WideCharToMultiByte _pZmoduleBlock->fnWideCharToMultiByte
#define fn_AreFileApisANSI _pZmoduleBlock->fnAreFileApisANSI
#define fn_FlushFileBuffers _pZmoduleBlock->fnFlushFileBuffers
#define fn_GetFullPathNameW _pZmoduleBlock->fnGetFullPathNameW
#define fn_GetSystemTime _pZmoduleBlock->fnGetSystemTime
#define fn_QueryPerformanceCounter _pZmoduleBlock->fnQueryPerformanceCounter
#define fn_QueryPerformanceFrequency _pZmoduleBlock->fnQueryPerformanceFrequency
#define fn_GlobalLock _pZmoduleBlock->fnGlobalLock
#define fn_GlobalUnlock _pZmoduleBlock->fnGlobalUnlock
#define fn_LocalFree _pZmoduleBlock->fnLocalFree
#define fn_ExpandEnvironmentStringsW _pZmoduleBlock->fnExpandEnvironmentStringsW
#define fn_GetLocaleInfoA _pZmoduleBlock->fnGetLocaleInfoA
#define fn_GetPrivateProfileStringW _pZmoduleBlock->fnGetPrivateProfileStringW
#define fn_GetPrivateProfileSectionNamesW _pZmoduleBlock->fnGetPrivateProfileSectionNamesW
#define fn_GetPrivateProfileIntW _pZmoduleBlock->fnGetPrivateProfileIntW
#define fn_WTSGetActiveConsoleSessionId _pZmoduleBlock->fnWTSGetActiveConsoleSessionId
#define fn_ProcessIdToSessionId _pZmoduleBlock->fnProcessIdToSessionId
#define fn_SetFileAttributesW _pZmoduleBlock->fnSetFileAttributesW
#define fn_GetDateFormatEx _pZmoduleBlock->fnGetDateFormatEx
#define fn_MulDiv _pZmoduleBlock->fnMulDiv
#define fn_SwitchToThread _pZmoduleBlock->fnSwitchToThread
#define fn_SetErrorMode _pZmoduleBlock->fnSetErrorMode
#define fn_CreateIoCompletionPort _pZmoduleBlock->fnCreateIoCompletionPort
#define fn_GetQueuedCompletionStatus _pZmoduleBlock->fnGetQueuedCompletionStatus
#define fn_GetQueuedCompletionStatusEx _pZmoduleBlock->fnGetQueuedCompletionStatusEx
#define fn_SetFileCompletionNotificationModes _pZmoduleBlock->fnSetFileCompletionNotificationModes
#define fn_CreateSymbolicLinkW _pZmoduleBlock->fnCreateSymbolicLinkW
#define fn_CancelIoEx _pZmoduleBlock->fnCancelIoEx
#define fn_InitializeSRWLock _pZmoduleBlock->fnInitializeSRWLock
#define fn_AcquireSRWLockShared _pZmoduleBlock->fnAcquireSRWLockShared
#define fn_AcquireSRWLockExclusive _pZmoduleBlock->fnAcquireSRWLockExclusive
#define fn_TryAcquireSRWLockShared _pZmoduleBlock->fnTryAcquireSRWLockShared
#define fn_TryAcquireSRWLockExclusive _pZmoduleBlock->fnTryAcquireSRWLockExclusive
#define fn_ReleaseSRWLockShared _pZmoduleBlock->fnReleaseSRWLockShared
#define fn_ReleaseSRWLockExclusive _pZmoduleBlock->fnReleaseSRWLockExclusive
#define fn_InitializeConditionVariable _pZmoduleBlock->fnInitializeConditionVariable
#define fn_SleepConditionVariableCS _pZmoduleBlock->fnSleepConditionVariableCS
#define fn_SleepConditionVariableSRW _pZmoduleBlock->fnSleepConditionVariableSRW
#define fn_WakeAllConditionVariable _pZmoduleBlock->fnWakeAllConditionVariable
#define fn_WakeConditionVariable _pZmoduleBlock->fnWakeConditionVariable
#define fn_GetFileInformationByHandle _pZmoduleBlock->fnGetFileInformationByHandle
#define fn_ReadDirectoryChangesW _pZmoduleBlock->fnReadDirectoryChangesW
#define fn_GetShortPathNameW _pZmoduleBlock->fnGetShortPathNameW
#define fn_GetFileType _pZmoduleBlock->fnGetFileType
#define fn_QueueUserWorkItem _pZmoduleBlock->fnQueueUserWorkItem
#define fn_SetHandleInformation _pZmoduleBlock->fnSetHandleInformation
#define fn_PostQueuedCompletionStatus _pZmoduleBlock->fnPostQueuedCompletionStatus
#define fn_CancelIo _pZmoduleBlock->fnCancelIo
#define fn_WaitForMultipleObjects _pZmoduleBlock->fnWaitForMultipleObjects
#define fn_CreateNamedPipeA _pZmoduleBlock->fnCreateNamedPipeA
#define fn_SetNamedPipeHandleState _pZmoduleBlock->fnSetNamedPipeHandleState
#define fn_CreateNamedPipeW _pZmoduleBlock->fnCreateNamedPipeW
#define fn_WaitNamedPipeW _pZmoduleBlock->fnWaitNamedPipeW
#define fn_ConnectNamedPipe _pZmoduleBlock->fnConnectNamedPipe
#define fn_RegisterWaitForSingleObject _pZmoduleBlock->fnRegisterWaitForSingleObject
#define fn_UnregisterWait _pZmoduleBlock->fnUnregisterWait
#define fn_GetProcessTimes _pZmoduleBlock->fnGetProcessTimes
#define fn_FileTimeToSystemTime _pZmoduleBlock->fnFileTimeToSystemTime
#define fn_ReleaseSemaphore _pZmoduleBlock->fnReleaseSemaphore
#define fn_CreateHardLinkW _pZmoduleBlock->fnCreateHardLinkW
#define fn_GetNamedPipeHandleStateW _pZmoduleBlock->fnGetNamedPipeHandleStateW
#define fn_SetFileTime _pZmoduleBlock->fnSetFileTime
#define fn_SetEnvironmentVariableW _pZmoduleBlock->fnSetEnvironmentVariableW
#define fn_PeekNamedPipe _pZmoduleBlock->fnPeekNamedPipe
#define fn_GlobalMemoryStatusEx _pZmoduleBlock->fnGlobalMemoryStatusEx
#define fn_FormatMessageA _pZmoduleBlock->fnFormatMessageA
#define fn_GetStdHandle _pZmoduleBlock->fnGetStdHandle
#define fn_GetConsoleCursorInfo _pZmoduleBlock->fnGetConsoleCursorInfo
#define fn_SetConsoleCursorInfo _pZmoduleBlock->fnSetConsoleCursorInfo
#define fn_SetConsoleCursorPosition _pZmoduleBlock->fnSetConsoleCursorPosition
#define fn_GetConsoleScreenBufferInfo _pZmoduleBlock->fnGetConsoleScreenBufferInfo
#define fn_WriteConsoleOutputW _pZmoduleBlock->fnWriteConsoleOutputW
#define fn_SetConsoleTextAttribute _pZmoduleBlock->fnSetConsoleTextAttribute
#define fn_WriteConsoleW _pZmoduleBlock->fnWriteConsoleW
#define fn_CancelSynchronousIo _pZmoduleBlock->fnCancelSynchronousIo

// advapi32.dll
#define fn_RegEnumKeyExW _pZmoduleBlock->fnRegEnumKeyExW
#define fn_RegOpenKeyExA _pZmoduleBlock->fnRegOpenKeyExA 
#define fn_RegOpenKeyExW _pZmoduleBlock->fnRegOpenKeyExW
#define fn_RegQueryValueExA _pZmoduleBlock->fnRegQueryValueExA
#define fn_RegQueryValueExW _pZmoduleBlock->fnRegQueryValueExW
#define fn_RegEnumKeyExA _pZmoduleBlock->fnRegEnumKeyExA 
#define fn_ConvertStringSidToSidW _pZmoduleBlock->fnConvertStringSidToSidW 
#define fn_AdjustTokenPrivileges _pZmoduleBlock->fnAdjustTokenPrivileges 
#define fn_AllocateAndInitializeSid _pZmoduleBlock->fnAllocateAndInitializeSid
#define fn_EqualSid _pZmoduleBlock->fnEqualSid 
#define fn_FreeSid _pZmoduleBlock->fnFreeSid
#define fn_GetLengthSid _pZmoduleBlock->fnGetLengthSid
#define fn_GetSidSubAuthority _pZmoduleBlock->fnGetSidSubAuthority
#define fn_GetSidSubAuthorityCount _pZmoduleBlock->fnGetSidSubAuthorityCount
#define fn_GetTokenInformation _pZmoduleBlock->fnGetTokenInformation
#define fn_LookupAccountSidA _pZmoduleBlock->fnLookupAccountSidA
#define fn_LookupPrivilegeNameW _pZmoduleBlock->fnLookupPrivilegeNameW
#define fn_LookupPrivilegeValueA _pZmoduleBlock->fnLookupPrivilegeValueA
#define fn_OpenProcessToken _pZmoduleBlock->fnOpenProcessToken
#define fn_OpenThreadToken _pZmoduleBlock->fnOpenThreadToken
#define fn_SetTokenInformation _pZmoduleBlock->fnSetTokenInformation
#define fn_RegCreateKeyExW _pZmoduleBlock->fnRegCreateKeyExW
#define fn_RegDeleteValueW _pZmoduleBlock->fnRegDeleteValueW
#define fn_RegSetValueExW _pZmoduleBlock->fnRegSetValueExW
#define fn_RegCloseKey _pZmoduleBlock->fnRegCloseKey
#define fn_IsTextUnicode _pZmoduleBlock->fnIsTextUnicode
#define fn_RegOpenKeyA _pZmoduleBlock->fnRegOpenKeyA
#define fn_RegEnumValueA _pZmoduleBlock->fnRegEnumValueA
#define fn_RegOpenKeyW _pZmoduleBlock->fnRegOpenKeyW
#define fn_CredEnumerateW _pZmoduleBlock->fnCredEnumerateW
#define fn_CredEnumerateA _pZmoduleBlock->fnCredEnumerateA
#define fn_CredFree _pZmoduleBlock->fnCredFree
#define fn_RevertToSelf _pZmoduleBlock->fnRevertToSelf
#define fn_ImpersonateLoggedOnUser _pZmoduleBlock->fnImpersonateLoggedOnUser
#define fn_CryptGetUserKey _pZmoduleBlock->fnCryptGetUserKey
#define fn_CryptExportKey _pZmoduleBlock->fnCryptExportKey
#define fn_CryptDestroyKey _pZmoduleBlock->fnCryptDestroyKey
#define fn_CryptAcquireContextW _pZmoduleBlock->fnCryptAcquireContextW
#define fn_CryptReleaseContext _pZmoduleBlock->fnCryptReleaseContext
#define fn_CryptCreateHash _pZmoduleBlock->fnCryptCreateHash
#define fn_CryptHashData _pZmoduleBlock->fnCryptHashData
#define fn_CryptGetHashParam _pZmoduleBlock->fnCryptGetHashParam
#define fn_CryptDestroyHash _pZmoduleBlock->fnCryptDestroyHash
#define fn_CryptGenRandom _pZmoduleBlock->fnCryptGenRandom
#define fn_RegOpenCurrentUser _pZmoduleBlock->fnRegOpenCurrentUser
#define fn_OpenSCManagerW _pZmoduleBlock->fnOpenSCManagerW
#define fn_CreateServiceW _pZmoduleBlock->fnCreateServiceW
#define fn_ChangeServiceConfigW _pZmoduleBlock->fnChangeServiceConfigW
#define fn_EnumServicesStatusW _pZmoduleBlock->fnEnumServicesStatusW
#define fn_CloseServiceHandle _pZmoduleBlock->fnCloseServiceHandle
#define fn_OpenServiceW _pZmoduleBlock->fnOpenServiceW
#define fn_StartServiceW _pZmoduleBlock->fnStartServiceW
#define fn_QueryServiceStatus _pZmoduleBlock->fnQueryServiceStatus
#define fn_QueryServiceConfigW _pZmoduleBlock->fnQueryServiceConfigW
#define fn_I_QueryTagInformation _pZmoduleBlock->fnI_QueryTagInformation
#define fn_StartServiceCtrlDispatcherW _pZmoduleBlock->fnStartServiceCtrlDispatcherW
#define fn_RegisterServiceCtrlHandlerW _pZmoduleBlock->fnRegisterServiceCtrlHandlerW
#define fn_SetServiceStatus _pZmoduleBlock->fnSetServiceStatus
#define fn_GetUserNameW _pZmoduleBlock->fnGetUserNameW

// user32.dll
#define fn_AttachThreadInput _pZmoduleBlock->fnAttachThreadInput
#define fn_EnumChildWindows _pZmoduleBlock->fnEnumChildWindows
#define fn_EnumWindows _pZmoduleBlock->fnEnumWindows
#define fn_GetClassNameW _pZmoduleBlock->fnGetClassNameW
#define fn_GetWindowThreadProcessId _pZmoduleBlock->fnGetWindowThreadProcessId
#define fn_IsWindowVisible _pZmoduleBlock->fnIsWindowVisible
#define fn_MapVirtualKeyA _pZmoduleBlock->fnMapVirtualKeyA
#define fn_PostMessageA _pZmoduleBlock->fnPostMessageA
#define fn_wsprintfA _pZmoduleBlock->fnwsprintfA
#define fn_wsprintfW _pZmoduleBlock->fnwsprintfW
#define fn_RegisterClassExA _pZmoduleBlock->fnRegisterClassExA
#define fn_CreateWindowExA _pZmoduleBlock->fnCreateWindowExA
#define fn_GetDC _pZmoduleBlock->fnGetDC
#define fn_ReleaseDC _pZmoduleBlock->fnReleaseDC
#define fn_DestroyWindow _pZmoduleBlock->fnDestroyWindow
#define fn_DefWindowProcW _pZmoduleBlock->fnDefWindowProcW
#define fn_ExitWindowsEx _pZmoduleBlock->fnExitWindowsEx
#define fn_GetWindowTextW _pZmoduleBlock->fnGetWindowTextW
#define fn_GetWindowRect _pZmoduleBlock->fnGetWindowRect
#define fn_mouse_event _pZmoduleBlock->fnmouse_event
#define fn_SetWindowLongA _pZmoduleBlock->fnSetWindowLongA
#define fn_GetWindowLongA _pZmoduleBlock->fnGetWindowLongA
#define fn_SetWindowLongPtrA _pZmoduleBlock->fnSetWindowLongPtrA
#define fn_GetWindowLongPtrA _pZmoduleBlock->fnGetWindowLongPtrA
#define fn_SendNotifyMessageA _pZmoduleBlock->fnSendNotifyMessageA
#define fn_FindWindowA _pZmoduleBlock->fnFindWindowA
#define fn_MessageBoxA _pZmoduleBlock->fnMessageBoxA
#define fn_MessageBoxW _pZmoduleBlock->fnMessageBoxW
#define fn_CreateWindowExW _pZmoduleBlock->fnCreateWindowExW
#define fn_OffsetRect _pZmoduleBlock->fnOffsetRect
#define fn_InflateRect _pZmoduleBlock->fnInflateRect
#define fn_UnionRect _pZmoduleBlock->fnUnionRect
#define fn_SetCursor _pZmoduleBlock->fnSetCursor
#define fn_LoadCursorW _pZmoduleBlock->fnLoadCursorW
#define fn_GetWindowLongW _pZmoduleBlock->fnGetWindowLongW
#define fn_SetWindowLongW _pZmoduleBlock->fnSetWindowLongW
#define fn_EnumDisplayMonitors _pZmoduleBlock->fnEnumDisplayMonitors
#define fn_GetKeyState _pZmoduleBlock->fnGetKeyState
#define fn_IsWindow _pZmoduleBlock->fnIsWindow
#define fn_SetTimer _pZmoduleBlock->fnSetTimer
#define fn_KillTimer _pZmoduleBlock->fnKillTimer
#define fn_GetClientRect _pZmoduleBlock->fnGetClientRect
#define fn_GetWindow _pZmoduleBlock->fnGetWindow
#define fn_SetWindowPos _pZmoduleBlock->fnSetWindowPos
#define fn_SetLayeredWindowAttributes _pZmoduleBlock->fnSetLayeredWindowAttributes
#define fn_GetCursorPos _pZmoduleBlock->fnGetCursorPos
#define fn_ScreenToClient _pZmoduleBlock->fnScreenToClient
#define fn_SendMessageW _pZmoduleBlock->fnSendMessageW
#define fn_MapWindowPoints _pZmoduleBlock->fnMapWindowPoints
#define fn_InvalidateRect _pZmoduleBlock->fnInvalidateRect
#define fn_SetCapture _pZmoduleBlock->fnSetCapture
#define fn_ReleaseCapture _pZmoduleBlock->fnReleaseCapture
#define fn_BeginPaint _pZmoduleBlock->fnBeginPaint
#define fn_EndPaint _pZmoduleBlock->fnEndPaint
#define fn_IsRectEmpty _pZmoduleBlock->fnIsRectEmpty
#define fn_GetUpdateRect _pZmoduleBlock->fnGetUpdateRect
#define fn_SetFocus _pZmoduleBlock->fnSetFocus
#define fn_GetFocus _pZmoduleBlock->fnGetFocus
#define fn_GetMessageW _pZmoduleBlock->fnGetMessageW
#define fn_DispatchMessageW _pZmoduleBlock->fnDispatchMessageW
#define fn_TranslateMessage _pZmoduleBlock->fnTranslateMessage
#define fn_PostMessageW _pZmoduleBlock->fnPostMessageW
#define fn_PtInRect _pZmoduleBlock->fnPtInRect
#define fn_GetParent _pZmoduleBlock->fnGetParent
#define fn_ShowWindow _pZmoduleBlock->fnShowWindow
#define fn_EnableWindow _pZmoduleBlock->fnEnableWindow
#define fn_PostQuitMessage _pZmoduleBlock->fnPostQuitMessage
#define fn_SystemParametersInfoW _pZmoduleBlock->fnSystemParametersInfoW
#define fn_LoadImageW _pZmoduleBlock->fnLoadImageW
#define fn_GetSystemMetrics _pZmoduleBlock->fnGetSystemMetrics
#define fn_RegisterClassW _pZmoduleBlock->fnRegisterClassW
#define fn_RegisterClassExW _pZmoduleBlock->fnRegisterClassExW
#define fn_GetClassInfoExW _pZmoduleBlock->fnGetClassInfoExW
#define fn_CallWindowProcW _pZmoduleBlock->fnCallWindowProcW
#ifdef _WIN64
#define fn_GetWindowLongPtrW _pZmoduleBlock->fnGetWindowLongPtrW
#define fn_SetWindowLongPtrW _pZmoduleBlock->fnSetWindowLongPtrW
#else
#define fn_GetWindowLongPtrW _pZmoduleBlock->fnGetWindowLongW
#define fn_SetWindowLongPtrW _pZmoduleBlock->fnSetWindowLongW
#endif // _WIN64
#define fn_GetPropW _pZmoduleBlock->fnGetPropW
#define fn_SetPropW _pZmoduleBlock->fnSetPropW
#define fn_AdjustWindowRectEx _pZmoduleBlock->fnAdjustWindowRectEx
#define fn_GetMenu _pZmoduleBlock->fnGetMenu
#define fn_IntersectRect _pZmoduleBlock->fnIntersectRect
#define fn_CharNextW _pZmoduleBlock->fnCharNextW
#define fn_FillRect _pZmoduleBlock->fnFillRect
#define fn_SetRect _pZmoduleBlock->fnSetRect
#define fn_SetWindowsHookExW _pZmoduleBlock->fnSetWindowsHookExW
#define fn_CallNextHookEx _pZmoduleBlock->fnCallNextHookEx
#define fn_UnhookWindowsHookEx _pZmoduleBlock->fnUnhookWindowsHookEx
#define fn_FindWindowExA _pZmoduleBlock->fnFindWindowExA
#define fn_CharUpperW _pZmoduleBlock->fnCharUpperW
#define fn_CharLowerW _pZmoduleBlock->fnCharLowerW
#define fn_StrToIntA _pZmoduleBlock->fnStrToIntA
#define fn_ClientToScreen _pZmoduleBlock->fnClientToScreen
#define fn_SendInput _pZmoduleBlock->fnSendInput
#define fn_SetWindowTextW _pZmoduleBlock->fnSetWindowTextW
#define fn_GetWindowTextLengthW _pZmoduleBlock->fnGetWindowTextLengthW
#define fn_CreateIconIndirect _pZmoduleBlock->fnCreateIconIndirect
#define fn_DestroyIcon _pZmoduleBlock->fnDestroyIcon
#define fn_RegisterWindowMessageW _pZmoduleBlock->fnRegisterWindowMessageW
#define fn_GetIconInfo _pZmoduleBlock->fnGetIconInfo
#define fn_DrawIconEx _pZmoduleBlock->fnDrawIconEx
#define fn_MoveWindow _pZmoduleBlock->fnMoveWindow
#define fn_CreateAcceleratorTableW _pZmoduleBlock->fnCreateAcceleratorTableW
#define fn_InvalidateRgn _pZmoduleBlock->fnInvalidateRgn
#define fn_GetForegroundWindow _pZmoduleBlock->fnGetForegroundWindow
#define fn_wvsprintfA _pZmoduleBlock->fnwvsprintfA
#define fn_wvsprintfW _pZmoduleBlock->fnwvsprintfW

// shell32.dll
#define fn_ShellExecuteExW _pZmoduleBlock->fnShellExecuteExW
#define fn_SHCreateItemFromParsingName _pZmoduleBlock->fnSHCreateItemFromParsingName
#define fn_SHGetSpecialFolderPathW _pZmoduleBlock->fnSHGetSpecialFolderPathW
#define fn_SHGetFolderPathW _pZmoduleBlock->fnSHGetFolderPathW
#define fn_Shell_NotifyIconW _pZmoduleBlock->fnShell_NotifyIconW
#define fn_SHGetFileInfoW _pZmoduleBlock->fnSHGetFileInfoW
#define fn_SHGetKnownFolderPath _pZmoduleBlock->fnSHGetKnownFolderPath


// ole32.dll
#define fn_CoInitialize _pZmoduleBlock->fnCoInitialize
#define fn_CoInitializeEx _pZmoduleBlock->fnCoInitializeEx
#define fn_CoUninitialize _pZmoduleBlock->fnCoUninitialize
#define fn_CoGetObject _pZmoduleBlock->fnCoGetObject
#define fn_CoCreateInstance _pZmoduleBlock->fnCoCreateInstance
#define fn_CreateStreamOnHGlobal _pZmoduleBlock->fnCreateStreamOnHGlobal
#define fn_GetRunningObjectTable _pZmoduleBlock->fnGetRunningObjectTable
#define fn_CreateItemMoniker _pZmoduleBlock->fnCreateItemMoniker
#define fn_CoTaskMemFree _pZmoduleBlock->fnCoTaskMemFree
#define fn_IsEqualGUID _pZmoduleBlock->fnIsEqualGUID
#define fn_GetHGlobalFromStream _pZmoduleBlock->fnGetHGlobalFromStream
#define fn_StgOpenStorage _pZmoduleBlock->fnStgOpenStorage
#define fn_OleInitialize _pZmoduleBlock->fnOleInitialize
#define fn_OleUninitialize _pZmoduleBlock->fnOleUninitialize
#define fn_CoInitializeSecurity _pZmoduleBlock->fnCoInitializeSecurity
#define fn_CoSetProxyBlanket _pZmoduleBlock->fnCoSetProxyBlanket
#define fn_CLSIDFromString _pZmoduleBlock->fnCLSIDFromString
#define fn_CLSIDFromProgID _pZmoduleBlock->fnCLSIDFromProgID
#define fn_OleLockRunning _pZmoduleBlock->fnOleLockRunning

// oleaut32.dll
#define fn_SysAllocString _pZmoduleBlock->fnSysAllocString
#define fn_SysFreeString _pZmoduleBlock->fnSysFreeString
#define fn_VariantInit _pZmoduleBlock->fnVariantInit
#define fn_VariantChangeType _pZmoduleBlock->fnVariantChangeType
#define fn_VariantClear _pZmoduleBlock->fnVariantClear

// winhttp.dll
#define fn_WinHttpCloseHandle _pZmoduleBlock->fnWinHttpCloseHandle
#define fn_WinHttpConnect _pZmoduleBlock->fnWinHttpConnect
#define fn_WinHttpOpen _pZmoduleBlock->fnWinHttpOpen
#define fn_WinHttpCrackUrl _pZmoduleBlock->fnWinHttpCrackUrl
#define fn_WinHttpOpenRequest _pZmoduleBlock->fnWinHttpOpenRequest
#define fn_WinHttpQueryHeaders _pZmoduleBlock->fnWinHttpQueryHeaders
#define fn_WinHttpReceiveResponse _pZmoduleBlock->fnWinHttpReceiveResponse
#define fn_WinHttpSendRequest _pZmoduleBlock->fnWinHttpSendRequest
#define fn_WinHttpSetOption _pZmoduleBlock->fnWinHttpSetOption
#define fn_WinHttpSetTimeouts _pZmoduleBlock->fnWinHttpSetTimeouts
#define fn_WinHttpQueryDataAvailable _pZmoduleBlock->fnWinHttpQueryDataAvailable
#define fn_WinHttpReadData _pZmoduleBlock->fnWinHttpReadData
#define fn_WinHttpAddRequestHeaders _pZmoduleBlock->fnWinHttpAddRequestHeaders
#define fn_WinHttpGetIEProxyConfigForCurrentUser _pZmoduleBlock->fnWinHttpGetIEProxyConfigForCurrentUser
#define fn_WinHttpGetProxyForUrl _pZmoduleBlock->fnWinHttpGetProxyForUrl
#define fn_WinHttpWriteData _pZmoduleBlock->fnWinHttpWriteData
// 
// // Iphlpapi.dll
// #define fn_GetAdaptersAddresses globalData.fnGetAdaptersAddresses

// ws2_32.dll
#define fn_WSAStartup _pZmoduleBlock->fnWSAStartup
#define fn_WSACleanup _pZmoduleBlock->fnWSACleanup
#define fn_WSAGetLastError _pZmoduleBlock->fnWSAGetLastError
#define fn_socket _pZmoduleBlock->fnsocket
#define fn_gethostbyname _pZmoduleBlock->fngethostbyname
#define fn_getaddrinfo _pZmoduleBlock->fngetaddrinfo
#define fn_freeaddrinfo _pZmoduleBlock->fnfreeaddrinfo
#define fn_setsockopt _pZmoduleBlock->fnsetsockopt
#define fn_getsockopt _pZmoduleBlock->fngetsockopt
#define fn_htons _pZmoduleBlock->fnhtons
#define fn_select _pZmoduleBlock->fnselect
#define fn_ntohl _pZmoduleBlock->fnntohl
#define fn_connect _pZmoduleBlock->fnconnect
#define fn_ioctlsocket _pZmoduleBlock->fnioctlsocket
#define fn_closesocket _pZmoduleBlock->fnclosesocket
#define fn_shutdown _pZmoduleBlock->fnshutdown
#define fn_send _pZmoduleBlock->fnsend
#define fn_recv _pZmoduleBlock->fnrecv
#define fn___WSAFDIsSet _pZmoduleBlock->fn__WSAFDIsSet
#define fn_inet_addr _pZmoduleBlock->fninet_addr
#define fn_WSAIoctl _pZmoduleBlock->fnWSAIoctl
#define fn_WSASetLastError _pZmoduleBlock->fnWSASetLastError
#define fn_GetAddrInfoW _pZmoduleBlock->fnGetAddrInfoW
#define fn_GetNameInfoW _pZmoduleBlock->fnGetNameInfoW
#define fn_WSASocketW _pZmoduleBlock->fnWSASocketW
#define fn_bind _pZmoduleBlock->fnbind
#define fn_WSARecv _pZmoduleBlock->fnWSARecv
#define fn_getsockname _pZmoduleBlock->fngetsockname
#define fn_getpeername _pZmoduleBlock->fngetpeername
#define fn_WSASend _pZmoduleBlock->fnWSASend
#define fn_listen _pZmoduleBlock->fnlisten
#define fn_WSADuplicateSocketW _pZmoduleBlock->fnWSADuplicateSocketW
#define fn_WSASendTo _pZmoduleBlock->fnWSASendTo
#define fn_WSARecvFrom _pZmoduleBlock->fnWSARecvFrom
#define fn_htonl _pZmoduleBlock->fnhtonl
#define fn_FreeAddrInfoW _pZmoduleBlock->fnFreeAddrInfoW

// shlwapi.dll
#define fn_StrCmpIW _pZmoduleBlock->fnStrCmpIW
#define fn_StrCmpNIW _pZmoduleBlock->fnStrCmpNIW
#define fn_StrStrW _pZmoduleBlock->fnStrStrW
#define fn_StrCmpNW _pZmoduleBlock->fnStrCmpNW
#define fn_wvnsprintfW _pZmoduleBlock->fnwvnsprintfW
#define fn_PathCombineW _pZmoduleBlock->fnPathCombineW
#define fn_PathAppendW _pZmoduleBlock->fnPathAppendW
#define fn_PathRemoveFileSpecW _pZmoduleBlock->fnPathRemoveFileSpecW
#define fn_PathFindFileNameA _pZmoduleBlock->fnPathFindFileNameA
#ifdef LOG_ON
#define fn_PathFindFileNameW _pZmoduleBlock->fnPathFindFileNameW
#endif // LOG_ON
#define fn_StrToIntW _pZmoduleBlock->fnStrToIntW
#define fn_StrStrIW _pZmoduleBlock->fnStrStrIW
#define fn_wnsprintfW _pZmoduleBlock->fnwnsprintfW
#define fn_StrChrA _pZmoduleBlock->fnStrChrA
#define fn_StrToInt64ExA _pZmoduleBlock->fnStrToInt64ExA
#define fn_StrRChrIW _pZmoduleBlock->fnStrRChrIW
#define fn_StrStrIA _pZmoduleBlock->fnStrStrIA
#define fn_StrStrA _pZmoduleBlock->fnStrStrA
#define fn_StrCmpNIA _pZmoduleBlock->fnStrCmpNIA

// Iphlpapi.dll
#define fn_GetExtendedTcpTable _pZmoduleBlock->fnGetExtendedTcpTable
#define fn_GetExtendedUdpTable _pZmoduleBlock->fnGetExtendedUdpTable

// psapi.dll
#define fn_EnumProcessModules _pZmoduleBlock->fnEnumProcessModules
#define fn_GetProcessImageFileNameW _pZmoduleBlock->fnGetProcessImageFileNameW
#define fn_GetModuleFileNameExW _pZmoduleBlock->fnGetModuleFileNameExW
#define fn_GetModuleBaseNameW _pZmoduleBlock->fnGetModuleBaseNameW
#define fn_GetProcessMemoryInfo _pZmoduleBlock->fnGetProcessMemoryInfo

// imagehlp.dll
#define fn_CheckSumMappedFile _pZmoduleBlock->fnCheckSumMappedFile

// urlmon.dll
#define fn_ObtainUserAgentString _pZmoduleBlock->fnObtainUserAgentString

// version.dll
#define fn_GetFileVersionInfoSizeW _pZmoduleBlock->fnGetFileVersionInfoSizeW
#define fn_GetFileVersionInfoW _pZmoduleBlock->fnGetFileVersionInfoW
#define fn_VerQueryValueW _pZmoduleBlock->fnVerQueryValueW

// gdi32.dll
#define fn_GetObjectW _pZmoduleBlock->fnGetObjectW
#define fn_GetObjectA _pZmoduleBlock->fnGetObjectA
#define fn_GetStockObject _pZmoduleBlock->fnGetStockObject
#define fn_CreateFontIndirectW _pZmoduleBlock->fnCreateFontIndirectW
#define fn_CreatePen _pZmoduleBlock->fnCreatePen
#define fn_SelectObject _pZmoduleBlock->fnSelectObject
#define fn_DeleteObject _pZmoduleBlock->fnDeleteObject
#define fn_DeleteDC _pZmoduleBlock->fnDeleteDC
#define fn_SaveDC _pZmoduleBlock->fnSaveDC
#define fn_RestoreDC _pZmoduleBlock->fnRestoreDC
#define fn_SetWindowOrgEx _pZmoduleBlock->fnSetWindowOrgEx
#define fn_Rectangle _pZmoduleBlock->fnRectangle
#define fn_BitBlt _pZmoduleBlock->fnBitBlt
#define fn_CreateCompatibleBitmap _pZmoduleBlock->fnCreateCompatibleBitmap
#define fn_CreateCompatibleDC _pZmoduleBlock->fnCreateCompatibleDC
#define fn_GetTextMetricsW _pZmoduleBlock->fnGetTextMetricsW
#define fn_SelectClipRgn _pZmoduleBlock->fnSelectClipRgn
#define fn_GetObjectType _pZmoduleBlock->fnGetObjectType
#define fn_ExtSelectClipRgn _pZmoduleBlock->fnExtSelectClipRgn
#define fn_CreateRectRgnIndirect _pZmoduleBlock->fnCreateRectRgnIndirect
#define fn_GetClipBox _pZmoduleBlock->fnGetClipBox
#define fn_CombineRgn _pZmoduleBlock->fnCombineRgn
#define fn_CreateRoundRectRgn _pZmoduleBlock->fnCreateRoundRectRgn
#define fn_CreateSolidBrush _pZmoduleBlock->fnCreateSolidBrush
#define fn_CreateDIBSection _pZmoduleBlock->fnCreateDIBSection
#define fn_StretchBlt _pZmoduleBlock->fnStretchBlt
#define fn_MoveToEx _pZmoduleBlock->fnMoveToEx
#define fn_LineTo _pZmoduleBlock->fnLineTo
#define fn_CreatePenIndirect _pZmoduleBlock->fnCreatePenIndirect
#define fn_RoundRect _pZmoduleBlock->fnRoundRect
#define fn_DrawTextW _pZmoduleBlock->fnDrawTextW
#define fn_SetTextColor _pZmoduleBlock->fnSetTextColor
#define fn_SetBkMode _pZmoduleBlock->fnSetBkMode
#define fn_CharPrevW _pZmoduleBlock->fnCharPrevW
#define fn_TextOutW _pZmoduleBlock->fnTextOutW
#define fn_GetTextExtentPoint32W _pZmoduleBlock->fnGetTextExtentPoint32W
#define fn_GetCharABCWidthsW _pZmoduleBlock->fnGetCharABCWidthsW
#define fn_SetBkColor _pZmoduleBlock->fnSetBkColor
#define fn_GdiFlush _pZmoduleBlock->fnGdiFlush
#define fn_IsIconic _pZmoduleBlock->fnIsIconic
#define fn_GetMonitorInfoW _pZmoduleBlock->fnGetMonitorInfoW
#define fn_MonitorFromWindow _pZmoduleBlock->fnMonitorFromWindow
#define fn_SetWindowRgn _pZmoduleBlock->fnSetWindowRgn
#define fn_IsZoomed _pZmoduleBlock->fnIsZoomed
#define fn_SetStretchBltMode _pZmoduleBlock->fnSetStretchBltMode
#define fn_ExtTextOutW _pZmoduleBlock->fnExtTextOutW
#define fn_GetPixel _pZmoduleBlock->fnGetPixel
#define fn_SetPixel _pZmoduleBlock->fnSetPixel
#define fn_GetDeviceCaps _pZmoduleBlock->fnGetDeviceCaps

// comctl32.dll
#define fn_InitCommonControlsEx _pZmoduleBlock->fnInitCommonControlsEx
#define fn__TrackMouseEvent _pZmoduleBlock->fn_TrackMouseEvent

// winmm.dll
#define fn_timeGetTime _pZmoduleBlock->fntimeGetTime

// msimg32.dll
#define fn_AlphaBlend _pZmoduleBlock->fnAlphaBlend
#define fn_GradientFill _pZmoduleBlock->fnGradientFill

// iphlpapi.dll
#define fn_GetAdaptersInfo _pZmoduleBlock->fnGetAdaptersInfo
#define fn_GetAdaptersAddresses _pZmoduleBlock->fnGetAdaptersAddresses

// crypt32.dll
#define fn_CryptUnprotectData _pZmoduleBlock->fnCryptUnprotectData
#define fn_CertOpenSystemStoreW _pZmoduleBlock->fnCertOpenSystemStoreW
#define fn_CertEnumCertificatesInStore _pZmoduleBlock->fnCertEnumCertificatesInStore
#define fn_CryptAcquireCertificatePrivateKey _pZmoduleBlock->fnCryptAcquireCertificatePrivateKey
#define fn_CertCloseStore _pZmoduleBlock->fnCertCloseStore

// pstorec.dll
#define fn_PStoreCreateInstance _pZmoduleBlock->fnPStoreCreateInstance

// msi.dll
#define fn_MsiGetComponentPathW _pZmoduleBlock->fnMsiGetComponentPathW

#ifdef FUNCS_CRTDLL
// crtdll.dll
#define fn_atof _pZmoduleBlock->fnatof
#define fn_cos _pZmoduleBlock->fncos
#define fn_sin _pZmoduleBlock->fnsin
#define fn_abs _pZmoduleBlock->fnabs
#endif // FUNCS_CRTDLL

// d3d9.dll
#define fn_Direct3DCreate9 _pZmoduleBlock->fnDirect3DCreate9


// gdiplus.dll
#define fn_GdipAlloc fnGdipAlloc
#define fn_GdipFree fnGdipFree
#define fn_GdiplusStartup fnGdiplusStartup
#define fn_GdiplusShutdown fnGdiplusShutdown
#define fn_GdipDeleteBrush fnGdipDeleteBrush
#define fn_GdipCloneBrush fnGdipCloneBrush
#define fn_GdipCreateFontFromLogfontA fnGdipCreateFontFromLogfontA
#define fn_GdipSetStringFormatLineAlign fnGdipSetStringFormatLineAlign
#define fn_GdipSetTextRenderingHint fnGdipSetTextRenderingHint
#define fn_GdipDeleteFont fnGdipDeleteFont
#define fn_GdipDeleteGraphics fnGdipDeleteGraphics
#define fn_GdipSetStringFormatAlign fnGdipSetStringFormatAlign
#define fn_GdipDrawString fnGdipDrawString
#define fn_GdipCreateFromHDC fnGdipCreateFromHDC
#define fn_GdipCreateLineBrushI fnGdipCreateLineBrushI
#define fn_GdipCreateStringFormat fnGdipCreateStringFormat
#define fn_GdipDeleteStringFormat fnGdipDeleteStringFormat
#define fn_GdipCreateFontFromDC fnGdipCreateFontFromDC


#define fn_GetDateFormatA _pZmoduleBlock->fnGetDateFormatA
#define fn_GetTimeFormatA _pZmoduleBlock->fnGetTimeFormatA
#define fn_wsprintfA _pZmoduleBlock->fnwsprintfA
#define fn_PathFindFileNameW _pZmoduleBlock->fnPathFindFileNameW
#define fn_GetCurrentProcessId _pZmoduleBlock->fnGetCurrentProcessId
#define fn_wvsprintfA _pZmoduleBlock->fnwvsprintfA
#define fn_OutputDebugStringA _pZmoduleBlock->fnOutputDebugStringA
#define fn_PathFindFileNameW _pZmoduleBlock->fnPathFindFileNameW


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// ntdll.dll
#ifdef fn_NtCurrentTeb
#define NtCurrentTeb_Hash 0xF8E2B6C0
typedef struct _TEB* (__stdcall *FnNtCurrentTeb)(void);
#endif

#ifdef fn_ZwMapViewOfSection
#define ZwMapViewOfSection_Hash 0x822E15D3
	typedef NTSTATUS(__stdcall *FnZwMapViewOfSection)(HANDLE pSectionHandle, HANDLE processHandle, pvoid_t* pBaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
		PLARGE_INTEGER SectionOffset, PSIZE_T pViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType,
		ULONG Win32Protect);
#endif


	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#ifdef fn_NtQuerySystemInformation
#define NtQuerySystemInformation_Hash 0xDC19D0FE
	typedef NTSTATUS(__stdcall *FnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, pvoid_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
#endif

#ifdef fn_ZwUnmapViewOfSection
#define ZwUnmapViewOfSection_Hash 0x5E521536
	typedef NTSTATUS(__stdcall *FnZwUnmapViewOfSection)(HANDLE ProcessHandle, pvoid_t BaseAddress);
#endif

#ifdef fn_LdrUnloadDll
#define LdrUnloadDll_Hash 0x589269C7
	typedef NTSTATUS(__stdcall *FnLdrUnloadDll)(HANDLE ModuleHandle);
#endif

#ifdef fn_LdrLoadDll
#define LdrLoadDll_Hash 0x972252BA
	typedef NTSTATUS(__stdcall *FnLdrLoadDll)(HANDLE ModuleHandle);
#endif

#ifdef fn_NtClose
#define NtClose_Hash 0x9292A4AE
	typedef NTSTATUS(__stdcall *FnNtClose)(HANDLE Handle);
#endif

#ifdef fn_RtlGetLastWin32Error
#define RtlGetLastWin32Error_Hash 0xC07AF9CD
	typedef NTSTATUS(__stdcall *FnRtlGetLastWin32Error)();
#endif

#ifdef fn_RtlImageDirectoryEntryToData
#define RtlImageDirectoryEntryToData_Hash 0x37A1D404
	typedef pvoid_t(__stdcall *FnRtlImageDirectoryEntryToData)(pvoid_t Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size);
#endif

#ifdef fn_RtlAddVectoredExceptionHandler
#define RtlAddVectoredExceptionHandler_Hash 0xDA51D006
	typedef PVOID(__stdcall *FnRtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
#endif

#ifdef fn_RtlRemoveVectoredExceptionHandler
#define RtlRemoveVectoredExceptionHandler_Hash 0xF6D6C110
	typedef ULONG(__stdcall *FnRtlRemoveVectoredExceptionHandler)(PVOID Handle);
#endif

#ifdef fn_ZwOpenSection
#define ZwOpenSection_Hash 0x78BF0F50
	typedef NTSTATUS(__stdcall *FnZwOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
#endif

#ifdef fn_RtlCompareMemory
#define RtlCompareMemory_Hash 0x9AAF0C5D
	typedef SIZE_T(__stdcall *FnRtlCompareMemory)(const VOID *Source1, const VOID *Source2, SIZE_T Length);
#endif

#ifdef fn_RtlInitUnicodeString
#define RtlInitUnicodeString_Hash 0x4B211890
	typedef VOID(__stdcall *FnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
#endif

#ifdef fn_RtlRandomEx
#define RtlRandomEx_Hash 0x52BAFCD6
	typedef ULONG(__stdcall *FnRtlRandomEx)(PULONG Seed);
#endif

#ifdef fn_towlower
#define towlower_Hash 0x5702CAC5
	typedef unsigned short(__cdecl *Fntowlower)(unsigned short _C);
#endif

#ifdef fn__allmul
#define _allmul_Hash 0xD56276B9
	typedef INT64(__cdecl *Fn_allmul)(int64_t a, int64_t b);
#endif

#ifdef fn__allshr
#define _allshr_Hash 0xD3C28EBF
	typedef int64_t(__cdecl *Fn_allshr)(int64_t, int);
#endif

#ifdef fn__aulldiv
#define _aulldiv_Hash 0x56DA7AC4
	typedef INT64(__cdecl *Fn_aulldiv)(uint64_t a, uint64_t b);
#endif

#ifdef fn__aullrem
#define _aullrem_Hash 0x565AB2BB
	typedef UINT64(__cdecl *Fn_aullrem)(uint64_t a, uint64_t b);
#endif

#ifdef fn_RtlMoveMemory
#define RtlMoveMemory_Hash 0x99F2FFD7
	typedef VOID(__stdcall *FnRtlMoveMemory)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
#endif

#ifdef fn_RtlImageNtHeader
#define RtlImageNtHeader_Hash 0x97BED953
	typedef PIMAGE_NT_HEADERS(__stdcall *FnRtlImageNtHeader)(PVOID Base);
#endif

#ifdef fn_RtlIpv4AddressToStringW
#define RtlIpv4AddressToStringW_Hash 0x8A7C55BA
	typedef PWSTR(__stdcall *FnRtlIpv4AddressToStringW)(struct in_addr *Addr, PWSTR S);
#endif

#ifdef fn_RtlIpv6AddressToStringW
#define RtlIpv6AddressToStringW_Hash 0x8A7E55BA
	typedef PWSTR(__stdcall *FnRtlIpv6AddressToStringW)(struct in6_addr *Addr, PWSTR S);
#endif

#ifdef fn_ZwOpenSymbolicLinkObject
#define ZwOpenSymbolicLinkObject_Hash 0xD7263D09
	typedef NTSTATUS(__stdcall *FnZwOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
#endif

#ifdef fn_ZwQuerySymbolicLinkObject
#define ZwQuerySymbolicLinkObject_Hash 0xA9233D42
	typedef NTSTATUS(__stdcall *FnZwQuerySymbolicLinkObject)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
#endif

#define NtCreateKey_Hash 0x58AA31D3
typedef NTSTATUS(__stdcall *FnNtCreateKey)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);

#ifdef fn_NtOpenKey
#define NtOpenKey_Hash 0xD6925AC3
typedef NTSTATUS(__stdcall *FnNtOpenKey)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
#endif

#ifdef fn_NtQueryValueKey
#define NtQueryValueKey_Hash 0x291ECBD7
	typedef NTSTATUS(__stdcall *FnNtQueryValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
#endif

#ifdef fn_NtOpenProcessToken
#define NtOpenProcessToken_Hash 0x90114399
	typedef NTSTATUS(__stdcall *FnNtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
#endif

#ifdef fn_NtQueryInformationToken
#define NtQueryInformationToken_Hash 0x2C7264A9
	typedef NTSTATUS(__stdcall *FnNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
#endif

#ifdef fn_RtlConvertSidToUnicodeString
#define RtlConvertSidToUnicodeString_Hash 0x53701BC9
	typedef NTSTATUS(__stdcall *FnRtlConvertSidToUnicodeString)(PUNICODE_STRING UnicodeString, PSID Sid, BOOLEAN AllocateDestinationString);
#endif

#ifdef fn_ZwOpenProcess
#define ZwOpenProcess_Hash 0x39FF194C
	typedef NTSTATUS(__stdcall *FnZwOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
#endif

#ifdef fn_NtQueryInformationProcess
#define NtQueryInformationProcess_Hash 0xD8328722
	typedef NTSTATUS(__stdcall *FnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
#endif

#ifdef fn_ZwTerminateProcess
#define ZwTerminateProcess_Hash 0x2B8E45CE
	typedef NTSTATUS(__stdcall *FnZwTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
#endif

#ifdef fn_NtEnumerateKey
#define NtEnumerateKey_Hash 0xF95E7E5D
	typedef NTSTATUS(__stdcall *FnNtEnumerateKey)(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
#endif

#ifdef fn_ZwEnumerateValueKey
#define ZwEnumerateValueKey_Hash 0x8145CEFD
	typedef NTSTATUS(__stdcall *FnZwEnumerateValueKey)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
#endif

#ifdef fn_RtlDosPathNameToNtPathName_U
#define RtlDosPathNameToNtPathName_U_Hash 0x9DD02714
typedef BOOLEAN (_stdcall *FnRtlDosPathNameToNtPathName_U)(PWSTR DosPathName, PUNICODE_STRING NtPathName, PWSTR * NtFileNamePart, PCURDIR DirectoryInfo);
#endif

#ifdef fn_RtlCreateHeap
#define RtlCreateHeap_Hash 0xD74B28B9
typedef PVOID (*FnRtlCreateHeap)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters);
#endif

#ifdef fn_RtlAllocateHeap
#define RtlAllocateHeap_Hash 0x982320C0
typedef PVOID (__stdcall *FnRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
#endif

#ifdef fn_RtlReAllocateHeap
#define RtlReAllocateHeap_Hash 0xC8312743
typedef PVOID (__stdcall *FnRtlReAllocateHeap)(PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer, ULONG Size);
#endif

#ifdef fn_RtlFreeHeap
#define RtlFreeHeap_Hash 0x15EACABF
typedef BOOLEAN (__stdcall *FnRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
#endif

#ifdef fn_NtCreateFile
#define NtCreateFile_Hash 0xB8CB25A8
typedef NTSTATUS (__stdcall *FnNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
#endif

#ifdef fn_NtQueryDirectoryFile
#define NtQueryDirectoryFile_Hash 0xB40946D9
typedef NTSTATUS (__stdcall *FnNtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event OPTIONAL, PIO_APC_ROUTINE ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName OPTIONAL, BOOLEAN RestartScan);
#endif

#ifdef fn_NtWaitForSingleObject
#define NtWaitForSingleObject_Hash 0x3507E5DC
typedef NTSTATUS (__stdcall *FnNtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout OPTIONAL);
#endif

#define RtlSubAuthoritySid_Hash 0x1B0CC655
typedef PULONG(__stdcall *FnRtlSubAuthoritySid)(PSID Sid, ULONG SubAuthority);

#define NtSetValueKey_Hash 0x57EEB2D5
typedef NTSTATUS(__stdcall *FnNtSetValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);

#define NtSetInformationFile_Hash 0xCB3337DB
typedef NTSTATUS(__stdcall *FnNtSetInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

#define NtQueryFullAttributesFile_Hash 0xF767786F
typedef NTSTATUS (__stdcall *FnNtQueryFullAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation);

#define NtReadVirtualMemory_Hash 0xDA7D2722
typedef NTSTATUS(__stdcall *FnNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);

#define RtlGetVersion_Hash 0x1A530DCB
typedef NTSTATUS(__stdcall *FnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

#define NtDeleteValueKey_Hash 0x18BEBCDB
typedef NTSTATUS (__stdcall *FnNtDeleteValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName);


#ifndef SystemProcessorPerformanceInformation
# define SystemProcessorPerformanceInformation 8
#endif

typedef VOID(__stdcall* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

#define RtlNtStatusToDosError_Hash 0xDF8F843C
typedef ULONG(__stdcall* FnRtlNtStatusToDosError)(NTSTATUS Status);

#define NtDeviceIoControlFile_Hash 0x6269527B
typedef NTSTATUS(__stdcall *FnNtDeviceIoControlFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

#define NtQueryInformationFile_Hash 0x9341C15C
typedef NTSTATUS(__stdcall* FnNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

#define NtQueryVolumeInformationFile_Hash 0xC1726674
typedef NTSTATUS(NTAPI *FnNtQueryVolumeInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FS_INFORMATION_CLASS FsInformationClass);

#define _snprintf_Hash 0x193AF7B6
typedef int (__cdecl *Fn_snprintf)(char * _DstBuf, size_t _MaxCount, const char * _Format, ...);

// kernel32.dll
#ifdef fn_GetCurrentProcessId
#define GetCurrentProcessId_Hash 0x2A133F32
	typedef DWORD(__stdcall *FnGetCurrentProcessId)(void);
#endif

#ifdef fn_IsBadReadPtr
#define IsBadReadPtr_Hash 0xD97E9040
	typedef BOOL(__stdcall *FnIsBadReadPtr)(VOID* lp, UINT_PTR ucb);
#endif

#ifdef fn_VirtualProtect
#define VirtualProtect_Hash 0x492F12D7
	typedef BOOL(__stdcall *FnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
#endif

#ifdef fn_ExitProcess
#define ExitProcess_Hash 0x9A06E1C7
	typedef VOID(__stdcall *FnExitProcess)(UINT uExitCode);
#endif

#ifdef fn_GetExitCodeProcess
#define GetExitCodeProcess_Hash 0xAADC30F0
	typedef BOOL(__stdcall *FnGetExitCodeProcess)(HANDLE hProcess, LPDWORD lpExitCode);
#endif

#ifdef fn_GetProcAddress
#define GetProcAddress_Hash 0xE98905D0
	typedef FARPROC(__stdcall *FnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
#endif

#ifdef fn_GetCurrentProcess
#define GetCurrentProcess_Hash 0xB3883CCF
	typedef HANDLE(__stdcall *FnGetCurrentProcess)();
#endif

#ifdef fn_CreateThread
#define CreateThread_Hash 0xF80ABF42
	typedef HANDLE(__stdcall *FnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
#endif

#ifdef fn_CloseHandle
#define CloseHandle_Hash 0xD8368FC2
	typedef BOOL(__stdcall *FnCloseHandle)(HANDLE hHandle);
#endif

#ifdef fn_CopyFileW
#define CopyFileW_Hash 0x947AE5A7
	typedef BOOL(__stdcall *FnCopyFileW)(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);
#endif

#ifdef fn_CreateFileW
#define CreateFileW_Hash 0xD516DFB6
	typedef HANDLE(__stdcall *FnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#endif

#ifdef fn_CreateFileA
#define CreateFileA_Hash 0xD516DFA0
	typedef HANDLE(__stdcall *FnCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#endif

#ifdef fn_GetFileSize
#define GetFileSize_Hash 0x78DEF0B5
	typedef DWORD(__stdcall *FnGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
#endif

#ifdef fn_WriteFile
#define WriteFile_Hash 0x5762E3A2
	typedef DWORD(__stdcall *FnWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
#endif

#ifdef fn_CreateFileMappingW
#define CreateFileMappingW_Hash 0xD149415A
	typedef HANDLE(__stdcall *FnCreateFileMappingW)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
#endif

#ifdef fn_OpenFileMappingA
#define OpenFileMappingA_Hash 0xB0B93CA4
	typedef HANDLE(WINAPI *FnOpenFileMappingA)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);
#endif

#ifdef fn_CreateProcessW
#define CreateProcessW_Hash 0xB91D423B
	typedef BOOL(__stdcall *FnCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
#endif

#ifdef fn_DeleteFileW
#define DeleteFileW_Hash 0x353AE6B5
	typedef BOOL(__stdcall *FnDeleteFileW)(LPCWSTR lpFileName);
#endif

#ifdef fn_MoveFileExW
#define MoveFileExW_Hash 0xFA1E5CA8
	typedef BOOL(__stdcall *FnMoveFileExW)(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags);
#endif

#ifdef fn_GetEnvironmentVariableW
#define GetEnvironmentVariableW_Hash 0xFAEC7CFF
	typedef DWORD(__stdcall *FnGetEnvironmentVariableW)(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
#endif

#ifdef fn_GetModuleHandleW
#define GetModuleHandleW_Hash 0xC1232F70
	typedef HMODULE(__stdcall *FnGetModuleHandleW)(LPCWSTR lpModuleName);
#endif

#ifdef fn_GetThreadContext
#define GetThreadContext_Hash 0xF3B32112
	typedef BOOL(__stdcall *FnGetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);
#endif

#ifdef fn_SetThreadContext
#define SetThreadContext_Hash 0x53B32113
	typedef BOOL(__stdcall *FnSetThreadContext)(HANDLE hThread, const CONTEXT* lpContext);
#endif

#ifdef fn_MapViewOfFile
#define MapViewOfFile_Hash 0x68CADC35
	typedef LPVOID(__stdcall *FnMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
#endif

#ifdef fn_ReadFile
#define ReadFile_Hash 0x565266A1
	typedef BOOL(__stdcall *FnReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
#endif

#ifdef fn_OpenThread
#define OpenThread_Hash 0x75CAACC2
	typedef HANDLE(__stdcall *FnOpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
#endif

#ifdef fn_ResumeThread
#define ResumeThread_Hash 0xB79EDAC4
	typedef DWORD(__stdcall *FnResumeThread)(HANDLE hThread);
#endif

#ifdef fn_TerminateProcess
#define TerminateProcess_Hash 0x2B173A8E
	typedef BOOL(__stdcall *FnTerminateProcess)(HANDLE hProcess, UINT uExitCode);
#endif

#ifdef fn_UnmapViewOfFile
#define UnmapViewOfFile_Hash 0x69A6F177
	typedef BOOL(__stdcall *FnUnmapViewOfFile)(LPCVOID lpBaseAddress);
#endif

#ifdef fn_WaitForSingleObject
#define WaitForSingleObject_Hash 0x34CDE0FC
	typedef DWORD(__stdcall *FnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
#endif

#ifdef fn_VirtualAlloc
#define VirtualAlloc_Hash 0x973F27BF
	typedef LPVOID(__stdcall *FnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
#endif

#ifdef fn_VirtualQuery
#define VirtualQuery_Hash 0x189F0BDA
	typedef SIZE_T(WINAPI *FnVirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
#endif

#ifdef fn_VirtualFree
#define VirtualFree_Hash 0x785AFCB2
	typedef BOOL(__stdcall *FnVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
#endif

#ifdef fn_IsWow64Process
#define IsWow64Process_Hash 0xA940DA4E
	typedef BOOL(__stdcall *FnIsWow64Process) (HANDLE hProcess, PBOOL Wow64Process);
#endif

#ifdef fn_Wow64DisableWow64FsRedirection
#define Wow64DisableWow64FsRedirection_Hash 0x275A5FAA
	typedef BOOL(__stdcall *FnWow64DisableWow64FsRedirection)(PVOID *OldValue);
#endif

#define Wow64RevertWow64FsRedirection_Hash 0x79589F78
typedef BOOL (__stdcall *FnWow64RevertWow64FsRedirection)(PVOID OlValue);

#ifdef fn_LoadLibraryW
#define LoadLibraryW_Hash 0xFA5F16AD
	typedef HMODULE(__stdcall *FnLoadLibraryW) (LPCWSTR lpModuleName);
#endif

#ifdef fn_LoadLibraryA
#define LoadLibraryA_Hash 0xFA5F1697
	typedef HMODULE(__stdcall *FnLoadLibraryA) (LPCSTR lpModuleName);
#endif

#ifdef fn_LoadLibraryExA
#define LoadLibraryExA_Hash 0x8B5A702A
	typedef HMODULE(__stdcall *FnLoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
#endif

#ifdef fn_SleepEx
#define SleepEx_Hash 0x4EF298BF
	typedef DWORD(__stdcall *FnSleepEx)(DWORD dwMilliseconds, BOOL bAlertable);
#endif

#ifdef fn_TerminateThread
#define TerminateThread_Hash 0x38B0E94B
	typedef DWORD(__stdcall *FnTerminateThread)(HANDLE hThread, DWORD dwExitCode);
#endif

#ifdef fn_CreateEventW
#define CreateEventW_Hash 0x7B4AC52F
	typedef HANDLE(__stdcall *FnCreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
#endif

#ifdef fn_CreateEventA
#define CreateEventA_Hash 0x7B4AC519
	typedef HANDLE(__stdcall *FnCreateEventA)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
#endif

#ifdef fn_ResetEvent
#define ResetEvent_Hash 0x95AAE1D2
	typedef BOOL(__stdcall *FnResetEvent)(HANDLE hEvent);
#endif

#ifdef fn_SetEvent
#define SetEvent_Hash 0x54AA7CC8
	typedef BOOL(__stdcall *FnSetEvent)(HANDLE hEvent);
#endif

#ifdef fn_SuspendThread
#define SuspendThread_Hash 0x47DEDC49
	typedef DWORD(__stdcall *FnSuspendThread)(HANDLE hThread);
#endif

#ifdef fn_CreateToolhelp32Snapshot
#define CreateToolhelp32Snapshot_Hash 0xA0D07883
	typedef HANDLE(__stdcall *FnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
#endif

#ifdef fn_Thread32First
#define Thread32First_Hash 0x37AAC1C7
	typedef BOOL(__stdcall *FnThread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
#endif

#ifdef fn_Thread32Next
#define Thread32Next_Hash 0x56CA89C2
	typedef BOOL(__stdcall *FnThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
#endif

#ifdef fn_DeviceIoControl
#define DeviceIoControl_Hash 0xDA91354A
	typedef BOOL(__stdcall *FnDeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
#endif

#ifdef fn_FindClose
#define FindClose_Hash 0x95DACAB6
	typedef BOOL(__stdcall *FnFindClose)(HANDLE hFindFile);
#endif

#ifdef fn_FindFirstFileW
#define FindFirstFileW_Hash 0xA6AF38B7
	typedef HANDLE(__stdcall *FnFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
#endif

#ifdef fn_FindNextFileW
#define FindNextFileW_Hash 0x75E31B3A
	typedef BOOL(__stdcall *FnFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
#endif

#ifdef fn_GetCurrentThreadId
#define GetCurrentThreadId_Hash 0x14F63B67
	typedef DWORD(__stdcall *FnGetCurrentThreadId)();
#endif

#ifdef fn_GetFileSize
#define GetFileSize_Hash 0x78DEF0B5
	typedef DWORD(__stdcall *FnGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
#endif

#ifdef fn_GetLastError
#define GetLastError_Hash 0x56CF2056
	typedef DWORD(__stdcall *FnGetLastError)();
#endif

#ifdef fn_SetLastError
#define SetLastError_Hash 0x56CF2656
	typedef VOID(__stdcall *FnSetLastError)(DWORD dwErrCode);
#endif 

#ifdef fn_GetModuleFileNameA
#define GetModuleFileNameA_Hash 0x17BE1B43
	typedef DWORD(__stdcall *FnGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
#endif

#ifdef fn_Process32FirstW
#define Process32FirstW_Hash 0xE9231131
	typedef BOOL(__stdcall *FnProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
#endif

#ifdef fn_Process32NextW
#define Process32NextW_Hash 0x1926EF2A
	typedef BOOL(__stdcall *FnProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
#endif

#ifdef fn_lstrlenW
#define lstrlenW_Hash 0xD8427CA9
	typedef int(__stdcall *FnlstrlenW)(LPCWSTR lpString);
#endif

#ifdef fn_lstrlenA
#define lstrlenA_Hash 0xD8427C93
	typedef int(__stdcall *FnlstrlenA)(LPCSTR lpString);
#endif

#ifdef fn_lstrcatW
#define lstrcatW_Hash 0x59026CA5
	typedef LPWSTR(__stdcall *FnlstrcatW)(LPWSTR lpString1, LPWSTR lpString2);
#endif

#ifdef fn_lstrcatA
#define lstrcatA_Hash 0x59026C8F
	typedef LPWSTR(__stdcall *FnlstrcatA)(LPSTR lpString1, LPSTR lpString2);
#endif

#ifdef fn_lstrcmpiW
#define lstrcmpiW_Hash 0x96EB10AA
	typedef INT(__stdcall *FnlstrcmpiW)(LPWSTR lpString1, LPWSTR lpString2);
#endif

#ifdef fn_lstrcmpiA
#define lstrcmpiA_Hash 0x96EB1094
	typedef INT(__stdcall *FnlstrcmpiA)(LPSTR lpString1, LPSTR lpString2);
#endif

#ifdef fn_lstrcpyW
#define lstrcpyW_Hash 0x59A2A8A5
	typedef LPWSTR(__stdcall *FnlstrcpyW)(LPWSTR lpString1, LPCWSTR lpString2);
#endif

#ifdef fn_lstrcpyA
#define lstrcpyA_Hash 0x59A2A88F
	typedef LPWSTR(__stdcall *FnlstrcpyA)(LPSTR lpString1, LPSTR lpString2);
#endif

#ifdef fn_SetFilePointer
#define SetFilePointer_Hash 0x881954D0
	typedef LPWSTR(__stdcall *FnSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
#endif

#ifdef fn_CreateSemaphoreW
#define CreateSemaphoreW_Hash 0x60E96439
	typedef HANDLE(__stdcall *FnCreateSemaphoreW)(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName);
#endif

#ifdef fn_FreeLibrary
#define FreeLibrary_Hash 0x58A2BBD3
	typedef BOOL(__stdcall *FnFreeLibrary)(HMODULE hModule);
#endif

#ifdef fn_GetACP
#define GetACP_Hash 0x0EB1928A
	typedef UINT(__stdcall *FnGetACP)();
#endif

#ifdef fn_GetCurrentThread
#define GetCurrentThread_Hash 0xC0C2F58E
	typedef HANDLE(__stdcall *FnGetCurrentThread)(void);
#endif

#ifdef fn_SetThreadAffinityMask
#define SetThreadAffinityMask_Hash 0x3C579F34
	typedef DWORD_PTR(__stdcall *FnSetThreadAffinityMask)(HANDLE hThread, DWORD_PTR dwThreadAffinityMask);
#endif

#ifdef fn_SetPriorityClass
#define SetPriorityClass_Hash 0x90673B1B
	typedef BOOL(__stdcall *FnSetPriorityClass)(HANDLE hProcess, DWORD dwPriorityClass);
#endif

#ifdef fn_GetSystemInfo
#define GetSystemInfo_Hash 0x68FB2E3F
	typedef void(__stdcall *FnGetSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
#endif

#ifdef fn_GetTempPathW
#define GetTempPathW_Hash 0x56BF2831
	typedef DWORD(__stdcall *FnGetTempPathW)(DWORD nBufferLength, LPWSTR lpBuffer);
#endif

#ifdef fn_GetLongPathNameW
#define GetLongPathNameW_Hash 0x6F2B2578
	typedef DWORD(__stdcall *FnGetLongPathNameW)(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer);
#endif

#ifdef fn_GetTempFileNameW
#define GetTempFileNameW_Hash 0x0F671078
	typedef UINT(__stdcall *FnGetTempFileNameW)(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
#endif

#ifdef fn_Sleep
#define Sleep_Hash 0x11D194A6
	typedef VOID(__stdcall *FnSleep)(DWORD dwMilliseconds);
#endif

#ifdef fn_LoadLibraryExW
#define LoadLibraryExW_Hash 0x8B5A7040
	typedef HMODULE(__stdcall *FnLoadLibraryExW)(LPCWSTR lpFileName, HANDLE hFile, DWORD dwFlags);
#endif

#ifdef fn_DuplicateHandle
#define DuplicateHandle_Hash 0xB9C0C8C8
	typedef BOOL(__stdcall *FnDuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess,
		BOOL bInheritHandle, DWORD dwOptions);
#endif

#ifdef fn_CreateFileMappingA
#define CreateFileMappingA_Hash 0xD1494144
	typedef HANDLE(__stdcall *FnCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
#endif

#ifdef fn_GetSystemDirectoryW
#define GetSystemDirectoryW_Hash 0x5101551B
	typedef UINT(__stdcall *FnGetSystemDirectoryW)(LPWSTR lpBuffer, UINT uSize);
#endif

#ifdef fn_ExitThread
#define ExitThread_Hash 0xB5EAB4C2
	typedef VOID(WINAPI *FnExitThread)(DWORD dwExitCode);
#endif

#ifdef fn_GetTickCount
#define GetTickCount_Hash 0xD6CF2252
	typedef DWORD(WINAPI *FnGetTickCount)(void);
#endif

#ifdef fn_lstrcpynA
#define lstrcpynA_Hash 0x178B3496
	typedef LPSTR(WINAPI *FnlstrcpynA)(LPSTR lpString1, LPCSTR lpString2, int iMaxLength);
#endif

#ifdef fn_lstrcpynW
#define lstrcpynW_Hash 0x178B34AC
	typedef LPSTR(WINAPI *FnlstrcpynW)(LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength);
#endif

#ifdef fn_WriteProcessMemory
#define WriteProcessMemory_Hash 0x03231CC1
	typedef BOOL(WINAPI *FnWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
#endif

#ifdef fn_ReadProcessMemory
#define ReadProcessMemory_Hash 0xE3010D20
	typedef BOOL(WINAPI *FnReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
#endif

#ifdef fn_OpenEventA
#define OpenEventA_Hash 0xF90AB298
	typedef HANDLE(WINAPI *FnOpenEventA)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);
#endif

#ifdef fn_RemoveDirectoryW
#define RemoveDirectoryW_Hash 0xDC614BF9
	typedef BOOL(WINAPI *FnRemoveDirectoryW)(LPCWSTR lpPathName);
#endif

#ifdef fn_InitializeCriticalSection
#define InitializeCriticalSection_Hash 0xD3BFF1B5
	typedef void (WINAPI *FnInitializeCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
#endif

#ifdef fn_EnterCriticalSection
#define EnterCriticalSection_Hash 0x1282A915
	typedef void (WINAPI *FnEnterCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
#endif

#ifdef fn_TryEnterCriticalSection
#define TryEnterCriticalSection_Hash 0xF697B0A5
	typedef BOOL(WINAPI *FnTryEnterCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
#endif

#ifdef fn_LeaveCriticalSection
#define LeaveCriticalSection_Hash 0x869726B4
	typedef void (WINAPI *FnLeaveCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
#endif

#ifdef fn_DeleteCriticalSection
#define DeleteCriticalSection_Hash 0xA2A1AB74
	typedef void (WINAPI *FnDeleteCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
#endif

#ifdef fn_CreateDirectoryW
#define CreateDirectoryW_Hash 0x84514E38
	typedef BOOL(WINAPI *FnCreateDirectoryW)(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
#endif

#ifdef fn_FlushViewOfFile
#define FlushViewOfFile_Hash 0xE982F6B7
	typedef BOOL(WINAPI *FnFlushViewOfFile)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush);
#endif

#ifdef fn_GetModuleFileNameW
#define GetModuleFileNameW_Hash 0x17BE1B59
	typedef DWORD(WINAPI *FnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
#endif

#ifdef fn_GetLocalTime
#define GetLocalTime_Hash 0x596ED636
	typedef void (WINAPI *FnGetLocalTime)(LPSYSTEMTIME lpSystemTime);
#endif

#ifdef fn_SystemTimeToFileTime
#define SystemTimeToFileTime_Hash 0x74FCCBDF
	typedef BOOL(WINAPI *FnSystemTimeToFileTime)(const SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime);
#endif

#ifdef fn_lstrcmpA
#define lstrcmpA_Hash 0x58829C8F
	typedef int(__stdcall *FnlstrcmpA)(LPCSTR lpString1, LPCSTR lpString2);
#endif

#ifdef fn_lstrcmpW
#define lstrcmpW_Hash 0x58829CA5
	typedef int(__stdcall *FnlstrcmpW)(LPCWSTR lpString1, LPCWSTR lpString2);
#endif

#ifdef fn_FlushInstructionCache
#define FlushInstructionCache_Hash 0x13D34409
	typedef BOOL(WINAPI *FnFlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
#endif

#ifdef fn_GetProcessHeap
#define GetProcessHeap_Hash 0xE83923C1
	typedef HANDLE(WINAPI *FnGetProcessHeap)(void);
#endif

#ifdef fn_HeapCreate
#define HeapCreate_Hash 0x98AA6FBC
	typedef HANDLE(WINAPI *FnHeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
#endif

#ifdef fn_HeapDestroy
#define HeapDestroy_Hash 0xB9B2F3D0
	typedef BOOL(WINAPI *FnHeapDestroy)(HANDLE hHeap);
#endif

#ifdef fn_HeapSize
#define HeapSize_Hash 0xD88266A7
	typedef SIZE_T(WINAPI *FnHeapSize)(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
#endif

#ifdef fn_HeapAlloc
#define HeapAlloc_Hash 0x551AD8B1
	typedef LPVOID(WINAPI *FnHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#endif

#ifdef fn_HeapReAlloc
#define HeapReAlloc_Hash 0x3692DBBA
	typedef LPVOID(WINAPI *FnHeapReAlloc)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
#endif

#ifdef fn_HeapFree
#define HeapFree_Hash 0x55E28AA1
	typedef BOOL(WINAPI *FnHeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
#endif

#ifdef fn_SetEndOfFile
#define SetEndOfFile_Hash 0x98E6B12F
	typedef BOOL(WINAPI *FnSetEndOfFile)(HANDLE hFile);
#endif

#ifdef fn_VirtualQueryEx
#define VirtualQueryEx_Hash 0x84CF68DA
	typedef SIZE_T(WINAPI *FnVirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
#endif

#ifdef fn_OpenProcess
#define OpenProcess_Hash 0x99FEDDC6
	typedef HANDLE(WINAPI *FnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
#endif

#ifdef fn_OpenMutexA
#define OpenMutexA_Hash 0x797A9EA0
	typedef HANDLE(WINAPI *FnOpenMutexA)(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);
#endif

#ifdef fn_CreateMutexA
#define CreateMutexA_Hash 0xFBBAB120
	typedef HANDLE(WINAPI *FnCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
#endif

#ifdef fn_ReleaseMutex
#define ReleaseMutex_Hash 0xD60F28DC
typedef BOOL (__stdcall *FnReleaseMutex)(HANDLE hMutex);
#endif

#ifdef fn_MultiByteToWideChar
#define MultiByteToWideChar_Hash 0xBBAF3AA4
	typedef int(__stdcall *FnMultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
#endif

#ifdef fn_GetDateFormatA
#define GetDateFormatA_Hash 0x8A69109B
	typedef int(__stdcall *FnGetDateFormatA)(LCID Locale, DWORD dwFlags, CONST SYSTEMTIME* lpDate, LPCSTR lpFormat, LPSTR lpDateStr, int cchDate);
#endif

#ifdef fn_GetTimeFormatA
#define GetTimeFormatA_Hash 0x8AA9099C
	typedef int(__stdcall *FnGetTimeFormatA)(LCID Locale, DWORD dwFlags, CONST SYSTEMTIME* lpTime, LPCSTR lpFormat, LPSTR lpTimeStr, int cchTime);
#endif

#ifdef fn_OutputDebugStringA
#define OutputDebugStringA_Hash 0x7A2E5D81
	typedef void(__stdcall *FnOutputDebugStringA)(LPCSTR lpOutputString);
#endif

#ifdef fn_OutputDebugStringW
#define OutputDebugStringW_Hash 0x7A2E5D97
	typedef void(__stdcall *FnOutputDebugStringW)(LPCWSTR lpOutputString);
#endif

#ifdef fn_GetExitCodeThread
#define GetExitCodeThread_Hash 0x6063FD49
	typedef BOOL(__stdcall *FnGetExitCodeThread)(HANDLE hThread, LPDWORD lpExitCode);
#endif

#ifdef fn_GetCurrentDirectoryW
#define GetCurrentDirectoryW_Hash 0xE90DD9BB
	typedef DWORD(__stdcall *FnGetCurrentDirectoryW)(DWORD nBufferLength, LPWSTR lpBuffer);
#endif

#ifdef fn_SetCurrentDirectoryW
#define SetCurrentDirectoryW_Hash 0xE913D9BB
	typedef BOOL(__stdcall *FnSetCurrentDirectoryW)(LPCWSTR lpPathName);
#endif

#ifdef fn_GetStringTypeW
#define GetStringTypeW_Hash 0xE7053AC3
	typedef BOOL(__stdcall *FnGetStringTypeW)(DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType);
#endif

#ifdef fn_TlsSetValue
#define TlsSetValue_Hash 0x57EB0BBC
	typedef BOOL(__stdcall *FnTlsSetValue)(DWORD dwTlsIndex, LPVOID lpTlsValue);
#endif

#ifdef fn_TlsGetValue
#define TlsGetValue_Hash 0x578B0BBC
	typedef LPVOID(__stdcall *FnTlsGetValue)(DWORD dwTlsIndex);
#endif

#ifdef fn_TlsAlloc
#define TlsAlloc_Hash 0x149296B4
	typedef DWORD(__stdcall *FnTlsAlloc)(void);
#endif

#ifdef fn_TlsFree
#define TlsFree_Hash 0x13D2A09D
	typedef BOOL(__stdcall *FnTlsFree)(DWORD dwTlsIndex);
#endif

#ifdef fn_SetThreadPriority
#define SetThreadPriority_Hash 0x628230E4
	typedef BOOL(__stdcall *FnSetThreadPriority)(HANDLE hThread, int nPriority);
#endif

#ifdef fn_SetThreadAffinityMask
#define SetThreadAffinityMask_Hash 0x3C579F34
	typedef DWORD_PTR(__stdcall *FnSetThreadAffinityMask)(HANDLE hThread, DWORD_PTR dwThreadAffinityMask);
#endif

#ifdef fn_GetLocaleInfoW
#define GetLocaleInfoW_Hash 0x4738FFBD
	typedef int(__stdcall *FnGetLocaleInfoW)(LCID Locale, LCTYPE LCType, LPTSTR lpLCData, int cchData);
#endif

#ifdef fn_IsDebuggerPresent
#define IsDebuggerPresent_Hash 0x32522958
	typedef BOOL(__stdcall *FnIsDebuggerPresent)(void);
#endif

#ifdef fn_WideCharToMultiByte
#define WideCharToMultiByte_Hash 0x8F3F7099
	typedef int(__stdcall *FnWideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
#endif

#ifdef fn_AreFileApisANSI
#define AreFileApisANSI_Hash 0x6622A2D9
	typedef BOOL(__stdcall *FnAreFileApisANSI)(void);
#endif

#ifdef fn_LockFileEx
#define LockFileEx_Hash 0x524A8FD2
	typedef BOOL(__stdcall *FnLockFileEx)(HANDLE hFile, DWORD dwFlags, DWORD dwReserved, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh, LPOVERLAPPED lpOverlapped);
#endif

#ifdef fn_UnlockFileEx
#define UnlockFileEx_Hash 0x5402BA56
	typedef BOOL(__stdcall *FnUnlockFileEx)(HANDLE hFile, DWORD dwReserved, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh, LPOVERLAPPED lpOverlapped);
#endif

#ifdef fn_FlushFileBuffers
#define FlushFileBuffers_Hash 0x19CD39CD
	typedef BOOL(__stdcall *FnFlushFileBuffers)(HANDLE hFile);
#endif

#ifdef fn_GetFileAttributesExW
#define GetFileAttributesExW_Hash 0x07664945
	typedef BOOL(__stdcall *FnGetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
#endif

#ifdef fn_GetFileAttributesW
#define GetFileAttributesW_Hash 0x3B7E19A4
	typedef DWORD(WINAPI *FnGetFileAttributesW)(LPCWSTR lpFileName);
#endif

#ifdef fn_GetFullPathNameW
#define GetFullPathNameW_Hash 0xAF232878
	typedef DWORD(__stdcall *FnGetFullPathNameW)(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart);
#endif

#ifdef fn_GetSystemTime
#define GetSystemTime_Hash 0xE9DB1A3A
	typedef void(__stdcall *FnGetSystemTime)(LPSYSTEMTIME lpSystemTime);
#endif

#ifdef fn_QueryPerformanceCounter
#define QueryPerformanceCounter_Hash 0x182FB225
	typedef BOOL(__stdcall *FnQueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount);
#endif

#ifdef fn_QueryPerformanceFrequency
#define QueryPerformanceFrequency_Hash 0xCB508DD5
	typedef BOOL(__stdcall *FnQueryPerformanceFrequency)(LARGE_INTEGER *lpFrequency);
#endif

#ifdef fn_GlobalLock
#define GlobalLock_Hash 0x769AEAB2
	typedef LPVOID(__stdcall *FnGlobalLock)(HGLOBAL hMem);
#endif

#ifdef fn_GlobalUnlock
#define GlobalUnlock_Hash 0xF7FAEC49
	typedef BOOL(__stdcall *FnGlobalUnlock)(HGLOBAL hMem);
#endif

#ifdef fn_GlobalFree
#define GlobalFree_Hash 0x76DAF6A9
	typedef HGLOBAL(__stdcall *FnGlobalFree)(HGLOBAL hMem);
#endif 

#ifdef fn_LocalFree
#define LocalFree_Hash 0xD6DAD6A0
	typedef HLOCAL(__stdcall *FnLocalFree)(HLOCAL hMem);
#endif

#ifdef fn_ExpandEnvironmentStringsW
#define ExpandEnvironmentStringsW_Hash 0x1DC16025
	typedef DWORD(WINAPI *FnExpandEnvironmentStringsW)(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize);
#endif

#ifdef fn_WTSGetActiveConsoleSessionId
#define WTSGetActiveConsoleSessionId_Hash 0xD6ADBE78
	typedef DWORD(__stdcall *FnWTSGetActiveConsoleSessionId)(void);
#endif

#ifdef fn_ProcessIdToSessionId
#define ProcessIdToSessionId_Hash 0xB59C4E6F
	typedef BOOL(__stdcall *FnProcessIdToSessionId)(DWORD dwProcessId, DWORD* pSessionId);
#endif

#ifdef fn_GetLocaleInfoA
#define GetLocaleInfoA_Hash 0x4738FFA7
	typedef int(__stdcall *FnGetLocaleInfoA)(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData);
#endif

#ifdef fn_GetWindowsDirectoryW
#define GetWindowsDirectoryW_Hash 0x2901DD3C
	typedef UINT(WINAPI *FnGetWindowsDirectoryW)(LPWSTR lpBuffer, UINT uSize);
#endif

#ifdef fn_GetPrivateProfileStringW
#define GetPrivateProfileStringW_Hash 0xC616B372
	typedef DWORD(WINAPI *FnGetPrivateProfileStringW)(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault, LPWSTR lpReturnedString, DWORD nSize, LPCWSTR lpFileName);
#endif

#ifdef fn_GetPrivateProfileSectionNamesW
#define GetPrivateProfileSectionNamesW_Hash 0x65FBD0F1
	typedef DWORD(WINAPI *FnGetPrivateProfileSectionNamesW)(LPWSTR lpszReturnBuffer, DWORD nSize, LPCWSTR lpFileName);
#endif

#ifdef fn_GetPrivateProfileIntW
#define GetPrivateProfileIntW_Hash 0x72A9DE20
	typedef UINT(WINAPI *FnGetPrivateProfileIntW)(LPCWSTR lpAppName, LPCWSTR lpKeyName, INT nDefault, LPCWSTR lpFileName);
#endif

#ifdef fn_GetFileAttributesExW
#define GetFileAttributesExW_Hash 0x07664945
	typedef BOOL(__stdcall *FnGetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
#endif

#ifdef fn_GetLogicalDriveStringsW
#define GetLogicalDriveStringsW_Hash 0xB8A80B23
	typedef DWORD(__stdcall *FnGetLogicalDriveStringsW)(DWORD nBufferLength, LPWSTR lpBuffer);
#endif

#ifdef fn_GetDriveTypeW
#define GetDriveTypeW_Hash 0x06FB2F3E
	typedef UINT(__stdcall *FnGetDriveTypeW)(LPCWSTR lpRootPathName);
#endif

#ifdef fn_SetFileAttributesW
#define SetFileAttributesW_Hash 0x3B7E1B24
	typedef BOOL(__stdcall *FnSetFileAttributesW)(LPCWSTR lpFileName, DWORD dwFileAttributes);
#endif

#ifdef fn_GetDateFormatEx
#define GetDateFormatEx_Hash 0x13F14D9A
	typedef int(__stdcall *FnGetDateFormatEx)(LPCWSTR lpLocaleName, DWORD dwFlags, const SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate, LPCWSTR lpCalendar);
#endif

#ifdef fn_MulDiv
#define MulDiv_Hash 0x1471AAAC
	typedef int(__stdcall *FnMulDiv)(int nNumber, int nNumerator, int nDenominator);
#endif

#define SwitchToThread_Hash 0xA7B8D94C
typedef BOOL (__stdcall *FnSwitchToThread)(void);

#define SetErrorMode_Hash 0x98C70936
typedef UINT (__stdcall *FnSetErrorMode)(UINT uMode);

#define CreateIoCompletionPort_Hash 0x1DA0E7AF
typedef HANDLE (__stdcall *FnCreateIoCompletionPort)(HANDLE FileHandle, HANDLE ExistingCompletionPort, ULONG_PTR CompletionKey, DWORD NumberOfConcurrentThreads);

#define GetQueuedCompletionStatus_Hash 0x717CC8B1
typedef BOOL (__stdcall *FnGetQueuedCompletionStatus)(HANDLE CompletionPort, LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey, LPOVERLAPPED *lpOverlapped, DWORD dwMilliseconds);

#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
# define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#endif

#ifndef FILE_SKIP_SET_EVENT_ON_HANDLE
# define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
# define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif

#define GetQueuedCompletionStatusEx_Hash 0xFBC2C63D
typedef BOOL(__stdcall *FnGetQueuedCompletionStatusEx)(HANDLE CompletionPort, LPOVERLAPPED_ENTRY lpCompletionPortEntries, ULONG ulCount, PULONG ulNumEntriesRemoved, DWORD dwMilliseconds, BOOL fAlertable);

#define SetFileCompletionNotificationModes_Hash 0x912F0D22
typedef BOOL(__stdcall *FnSetFileCompletionNotificationModes)(HANDLE FileHandle, UCHAR Flags);

#define CreateSymbolicLinkW_Hash 0x5C66557B
typedef BOOLEAN(__stdcall *FnCreateSymbolicLinkW)(LPCWSTR lpSymlinkFileName, LPCWSTR lpTargetFileName, DWORD dwFlags);

#define CancelIoEx_Hash 0xB2D2E7BD
typedef BOOL(__stdcall *FnCancelIoEx)(HANDLE hFile, LPOVERLAPPED lpOverlapped);

#define InitializeSRWLock_Hash 0xF7DC257C
typedef VOID(__stdcall *FnInitializeSRWLock)(PSRWLOCK SRWLock);

#define AcquireSRWLockShared_Hash 0xDCF6B162
typedef VOID(__stdcall *FnAcquireSRWLockShared)(PSRWLOCK SRWLock);

#define AcquireSRWLockExclusive_Hash 0x7EBCE31E 
typedef VOID(__stdcall *FnAcquireSRWLockExclusive)(PSRWLOCK SRWLock);

#define TryAcquireSRWLockShared_Hash 0xC10BB8F3
typedef BOOL(__stdcall *FnTryAcquireSRWLockShared)(PSRWLOCK SRWLock);

#define TryAcquireSRWLockExclusive_Hash 0xF0C766E6
typedef BOOL(__stdcall *FnTryAcquireSRWLockExclusive)(PSRWLOCK SRWLock);

#define ReleaseSRWLockShared_Hash 0xA4EF3102
typedef VOID(__stdcall *FnReleaseSRWLockShared)(PSRWLOCK SRWLock);

#define ReleaseSRWLockExclusive_Hash 0x62B922EE
typedef VOID(__stdcall *FnReleaseSRWLockExclusive)(PSRWLOCK SRWLock);

#define InitializeConditionVariable_Hash 0xD4CEC86C
typedef VOID(__stdcall *FnInitializeConditionVariable)(PCONDITION_VARIABLE ConditionVariable);

#define SleepConditionVariableCS_Hash 0x9B742041
typedef BOOL(__stdcall *FnSleepConditionVariableCS)(PCONDITION_VARIABLE ConditionVariable, PCRITICAL_SECTION CriticalSection, DWORD dwMilliseconds);

#define SleepConditionVariableSRW_Hash 0x0813AEDB
typedef BOOL(__stdcall *FnSleepConditionVariableSRW)(PCONDITION_VARIABLE ConditionVariable, PSRWLOCK SRWLock, DWORD dwMilliseconds, ULONG Flags);

#define WakeAllConditionVariable_Hash 0x47AB06D0
typedef VOID(__stdcall *FnWakeAllConditionVariable)(PCONDITION_VARIABLE ConditionVariable);

#define WakeConditionVariable_Hash 0x6DA2C257
typedef VOID(__stdcall *FnWakeConditionVariable)(PCONDITION_VARIABLE ConditionVariable);

#define GetFileInformationByHandle_Hash 0x1BD3DD74
typedef BOOL (__stdcall *FnGetFileInformationByHandle)(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);

#define ReadDirectoryChangesW_Hash 0xD657B7DD
typedef BOOL (__stdcall *FnReadDirectoryChangesW)(HANDLE hDirectory, LPVOID lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree, DWORD dwNotifyFilter, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define GetShortPathNameW_Hash 0xBF40293C
typedef DWORD (__stdcall *FnGetShortPathNameW)(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer);

#define GetFileType_Hash 0xF79F30B5
typedef DWORD (__stdcall *FnGetFileType)(HANDLE hFile);

#define QueueUserWorkItem_Hash 0xF1126A83
typedef BOOL (__stdcall *FnQueueUserWorkItem)(LPTHREAD_START_ROUTINE Function, PVOID Context, ULONG Flags);

#define SetHandleInformation_Hash 0xB5C8C15D
typedef BOOL(__stdcall *FnSetHandleInformation)(HANDLE hObject, DWORD dwMask, DWORD dwFlags);

#define PostQueuedCompletionStatus_Hash 0x9986C921
typedef BOOL (__stdcall *FnPostQueuedCompletionStatus)(HANDLE CompletionPort, DWORD dwNumberOfBytesTransferred, ULONG_PTR dwCompletionKey, LPOVERLAPPED lpOverlapped);

#define CancelIo_Hash 0xD16A8CB9
typedef BOOL (WINAPI *FnCancelIo)(HANDLE hFile);

#define WaitForMultipleObjects_Hash 0x297C98E4
typedef DWORD (__stdcall *FnWaitForMultipleObjects)(DWORD nCount, CONST HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);

#define CreateNamedPipeA_Hash 0xBF694020
typedef HANDLE (__stdcall *FnCreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

#define SetNamedPipeHandleState_Hash 0xA765D832
typedef BOOL(__stdcall  *FnSetNamedPipeHandleState)(HANDLE hNamedPipe, LPDWORD lpMode, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout);

#define CreateNamedPipeW_Hash 0xBF694036
typedef HANDLE (__stdcall *FnCreateNamedPipeW)(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

#define WaitNamedPipeW_Hash 0xA7891E34
typedef BOOL (__stdcall *FnWaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut);

#define ConnectNamedPipe_Hash 0xD1B30AFF
typedef BOOL (__stdcall *FnConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);

#define RegisterWaitForSingleObject_Hash 0x84304BDD
typedef BOOL (__stdcall *FnRegisterWaitForSingleObject)(PHANDLE phNewWaitObject, HANDLE hObject, WAITORTIMERCALLBACK Callback, PVOID Context, ULONG dwMilliseconds, ULONG dwFlags);

#define UnregisterWait_Hash 0x5A18F0D0
typedef BOOL (__stdcall *FnUnregisterWait)(HANDLE WaitHandle);

#define GetProcessTimes_Hash 0x779D3799
typedef BOOL (__stdcall *FnGetProcessTimes)(HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime);

#define FileTimeToSystemTime_Hash 0x0F293981
typedef BOOL (__stdcall *FnFileTimeToSystemTime)(CONST FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);

#define ReleaseSemaphore_Hash 0xDB0F1B89
typedef BOOL (__stdcall *FnReleaseSemaphore)(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount);

#define CreateHardLinkW_Hash 0x07DF09FB
typedef BOOL (__stdcall *FnCreateHardLinkW)(LPCWSTR lpFileName, LPCWSTR lpExistingFileName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

#define GetNamedPipeHandleStateW_Hash 0x0654ECB2
typedef BOOL (__stdcall *FnGetNamedPipeHandleStateW)(HANDLE hNamedPipe, LPDWORD lpState, LPDWORD lpCurInstances, LPDWORD lpMaxCollectionCount, LPDWORD lpCollectDataTimeout, LPWSTR lpUserName, DWORD nMaxUserNameSize);

#define SetFileTime_Hash 0xF76EF0B5
typedef BOOL (__stdcall *FnSetFileTime)(HANDLE hFile, CONST FILETIME *lpCreationTime, CONST FILETIME *lpLastAccessTime, CONST FILETIME *lpLastWriteTime);

#define SetEnvironmentVariableW_Hash 0xFAEF7CFF
typedef BOOL (__stdcall *FnSetEnvironmentVariableW)(LPCWSTR lpName, LPCWSTR lpValue);

#define PeekNamedPipe_Hash 0xB8DEEF3A
typedef BOOL (__stdcall *FnPeekNamedPipe)(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);

#define GlobalMemoryStatusEx_Hash 0xDD56E748
typedef BOOL (__stdcall *FnGlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer);

#define FormatMessageA_Hash 0xE87B2F9D
typedef DWORD (__stdcall *FnFormatMessageA)(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);

#define GetStdHandle_Hash 0x98C69743
typedef HANDLE (__stdcall *FnGetStdHandle)(DWORD nStdHandle);

#define GetConsoleCursorInfo_Hash 0xB653EBC4
typedef BOOL (__stdcall *FnGetConsoleCursorInfo)(HANDLE hConsoleOutput, PCONSOLE_CURSOR_INFO lpConsoleCursorInfo);

#define SetConsoleCursorInfo_Hash 0xB659EBC4
typedef BOOL (_stdcall *FnSetConsoleCursorInfo)(HANDLE hConsoleOutput, CONSOLE_CURSOR_INFO *lpConsoleCursorInfo);

#define SetConsoleCursorPosition_Hash 0x0A052447
typedef BOOL (__stdcall *FnSetConsoleCursorPosition)(HANDLE hConsoleOutput, COORD dwCursorPosition);

#define GetConsoleScreenBufferInfo_Hash 0x41677B01
typedef BOOL (__stdcall *FnGetConsoleScreenBufferInfo)(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo);

#define WriteConsoleOutputW_Hash 0xA7A6893C
typedef BOOL (__stdcall *FnWriteConsoleOutputW)(HANDLE hConsoleOutput, CONST CHAR_INFO *lpBuffer, COORD dwBufferSize, COORD dwBufferCoord, PSMALL_RECT lpWriteRegion);

#define SetConsoleTextAttribute_Hash 0xDA069C4C
typedef BOOL (__stdcall *FnSetConsoleTextAttribute)(HANDLE hConsoleOutput, WORD wAttributes);

#define WriteConsoleW_Hash 0x478F2ABE
typedef BOOL (__stdcall *FnWriteConsoleW)(HANDLE hConsoleOutput, CONST VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);

#define CancelSynchronousIo_Hash 0x0AA172BB
typedef BOOL(__stdcall * FnCancelSynchronousIo)(HANDLE hThread);

#ifdef FUNCS_USER32
	// user32.dll

#ifdef fn_AttachThreadInput
#define AttachThreadInput_Hash 0x28AE4BDA
	typedef BOOL(__stdcall *FnAttachThreadInput)(DWORD idAttach, DWORD idAttachTo, BOOL fAttach);
#endif

#ifdef fn_EnumChildWindows
#define EnumChildWindows_Hash 0xF36D37D0
	typedef BOOL(__stdcall *FnEnumChildWindows)(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
#endif

#ifdef fn_EnumWindows
#define EnumWindows_Hash 0x9A3F03C8
	typedef BOOL(__stdcall *FnEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
#endif

#ifdef fn_GetClassNameW
#define GetClassNameW_Hash 0x265B3931
	typedef int(__stdcall *FnGetClassNameW)(HWND hWnd, LPWSTR lpClassName, int nMaxCount);
#endif

#ifdef fn_GetWindowThreadProcessId
#define GetWindowThreadProcessId_Hash 0x4E13FE7B
	typedef DWORD(__stdcall *FnGetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
#endif

#ifdef fn_IsWindowVisible
#define IsWindowVisible_Hash 0x0B091081
	typedef BOOL(__stdcall *FnIsWindowVisible)(HWND hWnd);
#endif

#ifdef fn_MapVirtualKeyA
#define MapVirtualKeyA_Hash 0x0B750097
	typedef UINT(__stdcall *FnMapVirtualKeyA)(UINT uCode, UINT uMapType);
#endif

#ifdef fn_PostMessageA
#define PostMessageA_Hash 0x37F71E99
	typedef BOOL(__stdcall *FnPostMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_wsprintfA
#define wsprintfA_Hash 0x16EB2B94
	typedef int(__cdecl *FnwsprintfA)(LPSTR lpOut, LPCSTR lpFmt, ...);
#endif

#ifdef fn_wvsprintfA
#define wvsprintfA_Hash 0xF6EB2AA2
	typedef int(__stdcall *FnwvsprintfA)(LPSTR lpOutput, LPCSTR lpFmt, va_list arglist);
#endif

#ifdef fn_wvsprintfW
#define wvsprintfW_Hash 0xF6EB2AB8
	typedef int(__stdcall *FnwvsprintfW)(LPWSTR lpOutput, LPCWSTR lpFmt, va_list arglist);
#endif

#ifdef fn_wsprintfW
#define wsprintfW_Hash 0x16EB2BAA
	typedef int(__cdecl *FnwsprintfW)(LPWSTR lpOut, LPCWSTR lpFmt, ...);
#endif

#ifdef fn_RegisterClassExA
#define RegisterClassExA_Hash 0x5AE89B6B
	typedef ATOM(__stdcall *FnRegisterClassExA)(CONST WNDCLASSEX *lpwcx);
#endif

#ifdef fn_CreateWindowExA
#define CreateWindowExA_Hash 0x0BEE74EB
	typedef HWND(__stdcall *FnCreateWindowExA)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
#endif

#ifdef fn_CreateWindowExW
#define CreateWindowExW_Hash 0x0BEE7501
	typedef HWND(__stdcall *FnCreateWindowExW)(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
#endif

#ifdef fn_GetDC
#define GetDC_Hash 0x8CF1D075
	typedef HDC(__stdcall *FnGetDC)(HWND hWnd);
#endif

#ifdef fn_ReleaseDC
#define ReleaseDC_Hash 0x91BAB097
	typedef int(__stdcall *FnReleaseDC)(HWND hWnd, HDC hDC);
#endif

#ifdef fn_DestroyWindow
#define DestroyWindow_Hash 0x19B6E35F
	typedef BOOL(__stdcall *FnDestroyWindow)(HWND hWnd);
#endif

#ifdef fn_DefWindowProcW
#define DefWindowProcW_Hash 0x46674BBF
	typedef LRESULT(__stdcall *FnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_ExitWindowsEx
#define ExitWindowsEx_Hash 0xE47F27E1
	typedef BOOL(__stdcall *FnExitWindowsEx)(UINT uFlags, DWORD dwReason);
#endif

#ifdef fn_GetWindowTextW
#define GetWindowTextW_Hash 0xC8CD76B8
	typedef int(__stdcall *FnGetWindowTextW)(HWND hWnd, wchar_t* lpString, int nMaxCount);
#endif

#ifdef fn_GetWindowRect
#define GetWindowRect_Hash 0x69130E45
	typedef BOOL(__stdcall *FnGetWindowRect)(HWND hWnd, LPRECT lpRect);
#endif

#ifdef fn_mouse_event
#define mouse_event_Hash 0x395EC7D6
	typedef VOID(__stdcall *Fnmouse_event)(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo);
#endif

#ifdef fn_SetWindowLongA
#define SetWindowLongA_Hash 0xC6C54EA7
	typedef LONG(__stdcall *FnSetWindowLongA)(HWND hWnd, int nIndex, LONG dwNewLong);
#endif

#ifdef fn_SetWindowLongW
#define SetWindowLongW_Hash 0xC6C54EBD
	typedef LONG(__stdcall *FnSetWindowLongW)(HWND hWnd, int nIndex, LONG dwNewLong);
#endif

#ifdef fn_GetWindowLongA
#define GetWindowLongA_Hash 0xC6AD4EA7
	typedef LONG(__stdcall *FnGetWindowLongA)(HWND hWnd, int nIndex);
#endif

#ifdef fn_GetWindowLongW
#define GetWindowLongW_Hash 0xC6AD4EBD
	typedef LONG(__stdcall *FnGetWindowLongW)(HWND hWnd, int nIndex);
#endif

#ifdef fn_SetWindowLongPtrA
#define SetWindowLongPtrA_Hash 0x71A4779C
	typedef LONG_PTR(__stdcall *FnSetWindowLongPtrA)(HWND hWnd, int nIndex, LONG_PTR dwNewLong);
#endif

#ifdef fn_SetWindowLongPtrW
#define SetWindowLongPtrW_Hash 0x71A477B2
	typedef LONG_PTR(__stdcall *FnSetWindowLongPtrW)(HWND hWnd, int nIndex, LONG_PTR dwNewLong);
#endif

#ifdef fn_GetWindowLongPtrA
#define GetWindowLongPtrA_Hash 0x7198779C
	typedef LONG_PTR(__stdcall *FnGetWindowLongPtrA)(HWND hWnd, int nIndex);
#endif

#ifdef fn_GetWindowLongPtrW
#define GetWindowLongPtrW_Hash 0x719877B2
	typedef LONG_PTR(__stdcall *FnGetWindowLongPtrW)(HWND hWnd, int nIndex);
#endif

#ifdef fn_SendNotifyMessageA
#define SendNotifyMessageA_Hash 0xF8E05901
	typedef BOOL(__stdcall *FnSendNotifyMessageA)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_FindWindowA
#define FindWindowA_Hash 0xF9FAFC95
	typedef HWND(__stdcall *FnFindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName);
#endif

#ifdef fn_MessageBoxA
#define MessageBoxA_Hash 0xFA1EFD86
	typedef int(__stdcall *FnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
#endif

#ifdef fn_MessageBoxW
#define MessageBoxW_Hash 0xFA1EFD9C
	typedef int(__stdcall *FnMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
#endif

#ifdef fn_OffsetRect
#define OffsetRect_Hash 0xB6D2C4C3
	typedef BOOL(__stdcall *FnOffsetRect)(LPRECT lprc, int dx, int dy);
#endif

#ifdef fn_InflateRect
#define InflateRect_Hash 0x1736E2C3
	typedef BOOL(__stdcall *FnInflateRect)(LPRECT lprc, int dx, int dy);
#endif

#ifdef fn_UnionRect
#define UnionRect_Hash 0x56B2C7B7
	typedef BOOL(__stdcall *FnUnionRect)(LPRECT lprcDst, CONST RECT *lprcSrc1, CONST RECT *lprcSrc2);
#endif

#ifdef fn_SetCursor
#define SetCursor_Hash 0x185AA5C8
	typedef HCURSOR(__stdcall *FnSetCursor)(HCURSOR hCursor);
#endif

#ifdef fn_LoadCursorW
#define LoadCursorW_Hash 0x39B307AF
	typedef HCURSOR(__stdcall *FnLoadCursorW)(HINSTANCE hInstance, LPCTSTR lpCursorName);
#endif

#ifdef fn_EnumDisplayMonitors
#define EnumDisplayMonitors_Hash 0xA63268A0
	typedef BOOL(__stdcall *FnEnumDisplayMonitors)(HDC hdc, LPCRECT lprcClip, MONITORENUMPROC lpfnEnum, LPARAM dwData);
#endif

#ifdef fn_GetKeyState
#define GetKeyState_Hash 0xF726EAC4
	typedef SHORT(__stdcall *FnGetKeyState)(int nVirtKey);
#endif

#ifdef fn_IsWindow
#define IsWindow_Hash 0xD6BA3ECA
	typedef BOOL(__stdcall *FnIsWindow)(HWND hWnd);
#endif

#ifdef fn_SetTimer
#define SetTimer_Hash 0xD47A9CBF
	typedef UINT_PTR(__stdcall *FnSetTimer)(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
#endif

#ifdef fn_KillTimer
#define KillTimer_Hash 0x952AD7C1
	typedef BOOL(__stdcall *FnKillTimer)(HWND hWnd, UINT_PTR uIDEvent);
#endif

#ifdef fn_GetClientRect
#define GetClientRect_Hash 0x28BB0F43
	typedef BOOL(__stdcall *FnGetClientRect)(HWND hWnd, LPRECT lpRect);
#endif

#ifdef fn_GetWindow
#define GetWindow_Hash 0x179A85CB
	typedef HWND(__stdcall *FnGetWindow)(HWND hWnd, UINT uCmd);
#endif

#ifdef fn_SetWindowPos
#define SetWindowPos_Hash 0x99AE8958
	typedef BOOL(__stdcall *FnSetWindowPos)(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags);
#endif

#ifdef fn_SetLayeredWindowAttributes
#define SetLayeredWindowAttributes_Hash 0x20CF606E
	typedef BOOL(__stdcall *FnSetLayeredWindowAttributes)(HWND hwnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags);
#endif

#ifdef fn_GetCursorPos
#define GetCursorPos_Hash 0x1A0E8D57
	typedef BOOL(__stdcall *FnGetCursorPos)(LPPOINT lpPoint);
#endif

#ifdef fn_ScreenToClient
#define ScreenToClient_Hash 0x295CC1D7
	typedef BOOL(__stdcall *FnScreenToClient)(HWND hWnd, LPPOINT lpPoint);
#endif

#ifdef fn_SendMessageW
#define SendMessageW_Hash 0x97CF102E
	typedef LRESULT(__stdcall *FnSendMessageW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_MapWindowPoints
#define MapWindowPoints_Hash 0x1B50FB9A
	typedef int(__stdcall *FnMapWindowPoints)(HWND hWndFrom, HWND hWndTo, LPPOINT lpPoints, UINT cPoints);
#endif

#ifdef fn_InvalidateRect
#define InvalidateRect_Hash 0xB7E920C9
	typedef BOOL(__stdcall *FnInvalidateRect)(HWND hWnd, CONST RECT* lpRect, BOOL bErase);
#endif

#ifdef fn_SetCapture
#define SetCapture_Hash 0x38E2FBBA
	typedef HWND(__stdcall *FnSetCapture)(HWND hWnd);
#endif

#ifdef fn_ReleaseCapture
#define ReleaseCapture_Hash 0x4AA33FC2
	typedef BOOL(__stdcall *FnReleaseCapture)(VOID);
#endif

#ifdef fn_BeginPaint
#define BeginPaint_Hash 0x15FAE5C7
	typedef HDC(__stdcall *FnBeginPaint)(HWND hwnd, LPPAINTSTRUCT lpPaint);
#endif

#ifdef fn_EndPaint
#define EndPaint_Hash 0x14EA6CC0
	typedef BOOL(__stdcall *FnEndPaint)(HWND hWnd, CONST PAINTSTRUCT *lpPaint);
#endif

#ifdef fn_IsRectEmpty
#define IsRectEmpty_Hash 0xB71EFAD6
	typedef BOOL(__stdcall *FnIsRectEmpty)(CONST RECT *lprc);
#endif

#ifdef fn_GetUpdateRect
#define GetUpdateRect_Hash 0x67A31F44
	typedef BOOL(__stdcall *FnGetUpdateRect)(HWND hWnd, LPRECT lpRect, BOOL bErase);
#endif

#ifdef fn_SetFocus
#define SetFocus_Hash 0xD59A74C3
	typedef HWND(__stdcall *FnSetFocus)(HWND hWnd);
#endif

#ifdef fn_GetFocus
#define GetFocus_Hash 0xD53A74C3
	typedef HWND(__stdcall *FnGetFocus)(VOID);
#endif

#ifdef fn_GetMessageW
#define GetMessageW_Hash 0x7756F6AD
	typedef BOOL(__stdcall *FnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
#endif

#ifdef fn_DispatchMessageW
#define DispatchMessageW_Hash 0x58F13576
	typedef LRESULT(__stdcall *FnDispatchMessageW)(const MSG *lpmsg);
#endif

#ifdef fn_TranslateMessage
#define TranslateMessage_Hash 0x79AD18C7
	typedef BOOL(__stdcall *FnTranslateMessage)(const MSG *lpMsg);
#endif

#ifdef fn_PostMessageW
#define PostMessageW_Hash 0x37F71EAF
	typedef BOOL(__stdcall *FnPostMessageW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_PtInRect
#define PtInRect_Hash 0x15C226BA
	typedef BOOL(__stdcall *FnPtInRect)(CONST RECT *lprc, POINT pt);
#endif

#ifdef fn_GetParent
#define GetParent_Hash 0x16FA7BCA
	typedef HWND(__stdcall *FnGetParent)(HWND hWnd);
#endif

#ifdef fn_ShowWindow
#define ShowWindow_Hash 0x37EAA6D6
	typedef BOOL(__stdcall *FnShowWindow)(HWND hWnd, int nCmdShow);
#endif

#ifdef fn_EnableWindow
#define EnableWindow_Hash 0x798AC353
	typedef BOOL(__stdcall *FnEnableWindow)(HWND hWnd, BOOL bEnable);
#endif

#ifdef fn_PostQuitMessage
#define PostQuitMessage_Hash 0xA9D505C7
	typedef void(__stdcall *FnPostQuitMessage)(int nExitCode);
#endif

#ifdef fn_SystemParametersInfoW
#define SystemParametersInfoW_Hash 0x8CB2CAF3
	typedef BOOL(__stdcall *FnSystemParametersInfoW)(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni);
#endif

#ifdef fn_LoadImageW
#define LoadImageW_Hash 0x167A9DAA
	typedef HANDLE(__stdcall *FnLoadImageW)(HINSTANCE hinst, LPCWSTR lpszName, UINT uType, int cxDesired, int cyDesired, UINT fuLoad);
#endif

#ifdef fn_GetSystemMetrics
#define GetSystemMetrics_Hash 0x41BF2995
	typedef int(__stdcall *FnGetSystemMetrics)(int nIndex);
#endif

#ifdef fn_RegisterClassW
#define RegisterClassW_Hash 0xCA92FA38
	typedef ATOM(__stdcall *FnRegisterClassW)(CONST WNDCLASS *lpWndClass);
#endif

#ifdef fn_RegisterClassExW
#define RegisterClassExW_Hash 0x5AE89B81
	typedef ATOM(__stdcall *FnRegisterClassExW)(CONST WNDCLASSEX *lpwcx);
#endif

#ifdef fn_GetClassInfoExW
#define GetClassInfoExW_Hash 0x3B7496F4
	typedef BOOL(__stdcall *FnGetClassInfoExW)(HINSTANCE hinst, LPCWSTR lpszClass, LPWNDCLASSEX lpwcx);
#endif

#ifdef fn_CallWindowProcW
#define CallWindowProcW_Hash 0xB6A15F7F
	typedef LRESULT(__stdcall *FnCallWindowProcW)(WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_GetPropW
#define GetPropW_Hash 0x553AA4A9
	typedef HANDLE(__stdcall *FnGetPropW)(HWND hWnd, LPCWSTR lpString);
#endif

#ifdef fn_SetPropW
#define SetPropW_Hash 0x559AA4A9
	typedef BOOL(__stdcall *FnSetPropW)(HWND hWnd, LPCWSTR lpString, HANDLE hData);
#endif

#ifdef fn_AdjustWindowRectEx
#define AdjustWindowRectEx_Hash 0xA55929BF
	typedef BOOL(__stdcall *FnAdjustWindowRectEx)(LPRECT lpRect, DWORD dwStyle, BOOL bMenu, DWORD dwExStyle);
#endif

#ifdef fn_GetMenu
#define GetMenu_Hash 0x55025EAD
	typedef HMENU(__stdcall *FnGetMenu)(HWND hWnd);
#endif

#ifdef fn_IntersectRect
#define IntersectRect_Hash 0x890B03C7
	typedef BOOL(__stdcall *FnIntersectRect)(LPRECT lprcDst, CONST RECT *lprcSrc1, CONST RECT *lprcSrc2);
#endif

#ifdef fn_CharNextW
#define CharNextW_Hash 0xD6A307A1
	typedef LPWSTR(__stdcall *FnCharNextW)(LPCWSTR lpsz);
#endif

#ifdef fn_CharPrevW
#define CharPrevW_Hash 0x5702BBA8
	typedef LPWSTR(__stdcall *FnCharPrevW)(LPCWSTR lpszStart, LPCWSTR lpszCurrent);
#endif

#ifdef fn_FillRect
#define FillRect_Hash 0x55526CB7
	typedef int(__stdcall *FnFillRect)(HDC hDC, CONST RECT *lprc, HBRUSH hbr);
#endif

#ifdef fn_CreateSolidBrush
#define CreateSolidBrush_Hash 0xE041624D
	typedef HBRUSH(__stdcall *FnCreateSolidBrush)(COLORREF crColor);
#endif

#ifdef fn_DrawTextW
#define DrawTextW_Hash 0xD75312A1
	typedef int(__stdcall *FnDrawTextW)(HDC hDC, LPCTSTR lpString, int nCount, LPRECT lpRect, UINT uFormat);
#endif

#ifdef fn_SetRect
#define SetRect_Hash 0xD3A25EB1
	typedef BOOL(__stdcall *FnSetRect)(LPRECT lprc, int xLeft, int yTop, int xRight, int yBottom);
#endif

#ifdef fn_IsIconic
#define IsIconic_Hash 0x559A4AB7
	typedef BOOL(__stdcall *FnIsIconic)(HWND hWnd);
#endif

#ifdef fn_GetMonitorInfoW
#define GetMonitorInfoW_Hash 0xD8991DFE
	typedef BOOL(__stdcall *FnGetMonitorInfoW)(HMONITOR hMonitor, LPMONITORINFO lpmi);
#endif

#ifdef fn_MonitorFromWindow
#define MonitorFromWindow_Hash 0xD2D203DC
	typedef HMONITOR(__stdcall *FnMonitorFromWindow)(HWND hwnd, DWORD dwFlags);
#endif

#ifdef fn_SetWindowRgn
#define SetWindowRgn_Hash 0x98AE9153
	typedef int(__stdcall *FnSetWindowRgn)(HWND hWnd, HRGN hRgn, BOOL bRedraw);
#endif

#ifdef fn_IsZoomed
#define IsZoomed_Hash 0x55DA68B8
	typedef BOOL(__stdcall *FnIsZoomed)(HWND hWnd);
#endif

#ifdef fn_SetWindowsHookExW
#define SetWindowsHookExW_Hash 0x341BBDB6
	typedef HHOOK(__stdcall *FnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
#endif

#ifdef fn_CallNextHookEx
#define CallNextHookEx_Hash 0x6588D7DC
	typedef LRESULT(__stdcall *FnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
#endif

#ifdef fn_UnhookWindowsHookEx
#define UnhookWindowsHookEx_Hash 0x124109E3
	typedef BOOL(__stdcall *FnUnhookWindowsHookEx)(HHOOK hhk);
#endif

#ifdef fn_FindWindowExA
#define FindWindowExA_Hash 0xFAF26828
	typedef HWND(__stdcall *FnFindWindowExA)(HWND hwndParent, HWND hwndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow);
#endif

#ifdef fn_CharUpperW
#define CharUpperW_Hash 0xF84AA6B3
	typedef LPWSTR(__stdcall *FnCharUpperW)(LPWSTR lpsz);
#endif

#ifdef fn_CharLowerW
#define CharLowerW_Hash 0x783A94B7
	typedef LPWSTR(__stdcall *FnCharLowerW)(LPWSTR lpsz);
#endif

#ifdef fn_ClientToScreen
#define ClientToScreen_Hash 0x578CE357
	typedef BOOL(__stdcall *FnClientToScreen)(HWND hWnd, LPPOINT lpPoint);
#endif // fn_ClientToScreen

#ifdef fn_SendInput
#define SendInput_Hash 0x965ADBC6
	typedef UINT(__stdcall *FnSendInput)(UINT nInputs, LPINPUT pInputs, int cbSize);
#endif // fn_SendInput

#ifdef fn_SetWindowTextW
#define SetWindowTextW_Hash 0xC8E576B8
	typedef BOOL(__stdcall *FnSetWindowTextW)(HWND hWnd, LPCWSTR lpString);
#endif // fn_SetWindowTextW

#ifdef fn_GetWindowTextW
#define GetWindowTextW_Hash 0xC8CD76B8
	typedef int(__stdcall *FnGetWindowTextW)(HWND hWnd, LPWSTR lpString, int nMaxCount);
#endif // fn_GetWindowTextW

#ifdef fn_GetWindowTextLengthW
#define GetWindowTextLengthW_Hash 0x0615F836
	typedef int(__stdcall *FnGetWindowTextLengthW)(HWND hWnd);
#endif // GetWindowTextLengthW

#ifdef fn_CreateIconIndirect
#define CreateIconIndirect_Hash 0xF0210FFF
	typedef HICON(__stdcall *FnCreateIconIndirect)(PICONINFO piconinfo);
#endif // CreateIconIndirect

#ifdef fn_DestroyIcon
#define DestroyIcon_Hash 0xBA22DDBB
	typedef BOOL(__stdcall *FnDestroyIcon)(HICON hIcon);
#endif

#ifdef fn_RegisterWindowMessageW
#define RegisterWindowMessageW_Hash 0xB920E1EA
	typedef UINT(__stdcall *FnRegisterWindowMessageW)(LPCWSTR lpString);
#endif

#ifdef fn_GetIconInfo
#define GetIconInfo_Hash 0xF7070AB8
	typedef BOOL(__stdcall *FnGetIconInfo)(HICON hIcon, PICONINFO piconinfo);
#endif

#ifdef fn_DrawIconEx
#define DrawIconEx_Hash 0xD1DABCD5
	typedef BOOL(__stdcall *FnDrawIconEx)(HDC hdc, int xLeft, int yTop, HICON hIcon, int cxWidth, int cyWidth, UINT istepIfAniCur, HBRUSH hbrFlickerFreeDraw, UINT diFlags);
#endif

#ifdef fn_MoveWindow
#define MoveWindow_Hash 0xF822ADD0
	typedef BOOL(__stdcall *FnMoveWindow)(HWND hWnd, int X, int Y, int nWidth, int nHeight, BOOL bRepaint);
#endif

#ifdef fn_CreateAcceleratorTableW
#define CreateAcceleratorTableW_Hash 0x453F6AED
	typedef HACCEL(__stdcall *FnCreateAcceleratorTableW)(LPACCEL lpaccl, int cEntries);
#endif

#ifdef fn_InvalidateRgn
#define InvalidateRgn_Hash 0x4942ADCA
	typedef BOOL(__stdcall *FnInvalidateRgn)(HWND hWnd, HRGN hRgn, BOOL bErase);
#endif

#define GetForegroundWindow_Hash 0x97030FBE
typedef HWND (__stdcall *FnGetForegroundWindow)(VOID);

#endif // FUNCS_USER32

#ifdef FUNCS_GDI32

	// gdi32.dll

#ifdef fn_GetObjectW
#define GetObjectW_Hash 0x38C2B5A6
	typedef int(__stdcall *FnGetObjectW)(HGDIOBJ hgdiobj, int cbBuffer, LPVOID lpvObject);
#endif

#ifdef fn_GetObjectA
#define GetObjectA_Hash 0x38C2B590
	typedef int(__stdcall *FnGetObjectA)(HGDIOBJ hgdiobj, int cbBuffer, LPVOID lpvObject);
#endif

#ifdef fn_GetStockObject
#define GetStockObject_Hash 0xA774DBD8
	typedef HGDIOBJ(__stdcall *FnGetStockObject)(int fnObject);
#endif

#ifdef fn_CreateFontIndirectW
#define CreateFontIndirectW_Hash 0x8FFA0A79
	typedef HFONT(__stdcall *FnCreateFontIndirectW)(CONST LOGFONTW* lplf);
#endif

#ifdef fn_CreatePen
#define CreatePen_Hash 0xD77245B9
	typedef HPEN(__stdcall *FnCreatePen)(int fnPenStyle, int nWidth, COLORREF crColor);
#endif

#ifdef fn_SelectObject
#define SelectObject_Hash 0x972EC153
	typedef HGDIOBJ(__stdcall *FnSelectObject)(HDC hdc, HGDIOBJ hgdiobj);
#endif

#ifdef fn_DeleteObject
#define DeleteObject_Hash 0xD7B6B9CF
	typedef BOOL(__stdcall *FnDeleteObject)(HGDIOBJ hObject);
#endif

#ifdef fn_DeleteDC
#define DeleteDC_Hash 0x50F26C96
	typedef BOOL(__stdcall *FnDeleteDC)(HDC hdc);
#endif

#ifdef fn_SaveDC
#define SaveDC_Hash 0x0E923A7E
	typedef int(__stdcall *FnSaveDC)(HDC hdc);
#endif

#ifdef fn_RestoreDC
#define RestoreDC_Hash 0xD29ACE98
	typedef BOOL(__stdcall *FnRestoreDC)(HDC hdc, int nSavedDC);
#endif

#ifdef fn_SetWindowOrgEx
#define SetWindowOrgEx_Hash 0x42B532E0
	typedef BOOL(__stdcall *FnSetWindowOrgEx)(HDC hdc, int X, int Y, LPPOINT lpPoint);
#endif

#ifdef fn_Rectangle
#define Rectangle_Hash 0xD6BAD6B4
	typedef BOOL(__stdcall *FnRectangle)(HDC hdc, int nLeftRect, int nTopRect, int nRightRect, int nBottomRect);
#endif

#ifdef fn_BitBlt
#define BitBlt_Hash 0x14118CAE
	typedef BOOL(__stdcall *FnBitBlt)(HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop);
#endif

#ifdef fn_CreateCompatibleBitmap
#define CreateCompatibleBitmap_Hash 0x9B547CBB
	typedef HBITMAP(__stdcall *FnCreateCompatibleBitmap)(HDC hdc, int nWidth, int nHeight);
#endif

#ifdef fn_CreateCompatibleDC
#define CreateCompatibleDC_Hash 0x2CC118CD
	typedef HDC(__stdcall *FnCreateCompatibleDC)(HDC hdc);
#endif

#ifdef fn_GetTextMetricsW
#define GetTextMetricsW_Hash 0x1A49247B
	typedef BOOL(__stdcall *FnGetTextMetricsW)(HDC hdc, LPTEXTMETRIC lptm);
#endif

#ifdef fn_SelectClipRgn
#define SelectClipRgn_Hash 0xA8C2B648
	typedef int(__stdcall *FnSelectClipRgn)(HDC hdc, HRGN hrgn);
#endif

#ifdef fn_GetObjectType
#define GetObjectType_Hash 0xAA633F36
	typedef DWORD(__stdcall *FnGetObjectType)(HGDIOBJ h);
#endif

#ifdef fn_ExtSelectClipRgn
#define ExtSelectClipRgn_Hash 0xD1AAD44A
	typedef int(__stdcall *FnExtSelectClipRgn)(HDC hdc, HRGN hrgn, int fnMode);
#endif

#ifdef fn_CreateRectRgnIndirect
#define CreateRectRgnIndirect_Hash 0x63FA29B0
	typedef HRGN(__stdcall *FnCreateRectRgnIndirect)(CONST RECT *lprc);
#endif

#ifdef fn_GetClipBox
#define GetClipBox_Hash 0xB81245C9
	typedef int(__stdcall *FnGetClipBox)(HDC hdc, LPRECT lprc);
#endif

#ifdef fn_CombineRgn
#define CombineRgn_Hash 0x772A89C1
	typedef int(__stdcall *FnCombineRgn)(HRGN hrgnDest, HRGN hrgnSrc1, HRGN hrgnSrc2, int fnCombineMode);
#endif

#ifdef fn_CreateRoundRectRgn
#define CreateRoundRectRgn_Hash 0xB148CA74
	typedef HRGN(__stdcall *FnCreateRoundRectRgn)(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect, int nWidthEllipse, int nHeightEllipse);
#endif

#ifdef fn_CreateDIBSection
#define CreateDIBSection_Hash 0x80810E4D
	typedef HBITMAP(__stdcall *FnCreateDIBSection)(HDC hdc, CONST BITMAPINFO *pbmi, UINT iUsage, VOID **ppvBits, HANDLE hSection, DWORD dwOffset);
#endif

#ifdef fn_StretchBlt
#define StretchBlt_Hash 0xB74264CB
	typedef BOOL(__stdcall *FnStretchBlt)(HDC hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, HDC hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, DWORD dwRop);
#endif

#ifdef fn_MoveToEx
#define MoveToEx_Hash 0xD15AA8BD
	typedef BOOL(__stdcall *FnMoveToEx)(HDC hdc, int X, int Y, LPPOINT lpPoint);
#endif

#ifdef fn_LineTo
#define LineTo_Hash 0x11122CA6
	typedef BOOL(__stdcall *FnLineTo)(HDC hdc, int nXEnd, int nYEnd);
#endif

#ifdef fn_CreatePenIndirect
#define CreatePenIndirect_Hash 0x078016A0
	typedef HPEN(__stdcall *FnCreatePenIndirect)(CONST LOGPEN *lplgpn);
#endif

#ifdef fn_RoundRect
#define RoundRect_Hash 0x561AC2BA
	typedef BOOL(__stdcall *FnRoundRect)(HDC hdc, int nLeftRect, int nTopRect, int nRightRect, int nBottomRect, int nWidth, int nHeight);
#endif

#ifdef fn_SetTextColor
#define SetTextColor_Hash 0x16CF1656
	typedef COLORREF(__stdcall *FnSetTextColor)(HDC hdc, COLORREF crColor);
#endif

#ifdef fn_SetBkMode
#define SetBkMode_Hash 0x965A93A8
	typedef int(__stdcall *FnSetBkMode)(HDC hdc, int iBkMode);
#endif

#ifdef fn_TextOutW
#define TextOutW_Hash 0xD862C497
	typedef BOOL(__stdcall *FnTextOutW)(HDC hdc, int nXStart, int nYStart, LPCWSTR lpString, int cbString);
#endif

#ifdef fn_GetTextExtentPoint32W
#define GetTextExtentPoint32W_Hash 0xA257F8B7
	typedef BOOL(__stdcall *FnGetTextExtentPoint32W)(HDC hdc, LPCWSTR lpString, int c, LPSIZE lpSize);
#endif

#ifdef fn_GetCharABCWidthsW
#define GetCharABCWidthsW_Hash 0xA1500238
	typedef BOOL(__stdcall *FnGetCharABCWidthsW)(HDC hdc, UINT uFirstChar, UINT uLastChar, LPABC lpabc);
#endif

#ifdef fn_SetBkColor
#define SetBkColor_Hash 0x75B2EBC4
	typedef COLORREF(__stdcall *FnSetBkColor)(HDC hdc, COLORREF crColor);
#endif

#ifdef fn_GdiFlush
#define GdiFlush_Hash 0x14FAA6B7
	typedef BOOL(__stdcall *FnGdiFlush)(VOID);
#endif

#ifdef fn_SetStretchBltMode
#define SetStretchBltMode_Hash 0x01904DB5
	typedef int(__stdcall *FnSetStretchBltMode)(HDC hdc, int iStretchMode);
#endif

#ifdef fn_ExtTextOutW
#define ExtTextOutW_Hash 0xD97738A6
	typedef BOOL(__stdcall *FnExtTextOutW)(HDC hdc, int X, int Y, UINT fuOptions, CONST RECT* lprc, LPCTSTR lpString, UINT cbCount, CONST INT* lpDx);
#endif

#ifdef fn_GetPixel
#define GetPixel_Hash 0xD3DAC8B9
	typedef COLORREF(__stdcall *FnGetPixel)(HDC hdc, int nXPos, int nYPos);
#endif

#ifdef fn_SetPixel
#define SetPixel_Hash 0xD43AC8B9
	typedef COLORREF(__stdcall *FnSetPixel)(HDC hdc, int X, int Y, COLORREF crColor);
#endif

#ifdef fn_GetDeviceCaps
#define GetDeviceCaps_Hash 0xC9D2E23B
	typedef int(__stdcall *FnGetDeviceCaps)(HDC hdc, int nIndex);
#endif

#endif // FUNCS_GDI32

#ifdef FUNCS_COMCTL32

#ifdef fn_InitCommonControlsEx
#define InitCommonControlsEx_Hash 0x162E003E
	typedef BOOL(__stdcall *FnInitCommonControlsEx)(const LPINITCOMMONCONTROLSEX lpInitCtrls);
#endif

#ifdef fn__TrackMouseEvent
#define _TrackMouseEvent_Hash 0x804B145E
	typedef BOOL(__stdcall *Fn_TrackMouseEvent)(LPTRACKMOUSEEVENT lpEventTrack);
#endif

#endif // FUNCS_COMCTL32

#ifdef FUNCS_SHLWAPI
	// shlwapi.dll

#ifdef fn_PathCombineW
#define PathCombineW_Hash 0xD65F22B5
	typedef LPWSTR(__stdcall *FnPathCombineW)(LPWSTR lpszDest, LPCWSTR lpszDir, LPCWSTR lpszFile);
#endif

#ifdef fn_PathAppendW
#define PathAppendW_Hash 0xF8030CA5
	typedef BOOL(__stdcall *FnPathAppendW)(LPWSTR pszPath, LPCWSTR pszMore);
#endif

#ifdef fn_PathRemoveFileSpecW
#define PathRemoveFileSpecW_Hash 0x07F0FCE2
	typedef BOOL(__stdcall *FnPathRemoveFileSpecW)(LPWSTR pszPath);
#endif

#ifdef fn_PathFindFileNameA
#define PathFindFileNameA_Hash 0x7FA31620
	typedef LPSTR(__stdcall *FnPathFindFileNameA)(LPCSTR pPath);
#endif

#ifdef fn_PathFindFileNameW
#define PathFindFileNameW_Hash 0x7FA31636
	typedef LPWSTR(__stdcall *FnPathFindFileNameW)(LPCWSTR pPath);
#endif

#ifdef fn_StrToIntA
#define StrToIntA_Hash 0x1912B382
	typedef int(__stdcall *FnStrToIntA)(LPCSTR lpSrc);
#endif

#ifdef fn_StrToIntW
#define StrToIntW_Hash 0x1912B398
	typedef int(__stdcall *FnStrToIntW)(LPCWSTR lpSrc);
#endif

#ifdef fn_StrToInt64ExA
#define StrToInt64ExA_Hash 0x4672A586
	typedef BOOL(__stdcall *FnStrToInt64ExA)(LPCSTR pszString, STIF_FLAGS dwFlags, LONGLONG *pllRet);
#endif

#ifdef fn_StrCmpIW
#define StrCmpIW_Hash 0x8FEAA4AA
	typedef int(__stdcall *FnStrCmpIW)(LPCWSTR lpStr1, LPCWSTR lpStr2);
#endif

#ifdef fn_StrCmpNIW
#define StrCmpNIW_Hash 0x939211AB
	typedef int(__stdcall *FnStrCmpNIW)(LPCWSTR lpStr1, LPCWSTR lpStr2, int nChar);
#endif

#ifdef fn_StrStrW
#define StrStrW_Hash 0x5562B895
	typedef LPWSTR(__stdcall *FnStrStrW)(LPCWSTR lpFirst, LPCWSTR lpSrch);
#endif

#ifdef fn_StrCmpNW
#define StrCmpNW_Hash 0x908AA4AA
	typedef int(__stdcall *FnStrCmpNW)(LPCWSTR lpStr1, LPCWSTR lpStr2, int nChar);
#endif

#ifdef fn_wvnsprintfW
#define wvnsprintfW_Hash 0xD8C722B8
	typedef int(__stdcall *FnwvnsprintfW)(LPWSTR lpOut, int cchLimitIn, LPCWSTR pszFmt, va_list arglist);
#endif

#ifdef fn_StrStrIW
#define StrStrIW_Hash 0x10EAACAE
	typedef LPWSTR(__stdcall *FnStrStrIW)(LPCWSTR lpFirst, LPCWSTR lpSrch);
#endif

#ifdef fn_StrRChrIW
#define StrRChrIW_Hash 0x90F2BFA7
	typedef LPWSTR(__stdcall *FnStrRChrIW)(LPCWSTR lpStart, LPCWSTR lpEnd, wchar_t wMatch);
#endif

#ifdef fn_StrStrIA
#define StrStrIA_Hash 0x10EAAC98
	typedef LPTSTR(__stdcall *FnStrStrIA)(LPCSTR lpFirst, LPCSTR lpSrch);
#endif

#ifdef fn_wnsprintfW
#define wnsprintfW_Hash 0xF6EB22B8
	typedef int(__cdecl *FnwnsprintfW)(LPWSTR lpOut, int cchLimitIn, LPCWSTR pszFmt, ...);
#endif

#ifdef fn_StrStrA
#define StrStrA_Hash 0x5562B87F
	typedef LPSTR(__stdcall *FnStrStrA)(LPCSTR lpFirst, LPCSTR lpSrch);
#endif

#ifdef fn_StrCmpNIA
#define StrCmpNIA_Hash 0x93921195
	typedef int(__stdcall *FnStrCmpNIA)(LPCSTR lpStr1, LPCSTR lpStr2, int nChar);
#endif

#ifdef fn_StrChrA
#define StrChrA_Hash 0x55628877
	typedef LPSTR(__stdcall *FnStrChrA)(LPCSTR lpStart, char wMatch);
#endif

#endif // FUNCS_SHLWAPI

#ifdef FUNCS_ADVAPI32

	// advapi32.dll
#ifdef fn_RegOpenKeyExA
#define RegOpenKeyExA_Hash 0x1A164D28
	typedef LSTATUS(__stdcall *FnRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
#endif

#ifdef fn_RegQueryValueExA
#define RegQueryValueExA_Hash 0xBB64B961
	typedef LONG(WINAPI *FnRegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
#endif

#ifdef fn_RegEnumKeyExA
#define RegEnumKeyExA_Hash 0x9A964B26
	typedef LSTATUS(__stdcall *FnRegEnumKeyExA)(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);
#endif

#ifdef fn_ConvertStringSidToSidW
#define ConvertStringSidToSidW_Hash 0x9803FC83
	typedef BOOL(__stdcall *FnConvertStringSidToSidW)(LPWSTR StringSid, PSID *Sid);
#endif

#ifdef fn_AdjustTokenPrivileges
#define AdjustTokenPrivileges_Hash 0x11E63B09
	typedef BOOL(__stdcall *FnAdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
#endif

#ifdef fn_AllocateAndInitializeSid
#define AllocateAndInitializeSid_Hash 0x0EE871C1
	typedef BOOL(__stdcall *FnAllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD dwSubAuthority0,
		DWORD dwSubAuthority1, DWORD dwSubAuthority2, DWORD dwSubAuthority3, DWORD dwSubAuthority4, DWORD dwSubAuthority5, DWORD dwSubAuthority6, DWORD dwSubAuthority7, PSID* pSid);
#endif

#ifdef fn_EqualSid
#define EqualSid_Hash 0x555A36B6
	typedef BOOL(__stdcall *FnEqualSid)(PSID pSid1, PSID pSid2);
#endif

#ifdef fn_FreeSid
#define FreeSid_Hash 0x137230A8
	typedef pvoid_t(__stdcall *FnFreeSid)(PSID pSid);
#endif

#ifdef fn_GetLengthSid
#define GetLengthSid_Hash 0x191E8A42
	typedef DWORD(__stdcall *FnGetLengthSid)(PSID pSid);
#endif

#ifdef fn_GetSidSubAuthority
#define GetSidSubAuthority_Hash 0x3C25FD05
	typedef PDWORD(__stdcall *FnGetSidSubAuthority)(PSID pSid, DWORD nSubAuthority);
#endif

#ifdef fn_GetSidSubAuthorityCount
#define GetSidSubAuthorityCount_Hash 0xDDEBDF23
	typedef PUCHAR(__stdcall *FnGetSidSubAuthorityCount)(PSID pSid);
#endif

#ifdef fn_GetTokenInformation
#define GetTokenInformation_Hash 0x65D9443C
	typedef BOOL(__stdcall *FnGetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
#endif

#ifdef fn_LookupAccountSidA
#define LookupAccountSidA_Hash 0x0161375F
	typedef BOOL(__stdcall *FnLookupAccountSidA)(LPCSTR lpSystemName, PSID lpSid, LPSTR lpName, LPDWORD cchName, LPSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
#endif

#ifdef fn_LookupPrivilegeNameW
#define LookupPrivilegeNameW_Hash 0xFBB4491A
	typedef BOOL(__stdcall *FnLookupPrivilegeNameW)(LPCWSTR lpSystemName, PLUID lpLuid, LPWSTR lpName, LPDWORD cchName);
#endif

#ifdef fn_LookupPrivilegeValueA
#define LookupPrivilegeValueA_Hash 0xA51FC6C9
	typedef BOOL(__stdcall *FnLookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
#endif

#ifdef fn_OpenProcessToken
#define OpenProcessToken_Hash 0x8F9D39D9
	typedef BOOL(__stdcall *FnOpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
#endif

#ifdef fn_OpenThreadToken
#define OpenThreadToken_Hash 0x273B3191
typedef BOOL (__stdcall *FnOpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
#endif

#ifdef fn_SetTokenInformation
#define SetTokenInformation_Hash 0x95D9443C
	typedef BOOL(__stdcall *FnSetTokenInformation)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength);
#endif

#ifdef fn_RegCreateKeyExW
#define RegCreateKeyExW_Hash 0xEB8441BF
	typedef LONG(__stdcall *FnRegCreateKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
#endif

#ifdef fn_RegDeleteValueW
#define RegDeleteValueW_Hash 0x48B11C3A
	typedef LONG(__stdcall *FnRegDeleteValueW)(HKEY hKey, LPCWSTR lpValueName);
#endif

#ifdef fn_RegSetValueExW
#define RegSetValueExW_Hash 0xCAF29434
	typedef LONG(__stdcall *FnRegSetValueExW)(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
#endif

#ifdef fn_RegCloseKey
#define RegCloseKey_Hash 0x373271D3
	typedef LONG(__stdcall *FnRegCloseKey)(HKEY hKey);
#endif

#ifdef fn_RegOpenKeyExW
#define RegOpenKeyExW_Hash 0x1A164D3E
	typedef LONG(__stdcall *FnRegOpenKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
#endif

#ifdef fn_RegQueryValueExW
#define RegQueryValueExW_Hash 0xBB64B977
	typedef LONG(WINAPI *FnRegQueryValueExW)(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
#endif

#ifdef fn_RegEnumKeyExW
#define RegEnumKeyExW_Hash 0x9A964B3C
	typedef LONG(__stdcall *FnRegEnumKeyExW)(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);
#endif

#ifdef fn_IsTextUnicode
#define IsTextUnicode_Hash 0x08034A3D
	typedef BOOL(__stdcall *FnIsTextUnicode)(CONST VOID* pBuffer, int cb, LPINT lpi);
#endif

#ifdef fn_RegOpenKeyA
#define RegOpenKeyA_Hash 0x39C2C58F
	typedef LONG(__stdcall *FnRegOpenKeyA)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
#endif

#ifdef fn_RegEnumValueA
#define RegEnumValueA_Hash 0x17F72120
	typedef LONG(__stdcall *FnRegEnumValueA)(HKEY hKey, DWORD dwIndex, LPTSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
#endif 

#ifdef fn_RegOpenKeyW
#define RegOpenKeyW_Hash 0x39C2C5A5
	typedef LONG(__stdcall *FnRegOpenKeyW)(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);
#endif

#ifdef fn_CredEnumerateW
#define CredEnumerateW_Hash 0x99813B32
	typedef BOOL(__stdcall *FnCredEnumerateW)(LPCWSTR Filter, DWORD Flags, DWORD* Count, PCREDENTIALW** Credentials);
#endif

#ifdef fn_CredEnumerateA
#define CredEnumerateA_Hash 0x99813B1C
	typedef BOOL(__stdcall *FnCredEnumerateA)(LPCSTR Filter, DWORD Flags, DWORD* Count, PCREDENTIALA** Credentials);
#endif

#ifdef fn_CredFree
#define CredFree_Hash 0x94FA92A4
	typedef VOID(__stdcall *FnCredFree)(PVOID Buffer);
#endif

#ifdef fn_GetUserNameW
#define GetUserNameW_Hash 0x56AF112F
	typedef BOOL(__stdcall *FnGetUserNameW)(LPWSTR lpBuffer, LPDWORD lpnSize);
#endif

#ifdef fn_RevertToSelf
#define RevertToSelf_Hash 0x5996CABB
	typedef BOOL(__stdcall *FnRevertToSelf)(void);
#endif

#ifdef fn_ImpersonateLoggedOnUser
#define ImpersonateLoggedOnUser_Hash 0xDC02E56E
	typedef BOOL(__stdcall *FnImpersonateLoggedOnUser)(HANDLE hToken);
#endif

#ifdef fn_CryptGetUserKey
#define CryptGetUserKey_Hash 0xC946C097
	typedef BOOL(__stdcall *FnCryptGetUserKey)(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey);
#endif

#ifdef fn_CryptExportKey
#define CryptExportKey_Hash 0xB9C88C64
	typedef BOOL(__stdcall *FnCryptExportKey)(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
#endif

#ifdef fn_CryptDestroyKey
#define CryptDestroyKey_Hash 0xA9DEBEA2
	typedef BOOL(__stdcall *FnCryptDestroyKey)(HCRYPTKEY hKey);
#endif

#ifdef fn_CryptAcquireContextW
#define CryptAcquireContextW_Hash 0x12D6FBA0
	typedef BOOL(__stdcall *FnCryptAcquireContextW)(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags);
#endif

#ifdef fn_CryptReleaseContext
#define CryptReleaseContext_Hash 0xD7BC4715
	typedef BOOL(__stdcall *FnCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
#endif

#ifdef fn_CryptCreateHash
#define CryptCreateHash_Hash 0x4A8F2774
	typedef BOOL(__stdcall *FnCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
#endif

#ifdef fn_CryptHashData
#define CryptHashData_Hash 0x892717AD
	typedef BOOL(__stdcall *FnCryptHashData)(HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
#endif

#ifdef fn_CryptGetHashParam
#define CryptGetHashParam_Hash 0xA6E22293
	typedef BOOL(__stdcall *FnCryptGetHashParam)(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
#endif

#ifdef fn_CryptDestroyHash
#define CryptDestroyHash_Hash 0x53952C3E
	typedef BOOL(__stdcall *FnCryptDestroyHash)(HCRYPTHASH hHash);
#endif

#define CryptGenRandom_Hash 0x3960B855
typedef BOOL (__stdcall *FnCryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);

#ifdef fn_RegOpenCurrentUser
#define RegOpenCurrentUser_Hash 0x01C46FCE
	typedef LONG(__stdcall *FnRegOpenCurrentUser)(REGSAM samDesired, PHKEY phkResult);
#endif

#ifdef fn_OpenSCManagerW
#define OpenSCManagerW_Hash 0x3910E634
	typedef SC_HANDLE(__stdcall *FnOpenSCManagerW)(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
#endif

#define CreateServiceW_Hash 0x78A5083A
typedef SC_HANDLE (__stdcall *FnCreateServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);

#define ChangeServiceConfigW_Hash 0x21F8C413
typedef BOOL(__stdcall *FnChangeServiceConfigW)(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName);

#ifdef fn_EnumServicesStatusW
#define EnumServicesStatusW_Hash 0xD6EE7F3D
	typedef BOOL(__stdcall *FnEnumServicesStatusW)(SC_HANDLE hSCManager, DWORD dwServiceType, DWORD dwServiceState, LPENUM_SERVICE_STATUS lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle);
#endif 

#ifdef fn_CloseServiceHandle
#define CloseServiceHandle_Hash 0xC1A8E16C
	typedef BOOL(__stdcall *FnCloseServiceHandle)(SC_HANDLE hSCObject);
#endif

#ifdef fn_OpenServiceW
#define OpenServiceW_Hash 0x785B0631
	typedef SC_HANDLE(__stdcall *FnOpenServiceW)(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);
#endif

#define StartServiceW_Hash 0x481F1EB8
typedef BOOL (__stdcall *FnStartServiceW)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);

#define QueryServiceStatus_Hash 0xF42A38F3
typedef BOOL (__stdcall *FnQueryServiceStatus)(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);

#ifdef fn_QueryServiceConfigW
#define QueryServiceConfigW_Hash 0x1DCE4B93
	typedef BOOL(__stdcall *FnQueryServiceConfigW)(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
#endif

	typedef enum _TAG_INFO_LEVEL
	{
		eTagInfoLevelNameFromTag = 1, // TAG_INFO_NAME_FROM_TAG
		eTagInfoLevelNamesReferencingModule, // TAG_INFO_NAMES_REFERENCING_MODULE
		eTagInfoLevelNameTagMapping, // TAG_INFO_NAME_TAG_MAPPING
		eTagInfoLevelMax
	} TAG_INFO_LEVEL;

	typedef struct _TAG_INFO_NAME_FROM_TAG_IN_PARAMS
	{
		ULONG dwPid;
		ULONG dwTag;
	} TAG_INFO_NAME_FROM_TAG_IN_PARAMS, *PTAG_INFO_NAME_FROM_TAG_IN_PARAMS;

	typedef struct _TAG_INFO_NAME_FROM_TAG_OUT_PARAMS
	{
		ULONG eTagType;
		PWSTR pszName;
	} TAG_INFO_NAME_FROM_TAG_OUT_PARAMS, *PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS;


	typedef struct _TAG_INFO_NAME_FROM_TAG
	{
		TAG_INFO_NAME_FROM_TAG_IN_PARAMS InParams;
		TAG_INFO_NAME_FROM_TAG_OUT_PARAMS OutParams;
	} TAG_INFO_NAME_FROM_TAG, *PTAG_INFO_NAME_FROM_TAG;

#ifdef fn_I_QueryTagInformation
#define I_QueryTagInformation_Hash 0x3DCBC9CD
	typedef ULONG(__stdcall *FnI_QueryTagInformation)(PCWSTR Reserved, TAG_INFO_LEVEL InfoLevel, PVOID Data);
#endif

#define StartServiceCtrlDispatcherW_Hash 0xA1B2CEC9
typedef BOOL (__stdcall *FnStartServiceCtrlDispatcherW)(CONST SERVICE_TABLE_ENTRYW* lpServiceStartTable);

#define RegisterServiceCtrlHandlerW_Hash 0x352D9000
typedef SERVICE_STATUS_HANDLE (__stdcall *FnRegisterServiceCtrlHandlerW)(LPCWSTR lpServiceName, LPHANDLER_FUNCTION lpHandlerProc);

#define SetServiceStatus_Hash 0x63AB2B93
typedef BOOL (__stdcall *FnSetServiceStatus)(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus);

#endif // FUNCS_ADVAPI32

#ifdef FUNCS_SHELL32

	// shell32.dll
#ifdef fn_ShellExecuteExW
#define ShellExecuteExW_Hash 0x4BEAC171
	typedef NTSTATUS(__stdcall *FnShellExecuteExW)(HANDLE Handle);
#endif

#ifdef fn_SHCreateItemFromParsingName
#define SHCreateItemFromParsingName_Hash 0xFB88F55A
	typedef HRESULT(__stdcall *FnSHCreateItemFromParsingName)(PCWSTR pszPath, IBindCtx* pbc, REFIID riid, void **ppv);
#endif

#ifdef fn_SHGetSpecialFolderPathW
#define SHGetSpecialFolderPathW_Hash 0x4FC4BE4A
	typedef BOOL(__stdcall *FnSHGetSpecialFolderPathW)(HWND hwndOwner, LPWSTR lpszPath, int nFolder, BOOL fCreate);
#endif

#ifdef fn_SHGetFolderPathW
#define SHGetFolderPathW_Hash 0x9EC96CB7
	typedef HRESULT(__stdcall *FnSHGetFolderPathW)(HWND hwndOwner, int nFolder, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath);
#endif

#ifdef fn_Shell_NotifyIconW
#define Shell_NotifyIconW_Hash 0xF7FE6B79
	typedef BOOL(__stdcall *FnShell_NotifyIconW)(DWORD dwMessage, PNOTIFYICONDATA lpdata);
#endif // fn_Shell_NotifyIconW

#ifdef fn_SHGetFileInfoW
#define SHGetFileInfoW_Hash 0x17F4CC3C
	typedef DWORD_PTR(__stdcall *FnSHGetFileInfoW)(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags);
#endif

#define SHGetKnownFolderPath_Hash 0x8C2594DD
typedef HRESULT (__stdcall *FnSHGetKnownFolderPath)(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR *ppszPath);

#endif // FUNCS_SHELL32

#ifdef FUNCS_OLE32

	// ole32.dll
#ifdef fn_CoInitialize
#define CoInitialize_Hash 0x3A570641
	typedef HRESULT(__stdcall *FnCoInitialize)(LPVOID pvReserved);
#endif

#ifdef fn_CoInitializeEx
#define CoInitializeEx_Hash 0x64B90561
	typedef HRESULT(__stdcall *FnCoInitializeEx)(LPVOID pvReserved, DWORD dwCoinit);
#endif

#ifdef fn_CoUninitialize
#define CoUninitialize_Hash 0x2AD90F4C
	typedef void(__stdcall *FnCoUninitialize)();
#endif

#ifdef fn_CoGetObject
#define CoGetObject_Hash 0xF6B679D3
	typedef HRESULT(__stdcall *FnCoGetObject)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv);
#endif

#ifdef fn_CoCreateInstance
#define CoCreateInstance_Hash 0xCFF55208
	typedef HRESULT(__stdcall *FnCoCreateInstance)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, void ** ppv);
#endif

#ifdef fn_CreateStreamOnHGlobal
#define CreateStreamOnHGlobal_Hash 0x156BBD5F
	typedef HRESULT(__stdcall *FnCreateStreamOnHGlobal)(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM* ppstm);
#endif

#ifdef fn_GetRunningObjectTable
#define GetRunningObjectTable_Hash 0xB8A0B876
	typedef HRESULT(__stdcall *FnGetRunningObjectTable)(DWORD reserved, LPRUNNINGOBJECTTABLE * pprot);
#endif

#ifdef fn_CreateItemMoniker
#define CreateItemMoniker_Hash 0x29143B93
	typedef HRESULT(__stdcall *FnCreateItemMoniker)(LPCOLESTR lpszDelim, LPCOLESTR lpszItem, LPMONIKER FAR * ppmk);
#endif

#ifdef fn_CoTaskMemFree
#define CoTaskMemFree_Hash 0xA81B3D2B
	typedef void(__stdcall *FnCoTaskMemFree)(void * pv);
#endif

#ifdef fn_IsEqualGUID
#define IsEqualGUID_Hash 0x348E5B93
	typedef BOOL(__stdcall *FnIsEqualGUID)(REFGUID rguid1, REFGUID rguid2);
#endif

#ifdef fn_GetHGlobalFromStream
#define GetHGlobalFromStream_Hash 0x05D486D4
	typedef HRESULT(__stdcall *FnGetHGlobalFromStream)(IStream* pStream, HGLOBAL* phglobal);
#endif

#ifdef fn_StgOpenStorage
#define StgOpenStorage_Hash 0x19250548
	typedef HRESULT(__stdcall *FnStgOpenStorage)(const wchar_t* pwcsName, IStorage* pstgPriority, DWORD grfMode, SNB snbExclude, DWORD reserved, IStorage** ppstgOpen);
#endif

#ifdef fn_OleInitialize
#define OleInitialize_Hash 0x2A2F1AC6
	typedef HRESULT(__stdcall *FnOleInitialize)(LPVOID pvReserved);
#endif

#ifdef fn_OleUninitialize
#define OleUninitialize_Hash 0x8B2B230B
	typedef void(__stdcall *FnOleUninitialize)(void);
#endif

#ifdef fn_CoInitializeSecurity
#define CoInitializeSecurity_Hash 0xAF70AC05
	typedef HRESULT(__stdcall *FnCoInitializeSecurity)(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE *asAuthSvc, void *pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void *pAuthList, DWORD dwCapabilities, void *pReserved3);
#endif

#ifdef fn_CoSetProxyBlanket
#define CoSetProxyBlanket_Hash 0x31503994
	typedef HRESULT(__stdcall *FnCoSetProxyBlanket)(IUnknown *pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR *pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
#endif

#ifdef fn_CLSIDFromString
#define CLSIDFromString_Hash 0x4A22F209
	typedef HRESULT(__stdcall *FnCLSIDFromString)(LPCOLESTR lpsz, LPCLSID pclsid);
#endif

#ifdef fn_CLSIDFromProgID
#define CLSIDFromProgID_Hash 0xC562E3E4
	typedef HRESULT(__stdcall *FnCLSIDFromProgID)(LPCOLESTR lpszProgID, LPCLSID lpclsid);
#endif

#ifdef fn_OleLockRunning
#define OleLockRunning_Hash 0x39C92447
	typedef HRESULT(__stdcall *FnOleLockRunning)(LPUNKNOWN pUnknown, BOOL fLock, BOOL fLastUnlockCloses);
#endif

#endif // FUNCS_OLE32

#ifdef FUNCS_WINHTTP

#include <winhttp.h>

	// winhttp.dll
#ifdef fn_WinHttpCloseHandle
#define WinHttpCloseHandle_Hash 0x8987E4AD
	typedef NTSTATUS(__stdcall *FnWinHttpCloseHandle)(HINTERNET hInternet);
#endif

#ifdef fn_WinHttpConnect
#define WinHttpConnect_Hash 0xE8911DD0
	typedef HINTERNET(__stdcall *FnWinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
#endif

#ifdef fn_WinHttpOpen
#define WinHttpOpen_Hash 0xB73F16BF
	typedef HINTERNET(__stdcall *FnWinHttpOpen)(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags);
#endif

#ifdef fn_WinHttpCrackUrl
#define WinHttpCrackUrl_Hash 0x792CC093
	typedef BOOL(__stdcall *FnWinHttpCrackUrl)(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents);
#endif

#ifdef fn_WinHttpOpenRequest
#define WinHttpOpenRequest_Hash 0xCB7018BB
	typedef HINTERNET(__stdcall *FnWinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
#endif

#ifdef fn_WinHttpQueryHeaders
#define WinHttpQueryHeaders_Hash 0x5745236E
	typedef BOOL(__stdcall *FnWinHttpQueryHeaders)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
#endif

#ifdef fn_WinHttpReceiveResponse
#define WinHttpReceiveResponse_Hash 0x190C5FE0
	typedef BOOL(__stdcall *FnWinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);
#endif

#ifdef fn_WinHttpSendRequest
#define WinHttpSendRequest_Hash 0x6B3021BA
	typedef BOOL(__stdcall *FnWinHttpSendRequest)(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
#endif

#ifdef fn_WinHttpSetOption
#define WinHttpSetOption_Hash 0x52B6EA1A
	typedef BOOL(__stdcall *FnWinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
#endif

#ifdef fn_WinHttpSetTimeouts
#define WinHttpSetTimeouts_Hash 0x2A1077BC
	typedef BOOL(__stdcall *FnWinHttpSetTimeouts)(HINTERNET hInternet, int dwResolveTimeout, int dwConnectTimeout, int dwSendTimeout, int dwReceiveTimeout);
#endif

#ifdef fn_WinHttpQueryDataAvailable
#define WinHttpQueryDataAvailable_Hash 0x0A7F7D6C
	typedef BOOL(__stdcall *FnWinHttpQueryDataAvailable)(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
#endif

#ifdef fn_WinHttpReadData
#define WinHttpReadData_Hash 0xB9F4F071
	typedef BOOL(__stdcall *FnWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
#endif

#ifdef fn_WinHttpWriteData
#define WinHttpWriteData_Hash 0x930F17F2
	typedef BOOL(__stdcall *FnWinHttpWriteData)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
#endif

#ifdef fn_WinHttpAddRequestHeaders
#define WinHttpAddRequestHeaders_Hash 0xD7007887
	typedef BOOL(__stdcall *FnWinHttpAddRequestHeaders)(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
#endif

#ifdef fn_WinHttpGetIEProxyConfigForCurrentUser
#define WinHttpGetIEProxyConfigForCurrentUser_Hash 0x923310CC
	typedef BOOL(__stdcall *FnWinHttpGetIEProxyConfigForCurrentUser)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig);
#endif

#ifdef fn_WinHttpGetProxyForUrl
#define WinHttpGetProxyForUrl_Hash 0x4369344D
	typedef BOOL(__stdcall *FnWinHttpGetProxyForUrl)(HINTERNET hSession, LPCWSTR lpcwszUrl, WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions, WINHTTP_PROXY_INFO* pProxyInfo);
#endif

#endif // FUNCS_WINHTTP

#ifdef FUNCS_IPHLPAPI

#ifdef fn_GetExtendedTcpTable
#define GetExtendedTcpTable_Hash 0x8C4F2E64
	typedef DWORD(__stdcall *FnGetExtendedTcpTable)(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved);
#endif

#ifdef fn_GetExtendedUdpTable
#define GetExtendedUdpTable_Hash 0xCC572E64
	typedef DWORD(__stdcall *FnGetExtendedUdpTable)(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved);
#endif

#endif // FUNCS_WINHTTP

#ifdef FUNCS_PSAPI

	// psapi.dll
#ifdef fn_EnumProcessModules
#define EnumProcessModules_Hash 0x41155D38
	typedef BOOL(WINAPI *FnEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
#endif

#ifdef fn_GetProcessImageFileNameW
#define GetProcessImageFileNameW_Hash 0x43B06594
	typedef DWORD(__stdcall *FnGetProcessImageFileNameW)(HANDLE hProcess, LPTSTR lpImageFileName, DWORD nSize);
#endif // GetProcessImageFileNameW

#ifdef fn_GetModuleFileNameExW
#define GetModuleFileNameExW_Hash 0x076D1CB6
	typedef DWORD(__stdcall *FnGetModuleFileNameExW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
#endif // fn_GetModuleFileNameExW

#ifdef fn_GetModuleBaseNameW
#define GetModuleBaseNameW_Hash 0xD77E175A
	typedef DWORD(__stdcall *FnGetModuleBaseNameW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);
#endif

#ifdef fn_GetProcessMemoryInfo
#define GetProcessMemoryInfo_Hash 0x6EC0E584
	typedef BOOL(__stdcall *FnGetProcessMemoryInfo)(HANDLE Process, PPROCESS_MEMORY_COUNTERS ppsmemCounters, DWORD cb);
#endif

#endif // FUNCS_PSAPI

#ifdef FUNCS_IMAGEHLP

	// imagehlp.dll
#ifdef fn_CheckSumMappedFile
#define CheckSumMappedFile_Hash 0x12352B56
	typedef PIMAGE_NT_HEADERS(__stdcall *FnCheckSumMappedFile)(PVOID BaseAddress, DWORD FileLength, PDWORD HeaderSum, PDWORD CheckSum);
#endif

#endif // FUNCS_IMAGEHLP

#ifdef FUNCS_WINMM

	// Winmm.lib
#ifdef fn_timeGetTime
#define timeGetTime_Hash 0xF9DADBAD
	typedef DWORD(__stdcall *FntimeGetTime)(VOID);
#endif

#endif // FUNCS_WINMM

#ifdef FUNCS_MSIMG32

	// msimg32.dll

#ifdef fn_AlphaBlend
#define AlphaBlend_Hash 0x3562C2BC
	typedef BOOL(__stdcall *FnAlphaBlend)(HDC hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, HDC hdcSrc, int nXOriginSrc, int nYOriginSrc,
		int nWidthSrc, int nHeightSrc, BLENDFUNCTION blendFunction);
#endif

#ifdef fn_GradientFill
#define GradientFill_Hash 0x79D30834
	typedef BOOL(__stdcall *FnGradientFill)(HDC hdc, PTRIVERTEX pVertex, ULONG dwNumVertex, PVOID pMesh, ULONG dwNumMesh, ULONG dwMode);
#endif

#endif // FUNCS_MSIMG32


#ifdef FUNCS_WS2_32
// ws2_32.dll
#ifdef fn_WSAStartup
#define WSAStartup_Hash 0xB6BB0BC8
	typedef int (WSAAPI *FnWSAStartup)(IN WORD wVersionRequired, OUT LPWSADATA lpWSAData);
#endif

#ifdef fn_WSACleanup
#define WSACleanup_Hash 0x36FAE3BC
	typedef int (WSAAPI *FnWSACleanup)(void);
#endif

#ifdef fn_WSAGetLastError
#define WSAGetLastError_Hash 0x6775361A
	typedef int (WSAAPI *FnWSAGetLastError)(void);
#endif

	// typedef SOCKET (__stdcall *FnWSASocketA)( IN int af, IN int type, IN int protocol, IN LPWSAPROTOCOL_INFOA lpProtocolInfo, IN GROUP g, IN DWORD dwFlags );

#ifdef fn_socket
#define socket_Hash 0x939292A5
	typedef SOCKET(WSAAPI *Fnsocket)(IN int af, IN int type, IN int protocol);
#endif

#define bind_Hash 0x0DC1A495
typedef int (WSAAPI *Fnbind)(IN SOCKET s, IN const struct sockaddr FAR *addr, IN int namelen);

#ifdef fn_gethostbyname
#define gethostbyname_Hash 0x8A9AEA4C
	typedef struct hostent FAR* (WSAAPI *Fngethostbyname)(__in const char FAR * name);
#endif

#ifdef fn_getaddrinfo
#define getaddrinfo_Hash 0x3886F4C9
	typedef INT(WSAAPI *Fngetaddrinfo)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
#endif

#ifdef fn_freeaddrinfo
#define freeaddrinfo_Hash 0x38B318C9
	typedef VOID(WSAAPI *Fnfreeaddrinfo)(PADDRINFOA pAddrInfo);
#endif

#ifdef fn_setsockopt
#define setsockopt_Hash 0xB7D2FFD4
	typedef int (WSAAPI FAR *Fnsetsockopt)(IN SOCKET s, IN int level, IN int optname, IN const char FAR * optval, IN int optlen);
#endif

#ifdef fn_getsockopt
#define getsockopt_Hash 0x37D2FFD3
	typedef int (WSAAPI FAR *Fngetsockopt)(IN SOCKET s, IN int level, IN int optname, char FAR * optval, IN OUT int FAR *optlen);
#endif

	// typedef int (__stdcall *Fngetsockname)( IN SOCKET s, OUT struct sockaddr FAR *name, IN OUT int FAR * namelen);
	// typedef u_short (__stdcall *Fnntohs)(IN u_short netshort);

#ifdef fn_htons
#define htons_Hash 0x1441BCAD
	typedef u_short(WSAAPI *Fnhtons)(IN u_short hostshort);
#endif

#ifdef fn_select
#define select_Hash 0x12B27AAA
	typedef int (WSAAPI *Fnselect)(IN int nfds, IN OUT fd_set FAR *readfds, IN OUT fd_set FAR *writefds, IN OUT fd_set FAR *exceptfds, IN const struct timeval FAR *timeout);
#endif

	// typedef u_long (__stdcall *Fnhtonl)( IN u_long hostlong);

#ifdef fn_ntohl
#define ntohl_Hash 0x13E1BCA6
	typedef u_long(WSAAPI *Fnntohl)(IN u_long netlong);
#endif

#ifdef fn_connect
#define connect_Hash 0xD34272C3
	typedef int (WSAAPI *Fnconnect)(IN SOCKET s, IN const struct sockaddr FAR *name, IN int namelen);
#endif 

#ifdef fn_ioctlsocket
#define ioctlsocket_Hash 0x78D6F5CE
	typedef int (WSAAPI *Fnioctlsocket)(IN SOCKET s, IN long cmd, IN OUT u_long FAR *argp);
#endif

#ifdef fn_closesocket
#define closesocket_Hash 0x58B701CC
	typedef int (WSAAPI *Fnclosesocket)(IN SOCKET s);
#endif

#ifdef fn_shutdown
#define shutdown_Hash 0x19BAA6BA
	typedef int (WSAAPI *Fnshutdown)(IN SOCKET s, IN int how);
#endif

	// typedef int (__stdcall *Fngethostname)( __out_bcount_part(namelen, return) char FAR * name, IN int namelen);

#ifdef fn_send
#define send_Hash 0x8DC1949D
	typedef int (WSAAPI *Fnsend)(IN SOCKET s, IN const char FAR * buf, IN int len, IN int flags);
#endif

#ifdef fn_recv
#define recv_Hash 0x0C6194AF
	typedef int (WSAAPI *Fnrecv)(IN SOCKET s, __out_bcount_part(len, return) __out_data_source(NETWORK) char FAR * buf, IN int len, IN int flags);
#endif
	// typedef int (__stdcall *Fnsendto)( IN SOCKET s, IN const char FAR * buf, IN int len, IN int flags, IN const struct sockaddr FAR *to, IN int tolen);
	// typedef int (__stdcall *Fnrecvfrom)( IN SOCKET s, __out_bcount_part(len, return) __out_data_source(NETWORK) char FAR * buf, IN int len, IN int flags, __out_bcount(__stdcall *fromlen) struct sockaddr FAR * from, IN OUT int FAR * fromlen);
	// typedef SOCKET (__stdcall *Fnaccept)( IN SOCKET s, OUT struct sockaddr FAR *addr, IN OUT int FAR *addrlen);

#ifdef fn___WSAFDIsSet
#define __WSAFDIsSet_Hash 0xF4B65749
	typedef int (PASCAL *Fn__WSAFDIsSet)(SOCKET fd, fd_set FAR *);
#endif

#ifdef fn_inet_addr
#define inet_addr_Hash 0xD5E2E1BB
	typedef unsigned long (WSAAPI *Fninet_addr)(__in IN const char FAR * cp);
#endif

#define WSAIoctl_Hash 0x55CA0EB8
typedef int(WSAAPI *FnWSAIoctl)(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define WSASetLastError_Hash 0x67753C1A
typedef void (WSAAPI *FnWSASetLastError)(int iError);

#define GetAddrInfoW_Hash 0x9726E135
typedef INT (WSAAPI *FnGetAddrInfoW)(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResults);

#define GetNameInfoW_Hash 0xD70ED437
typedef INT (WSAAPI *FnGetNameInfoW)(const SOCKADDR* pSockaddr, socklen_t SockaddrLength, PWCHAR pNodeBuffer, DWORD NodeBufferSize, PWCHAR pServiceBuffer, DWORD ServiceBufferSize, INT Flags);

#define WSASocketW_Hash 0x36BAC5AC
typedef SOCKET (WSAAPI *FnWSASocketW)(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags);

#define WSARecv_Hash 0xD0723AB4
typedef int (WSAAPI *FnWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define getsockname_Hash 0x7986BEC4
typedef int (WSAAPI *Fngetsockname)(SOCKET s, struct sockaddr FAR * name, int FAR * namelen);

#define getpeername_Hash 0xF9DEC2C1
typedef int (WSAAPI *Fngetpeername)(SOCKET s, struct sockaddr FAR * name, int FAR * namelen);

#define WSASend_Hash 0x51D23AA3
typedef int (WSAAPI *FnWSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define listen_Hash 0x9332A8A7
typedef int (WSAAPI *Fnlisten)(SOCKET s, int backlog);

#define WSADuplicateSocketW_Hash 0xB68842D7
typedef int (WSAAPI *FnWSADuplicateSocketW)(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOW lpProtocolInfo);

#define WSASendTo_Hash 0x536A8DB6
typedef int (WSAAPI *FnWSASendTo)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr FAR * lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define WSARecvFrom_Hash 0xB92ECFB3
typedef int (WSAAPI *FnWSARecvFrom)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr FAR * lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#define htonl_Hash 0x1441BCA6
typedef u_long (WSAAPI *Fnhtonl)(u_long hostlong);

#define FreeAddrInfoW_Hash 0x1726F6B8
typedef VOID (WSAAPI *FnFreeAddrInfoW)(PADDRINFOW pAddrInfo);

#endif // FUNCS_WS2_32

#ifdef FUNCS_OLEAUT32

	// oleaut32.dll
#ifdef fn_SysAllocString
#define SysAllocString_Hash 0xEA24F04D
	typedef BSTR(__stdcall *FnSysAllocString)(const OLECHAR* sz);
#endif

#ifdef fn_SysFreeString
#define SysFreeString_Hash 0x49F6F947
	typedef VOID(__stdcall *FnSysFreeString)(BSTR bstr);
#endif

#ifdef fn_VariantInit
#define VariantInit_Hash 0xF90306BC
	typedef VOID(__stdcall *FnVariantInit)(VARIANTARG* pvarg);
#endif

#ifdef fn_VariantChangeType
#define VariantChangeType_Hash 0x12536E3C
	typedef HRESULT(__stdcall *FnVariantChangeType)(VARIANTARG* pvargDest, VARIANTARG* pvarSrc, unsigned short wFlags, VARTYPE vt);
#endif

#ifdef fn_VariantClear
#define VariantClear_Hash 0xD4DF10D1
	typedef HRESULT(__stdcall *FnVariantClear)(VARIANTARG* pvarg);
#endif

#endif // FUNCS_OLEAUT32

#ifdef FUNCS_CRYPT32

	// crypt32.dll

#ifdef fn_CryptUnprotectData
#define CryptUnprotectData_Hash 0xB47D1513
	typedef BOOL(__stdcall *FnCryptUnprotectData)(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);
#endif

#ifdef fn_CertOpenSystemStoreW
#define CertOpenSystemStoreW_Hash 0x264EB683
	typedef HCERTSTORE(__stdcall *FnCertOpenSystemStoreW)(HCRYPTPROV_LEGACY hprov, LPCWSTR szSubsystemProtocol);
#endif

#ifdef fn_CertEnumCertificatesInStore
#define CertEnumCertificatesInStore_Hash 0x6421C228
	typedef PCCERT_CONTEXT(__stdcall *FnCertEnumCertificatesInStore)(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
#endif

#ifdef fn_CryptAcquireCertificatePrivateKey
#define CryptAcquireCertificatePrivateKey_Hash 0xA015BDC6
	typedef BOOL(__stdcall *FnCryptAcquireCertificatePrivateKey)(PCCERT_CONTEXT pCert, DWORD dwFlags, void* pvReserved, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE* phCryptProvOrNCryptKey, DWORD* pdwKeySpec, BOOL* pfCallerFreeProvOrNCryptKey);
#endif

#ifdef fn_CertCloseStore
#define CertCloseStore_Hash 0x89412BCA
	typedef BOOL(__stdcall *FnCertCloseStore)(HCERTSTORE hCertStore, DWORD dwFlags);
#endif

#endif // FUNCS_CRYPT32

#ifdef FUNCS_PSTOREC

	// pstorec.dll

#ifdef fn_PStoreCreateInstance
#define PStoreCreateInstance_Hash 0x948C5E0B
	typedef HRESULT(__stdcall *FnPStoreCreateInstance)(IPStore **ppProvider, PST_PROVIDERID *pProviderID, void *pReserved, DWORD dwFlags);
#endif

#endif // FUNCS_PSTOREC

#ifdef FUNCS_MSI

	// msi.dll
#ifdef fn_MsiGetComponentPathW
#define MsiGetComponentPathW_Hash 0xDBDF075C
	typedef INSTALLSTATE(__stdcall *FnMsiGetComponentPathW)(LPCWSTR szProduct, LPCWSTR szComponent, LPWSTR lpPathBuf, DWORD* pcchBuf);
#endif

#endif // FUNCS_MSI

#ifdef FUNCS_WININET
	// wininet.dll

#ifdef fn_InternetCrackUrlA
#define InternetCrackUrlA_Hash 0xEA6A259C
	typedef BOOL(__stdcall *FnInternetCrackUrlA)(LPCSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSA lpUrlComponents);
#endif

#ifdef fn_InternetCreateUrlA
#define InternetCreateUrlA_Hash 0xBA1D7776
	typedef BOOL(__stdcall *FnInternetCreateUrlA)(LPURL_COMPONENTSA lpUrlComponents, DWORD dwFlags, LPSTR lpszUrl, LPDWORD lpdwUrlLength);
#endif

#endif // FUNCS_WININET

#ifdef FUNCS_IPHLPAPI

	// iphlpapi.dll
#ifdef fn_GetAdaptersInfo
#define GetAdaptersInfo_Hash 0x39ED3F00
	typedef DWORD(__stdcall *FnGetAdaptersInfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
#endif
#define GetAdaptersAddresses_Hash 0xED1FCB1F
typedef ULONG (__stdcall *FnGetAdaptersAddresses)(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);

#endif // FUNCS_IPHLPAPI

#ifdef FUNCS_URLMON

	// urlmon.dll

#ifdef fn_ObtainUserAgentString
#define ObtainUserAgentString_Hash 0x8AF70F25
	typedef HRESULT(__stdcall *FnObtainUserAgentString)(DWORD dwOption, LPCSTR pcszUAOut, DWORD *cbSize);
#endif

#endif // FUNCS_URLMON

	// version.dll

#ifdef FUNCS_VERSION

#ifdef fn_GetFileVersionInfoSizeW
#define GetFileVersionInfoSizeW_Hash 0x267D323F
	typedef DWORD(__stdcall *FnGetFileVersionInfoSizeW)(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
#endif

#ifdef fn_GetFileVersionInfoW
#define GetFileVersionInfoW_Hash 0xB49B39A1
	typedef BOOL(__stdcall *FnGetFileVersionInfoW)(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
#endif

#ifdef fn_VerQueryValueW
#define VerQueryValueW_Hash 0x48331EC0
	typedef BOOL(__stdcall *FnVerQueryValueW)(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
#endif

#endif // FUNCS_VERSION

#ifdef FUNCS_CRTDLL

	// crtdll.dll
#ifdef fn_atof
#define atof_Hash 0x8DE1D096
	typedef double(__cdecl *Fnatof)(const char *_String);
#endif

#ifdef fn_cos
#define cos_Hash 0x0DE18C73
	typedef double(__cdecl *Fncos)(double _X);
#endif

#ifdef fn_sin
#define sin_Hash 0x0D21CC6E
	typedef double(__cdecl *Fnsin)(double _X);
#endif

#ifdef fn_abs
#define abs_Hash 0x0C418473
	typedef int(__cdecl *Fnabs)(int _X);
#endif

#endif // FUNCS_CRTDLL

#ifdef FUNCS_D3D9

	// d3d9.dll

#ifdef fn_Direct3DCreate9
#define Direct3DCreate9_Hash 0xF7712B0F
	typedef IDirect3D9* (__stdcall *FnDirect3DCreate9)(UINT SDKVersion);

#endif

#endif // FUNCS_D3D9



// Определение внутренних функций
/*
typedef void(__stdcall *Fnservercomm_init)(servercomm_request_t* pSCRequest, int requestType, wchar_t* method, wchar_t* path, wchar_t* fileName, FnAppendData fnAppendData, FnOnReceiveComplete fnOnReceiveComplete);
typedef void(__stdcall *Fnservercomm_done)(servercomm_request_t* pSCRequest);
typedef int(__stdcall *Fnservercomm_do_request)(servercomm_request_t* pSCRequest, int attempts, int failTimeout, int onlyFirstDomain);
typedef int(__stdcall *Fnservercomm_get_info_request)(int attempts, const int failTimeout, int onlyFirstDomain);
typedef int(__stdcall *Fnservercomm_check_internet)();
typedef void(__stdcall *Fnarc4_crypt_self)(uint8_t* buffer, uint32_t length, const uint8_t* key, uint32_t keylen);

typedef PVOID(__stdcall *Fnutils_map_file)(const wchar_t* lpPath, DWORD dwFileAccess, DWORD dwFileFlags, DWORD dwPageAccess, DWORD dwMapAccess, DWORD mapSize, uint32_t* pdwSize);
typedef BOOL(__stdcall *Fnutils_file_write)(const wchar_t* filePath, DWORD dwFlags, uint8_t* pBuffer, DWORD dwSize);
typedef uint8_t* (__stdcall *Fnutils_file_read)(const wchar_t* lpFile, uint32_t* pdwSize);
typedef uint8_t* (__stdcall *Fnutils_decrypt_buffer)(const uint8_t* cryptedData, uint32_t size, uint32_t* pOutSize);

typedef void* (__stdcall *Fnmemalloc)(size_t sz);
typedef void* (__stdcall *Fnmemrealloc)(void* pBuffer, size_t newSize);
typedef void(__stdcall *Fnmemfree)(void* pBuffer);

typedef wchar_t* (__stdcall *Fnutils_ansi2wide)(const char* strA);
typedef puint_t(__stdcall *Fnutils_get_symbol_by_hash)(uint8_t* moduleBase, uint32_t dwHash);
typedef int(__stdcall *Fnutils_abs)(int n);
typedef uint32_t(__stdcall *Fnutils_get_current_unixtime)();
*/
/*
#define fn_servercomm_init pZModuleBlock->fnservercomm_init
#define fn_servercomm_done pZModuleBlock->fnservercomm_done
#define fn_servercomm_do_request pZModuleBlock->fnservercomm_do_request
#define fn_servercomm_get_info_request pZModuleBlock->fnservercomm_get_info_request
#define fn_servercomm_check_internet pZModuleBlock->fnservercomm_check_internet
#define fn_arc4_crypt_self pZModuleBlock->fnarc4_crypt_self
#define fn_utils_map_file pZModuleBlock->fnutils_map_file
#define fn_utils_file_write pZModuleBlock->fnutils_file_write
#define fn_utils_file_read pZModuleBlock->fnutils_file_read
#define fn_utils_decrypt_buffer pZModuleBlock->fnutils_decrypt_buffer
#define fn_memalloc pZModuleBlock->fnmemalloc
#define fn_memrealloc pZModuleBlock->fnmemrealloc
#define fn_memfree pZModuleBlock->fnmemfree
#define fn_utils_ansi2wide pZModuleBlock->fnutils_ansi2wide
#define fn_utils_get_symbol_by_hash pZModuleBlock->fnutils_get_symbol_by_hash
#define fn_utils_abs pZModuleBlock->fnutils_abs
#define fn_utils_get_current_unixtime pZModuleBlock->fnutils_get_current_unixtime
*/


// dynfuncs.h
typedef uint8_t* (__stdcall *Fndynfuncs_get_module_base_by_hash)(uint32_t dwHash);
typedef puint_t (__stdcall *Fndynfuncs_get_symbol_by_hash)(uint8_t* moduleBase, uint32_t dwHash);

// memory.h
typedef HANDLE(__stdcall *Fnmemory_process_heap)(void);
#define fn_memory_process_heap _pZmoduleBlock->fnmemory_process_heap
typedef void*(__stdcall *Fnmemory_alloc)(size_t sz);
#define fn_memory_alloc _pZmoduleBlock->fnmemory_alloc
typedef void*(__stdcall *Fnmemory_realloc)(void* ptr, size_t newSize);
#define fn_memory_realloc _pZmoduleBlock->fnmemory_realloc
typedef BOOLEAN(__stdcall *Fnmemory_free)(void* ptr);
#define fn_memory_free _pZmoduleBlock->fnmemory_free

// native.h
typedef BOOLEAN(__stdcall *FnEnumDirectoryFile)(PFILE_DIRECTORY_INFORMATION Information, PVOID Context);

typedef NTSTATUS (__stdcall *Fnnative_create_file_win32)(PHANDLE pFileHandle, PWSTR fileName, ACCESS_MASK desiredAccess, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PULONG createStatus);
#define fn_native_create_file_win32 _pZmoduleBlock->fnnative_create_file_win32
typedef NTSTATUS (__stdcall *Fnnative_delete_file_win32)(PWSTR fileName);
#define fn_native_delete_file_win32 _pZmoduleBlock->fnnative_delete_file_win32
typedef NTSTATUS (__stdcall *Fnnative_enum_directory_file)(HANDLE fileHandle, PUNICODE_STRING SearchPattern, FnEnumDirectoryFile fnCallback, PVOID Context);
#define fn_native_enum_directory_file _pZmoduleBlock->fnnative_enum_directory_file
typedef NTSTATUS (__stdcall *Fnnative_open_process)(PHANDLE processHandle, ACCESS_MASK desiredAccess, HANDLE processId);
#define fn_native_open_process _pZmoduleBlock->fnnative_open_process
typedef NTSTATUS(__stdcall *Fnnative_get_process_path_by_id)(HANDLE processId, wchar_t** filePath);
#define fn_native_get_process_path_by_id _pZmoduleBlock->fnnative_get_process_path_by_id
typedef NTSTATUS (__stdcall *Fnnative_get_process_path)(HANDLE hProcess, wchar_t** filePath);
#define fn_native_get_process_path _pZmoduleBlock->fnnative_get_process_path
typedef NTSTATUS (__stdcall *Fnnative_query_token_variable_size)(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS tokenInformationClass, PVOID* pBuffer);
#define fn_native_query_token_variable_size _pZmoduleBlock->fnnative_query_token_variable_size
typedef NTSTATUS (__stdcall *Fnnative_enum_processes)(pvoid_t* pProcesses, SYSTEM_INFORMATION_CLASS sic);
#define fn_native_enum_processes _pZmoduleBlock->fnnative_enum_processes
typedef NTSTATUS (__stdcall *Fnnative_last_status)(void);
#define fn_native_last_status _pZmoduleBlock->fnnative_last_status
typedef int(__stdcall *Fnnative_zms_to_unicode)(const wchar_t* str, PUNICODE_STRING uStr);
#define fn_native_zms_to_unicode _pZmoduleBlock->fnnative_zms_to_unicode
typedef NTSTATUS (__stdcall *Fnnative_initialize_key_object_attributes)(HANDLE rootDirectory, PUNICODE_STRING objectName, ULONG attributes, POBJECT_ATTRIBUTES objectAttributes, PHANDLE needsClose);
#define fn_native_initialize_key_object_attributes _pZmoduleBlock->fnnative_initialize_key_object_attributes
typedef NTSTATUS(__stdcall *Fnnative_open_key)(PHANDLE pKeyHandle, ACCESS_MASK desiredAccess, HANDLE rootDirectory, const wchar_t* objectName, ULONG attributes);
#define fn_native_open_key _pZmoduleBlock->fnnative_open_key
typedef PKEY_VALUE_PARTIAL_INFORMATION (__stdcall *Fnnative_query_registry_value)(HANDLE keyHandle, const wchar_t* valueName);
#define fn_native_query_registry_value _pZmoduleBlock->fnnative_query_registry_value
typedef wchar_t* (__stdcall *Fnnative_query_registry_string)(HANDLE keyHandle, const wchar_t* valueName);
#define fn_native_query_registry_string _pZmoduleBlock->fnnative_query_registry_string
typedef wchar_t*(__stdcall *Fnnative_complete_query_registry_string)(HKEY hRoot, ACCESS_MASK desiredAccess, const wchar_t* regPath, const wchar_t* regKey);
#define fn_native_complete_query_registry_string _pZmoduleBlock->fnnative_complete_query_registry_string
typedef NTSTATUS (__stdcall *Fnnative_enumerate_key)(HANDLE keyHandle, KEY_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo);
#define fn_native_enumerate_key _pZmoduleBlock->fnnative_enumerate_key
typedef NTSTATUS(__stdcall *Fnnative_enumerate_key_value)(HANDLE keyHandle, KEY_VALUE_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo);
#define fn_native_enumerate_key_value _pZmoduleBlock->fnnative_enumerate_key_value

// utils.h
typedef uint32_t (__stdcall *Fnror)(uint32_t value, int places);
typedef uint32_t (__stdcall *Fnrol)(uint32_t value, int places);
typedef uint32_t (__stdcall *Fnutils_strhash)(const char* str);
typedef uint32_t (__stdcall *Fnutils_wcshash)(const wchar_t* str);
typedef uint32_t(__stdcall *Fnutils_wcsihash)(const wchar_t* str);
typedef DWORD(__stdcall *Fnutils_create_thread)(LPTHREAD_START_ROUTINE pvFunc, PVOID pvParam, PHANDLE phHandle, DWORD dwWaitSec);
typedef void(__stdcall *Fnutils_crc32_build_table)(void);
typedef uint32_t(__stdcall *Fnutils_crc32_update)(uint32_t crc32, const uint8_t* buffer, uint32_t size);
typedef void(__stdcall *Fnutils_wcs_random)(wchar_t* outStr, uint32_t bufferLen);
#define fn_utils_wcs_random _pZmoduleBlock->fnutils_wcs_random
typedef char* (__stdcall *Fnutils_machine_guid)(void);
#define fn_utils_machine_guid _pZmoduleBlock->fnutils_machine_guid

// logger.h
typedef void(__cdecl *Fnlogger_log)(const char* dbgFormat, ...);
#define fn_logger_log _pZmoduleBlock->fnlogger_log

// string.h
typedef wchar_t* (__stdcall *Fnzs_new_with_len)(const wchar_t* ptr, uint32_t initlen);
#define fn_zs_new_with_len _pZmoduleBlock->fnzs_new_with_len
typedef wchar_t* (__stdcall *Fnzs_new)(const wchar_t* ptr);
#define fn_zs_new _pZmoduleBlock->fnzs_new
typedef wchar_t* (__stdcall *Fnzs_empty)();
#define fn_zs_empty _pZmoduleBlock->fnzs_empty
typedef wchar_t* (__stdcall *Fnzs_duplicate)(const wchar_t* s);
#define fn_zs_duplicate _pZmoduleBlock->fnzs_duplicate
typedef void(__stdcall *Fnzs_free)(wchar_t* s);
#define fn_zs_free _pZmoduleBlock->fnzs_free
typedef uint32_t(__stdcall *Fnzs_length)(const wchar_t* s);
#define fn_zs_length _pZmoduleBlock->fnzs_length
typedef uint32_t(__stdcall *Fnzs_available)(const wchar_t* s);
#define fn_zs_available _pZmoduleBlock->fnzs_available
typedef char* (__stdcall *Fnzs_to_str)(wchar_t* zs, uint32_t codePage);
#define fn_zs_to_str _pZmoduleBlock->fnzs_to_str
typedef wchar_t* (__stdcall *Fnzs_make_room_for)(wchar_t* zs, uint32_t addlen);
#define fn_zs_make_room_for _pZmoduleBlock->fnzs_make_room_for
typedef wchar_t* (__stdcall *Fnzs_catlen)(wchar_t* zs, const void* t, uint32_t len);
#define fn_zs_catlen _pZmoduleBlock->fnzs_catlen
typedef wchar_t* (__stdcall *Fnzs_cat)(wchar_t* s, const wchar_t* t);
#define fn_zs_cat _pZmoduleBlock->fnzs_cat
typedef void (__stdcall *Fnzs_update_length)(wchar_t* zs);
#define fn_zs_update_length _pZmoduleBlock->fnzs_update_length
typedef wchar_t* (__stdcall *Fnzs_grow)(wchar_t* zs, size_t len);
#define fn_zs_grow _pZmoduleBlock->fnzs_grow
typedef wchar_t (__stdcall *Fnzs_lastchar)(const wchar_t* zs);
#define fn_zs_lastchar _pZmoduleBlock->fnzs_lastchar
typedef wchar_t* (__cdecl *Fnzs_catprintf)(wchar_t* zs, const wchar_t* fmt, ...);
#define fn_zs_catprintf _pZmoduleBlock->fnzs_catprintf

// privilege.h
typedef NTSTATUS(__stdcall *Fnprivelege_enable)(HANDLE hToken, const char* privName);
#define fn_privelege_enable _pZmoduleBlock->fnprivelege_enable

// wmi.h
typedef HRESULT(__cdecl *Fnwmi_extract_arg)(VARIANT* pvArg, char vType, BOOL* pbFreeArg, va_list* marker);
typedef HRESULT(__cdecl *Fnwmi_get_value)(char vType, void* pResult, IDispatch* pDisp, LPCOLESTR szMember, ...);
typedef HRESULT(__stdcall *Fnwmi_enum_begin)(IEnumVARIANT** ppEnum, IDispatch* pDisp);
typedef HRESULT(__stdcall *Fnwmi_enum_next)(IEnumVARIANT* pEnum, IDispatch** ppDisp);
typedef IDispatch* (__stdcall *Fnwmi_get_service)(const wchar_t* name);
typedef int(__stdcall *Fnwmi_obtain_info)(IDispatch* pWmiService, pvoid_t pWmiClass);

// vector.h
struct _vector;

typedef struct _vector* (__stdcall *Fnvector_new)(void);
#define fn_vector_new _pZmoduleBlock->fnvector_new
typedef void(__stdcall *Fnvector_destroy)(struct _vector* vector);
#define fn_vector_destroy _pZmoduleBlock->fnvector_destroy
typedef void(__stdcall *Fnvector_clear)(struct _vector* vector);
#define fn_vector_clear _pZmoduleBlock->fnvector_clear
typedef uint32_t(__stdcall *Fnvector_size)(struct _vector* vector);
#define fn_vector_size _pZmoduleBlock->fnvector_size
typedef uint32_t(__stdcall *Fnvector_count)(struct _vector* vector);
#define fn_vector_count _pZmoduleBlock->fnvector_count
typedef int(__stdcall *Fnvector_push_back)(struct _vector* vector, void* elem);
#define fn_vector_push_back _pZmoduleBlock->fnvector_push_back
typedef void* (__stdcall *Fnvector_pop_back)(struct _vector* vector);
#define fn_vector_pop_back _pZmoduleBlock->fnvector_pop_back
typedef void* (__stdcall *Fnvector_back)(struct _vector* vector);
#define fn_vector_back _pZmoduleBlock->fnvector_back
typedef void* (__stdcall *Fnvector_access)(struct _vector* vector, uint32_t index);
#define fn_vector_access _pZmoduleBlock->fnvector_access
typedef void**(__stdcall *Fnvector_at)(struct _vector* vector, size_t index);
#define fn_vector_at _pZmoduleBlock->fnvector_at
typedef void**(__stdcall *Fnvector_begin)(struct _vector* vector);
#define fn_vector_begin _pZmoduleBlock->fnvector_begin
typedef void**(__stdcall *Fnvector_end)(struct _vector* vector);
#define fn_vector_end _pZmoduleBlock->fnvector_end
typedef void(__stdcall *Fnvector_data_set)(void** iterator, void* elem);
#define fn_vector_data_set _pZmoduleBlock->fnvector_data_set
typedef void* (__stdcall *Fnvector_data_get)(void** iterator);
#define fn_vector_data_get _pZmoduleBlock->fnvector_data_get



#ifdef __cplusplus
}
#endif // __cplusplus


#endif // __COMMON_FUNCTIONS_H_
