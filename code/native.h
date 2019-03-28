#ifndef __COMMON_NATIVE_H_
#define __COMMON_NATIVE_H_

#define NATIVE_KEY_PREDEFINE(Number) ((HANDLE)(LONG_PTR)(-3 - (Number) * 2))
#define NATIVE_KEY_IS_PREDEFINED(Predefine) (((LONG_PTR)(Predefine) < 0) && ((LONG_PTR)(Predefine) & 0x1))
#define NATIVE_KEY_PREDEFINE_TO_NUMBER(Predefine) (ULONG)(((-(LONG_PTR)(Predefine) - 3) >> 1))

#define NATIVE_KEY_LOCAL_MACHINE NATIVE_KEY_PREDEFINE(0) // \Registry\Machine
#define NATIVE_KEY_USERS NATIVE_KEY_PREDEFINE(1) // \Registry\User
#define NATIVE_KEY_CLASSES_ROOT NATIVE_KEY_PREDEFINE(2) // \Registry\Machine\Software\Classes
#define NATIVE_KEY_CURRENT_USER NATIVE_KEY_PREDEFINE(3) // \Registry\User\<SID>
#define NATIVE_KEY_CURRENT_USER_NUMBER 3
#define NATIVE_KEY_MAXIMUM_PREDEFINE 4

#define NATIVE_FIRST_PROCESS(pProcesses) ((PSYSTEM_PROCESS_INFORMATION)(pProcesses))
#define NATIVE_NEXT_PROCESS(pProcess) ( \
    ((PSYSTEM_PROCESS_INFORMATION)(pProcess))->NextEntryOffset ? \
    (PSYSTEM_PROCESS_INFORMATION)((PCHAR)(pProcess) + \
    ((PSYSTEM_PROCESS_INFORMATION)(pProcess))->NextEntryOffset) : \
    NULL \
    )

#define MAX_UNICODE_STACK_BUFFER_LENGTH 256

// The PID of the idle process.
#define SYSTEM_IDLE_PROCESS_ID ((HANDLE)0)
// The PID of the system process.
#define SYSTEM_PROCESS_ID ((HANDLE)4)

#ifdef _M_IX86
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7ffe0000)
#endif

#ifdef _M_X64
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7ffe0000)
#endif

#define PTR_ADD_OFFSET(ptr, off) ((PVOID)((ULONG_PTR)(ptr) + (ULONG_PTR)(off)))

// Specifies a PEB string.
typedef enum _NATIVE_PEB_OFFSET
{
	NpoCurrentDirectory,
	NpoDllPath,
	NpoImagePathName,
	NpoCommandLine,
	NpoWindowTitle,
	NpoDesktopInfo,
	NpoShellInfo,
	NpoRuntimeData,
	NpoTypeMask = 0xffff,

	NpoWow64 = 0x10000
} NATIVE_PEB_OFFSET;

NTSTATUS __stdcall native_last_status(void);
NTSTATUS __stdcall native_create_file_win32(PHANDLE pFileHandle, PWSTR fileName, ACCESS_MASK desiredAccess, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PULONG createStatus);
NTSTATUS __stdcall native_delete_file_win32(PWSTR fileName);
NTSTATUS __stdcall native_enum_directory_file(HANDLE fileHandle, PUNICODE_STRING SearchPattern, FnEnumDirectoryFile fnCallback, PVOID Context);
NTSTATUS __stdcall native_open_process(PHANDLE processHandle, ACCESS_MASK desiredAccess, HANDLE processId);
NTSTATUS __stdcall native_get_process_path_by_id(HANDLE processId, wchar_t** filePath);
NTSTATUS __stdcall native_get_process_path(HANDLE hProcess, wchar_t** filePath);
NTSTATUS __stdcall native_query_token_variable_size(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS tokenInformationClass, PVOID* pBuffer);
NTSTATUS __stdcall native_enum_processes(pvoid_t* pProcesses, SYSTEM_INFORMATION_CLASS sic);
int __stdcall native_zms_to_unicode(const wchar_t* str, PUNICODE_STRING uStr);
NTSTATUS __stdcall native_initialize_key_object_attributes(HANDLE rootDirectory, PUNICODE_STRING objectName, ULONG attributes, POBJECT_ATTRIBUTES objectAttributes, PHANDLE needsClose);
NTSTATUS __stdcall native_create_key(PHANDLE pKeyHandle, ACCESS_MASK desiredAccess, HANDLE rootDirectory, wchar_t* objectName, ULONG attributes, ULONG createOptions, PULONG disposition);
NTSTATUS __stdcall native_open_key(PHANDLE pKeyHandle, ACCESS_MASK desiredAccess, HANDLE rootDirectory, const wchar_t* objectName, ULONG attributes);

PKEY_VALUE_PARTIAL_INFORMATION __stdcall native_query_registry_value(HANDLE keyHandle, const wchar_t* valueName);
wchar_t* __stdcall native_query_registry_string(HANDLE keyHandle, const wchar_t* valueName);
wchar_t* __stdcall native_complete_query_registry_string(HKEY hRoot, ACCESS_MASK desiredAccess, const wchar_t* regPath, const wchar_t* regKey);

NTSTATUS __stdcall native_enumerate_key(HANDLE keyHandle, KEY_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo);
NTSTATUS __stdcall native_enumerate_key_value(HANDLE keyHandle, KEY_VALUE_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo);

NTSTATUS __stdcall native_query_file_attributes(const wchar_t* fileName, PFILE_NETWORK_OPEN_INFORMATION FileInformation);
NTSTATUS __stdcall native_set_file_attributes(const wchar_t* fileName, PFILE_BASIC_INFORMATION pFBI);

NTSTATUS __stdcall native_get_process_peb32(HANDLE processHandle, PVOID* pPeb32);
NTSTATUS __stdcall native_query_process_variable_size(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID* pBuffer);
NTSTATUS __stdcall native_get_process_peb_string(HANDLE processHandle, NATIVE_PEB_OFFSET pebOffset, wchar_t** pString);
NTSTATUS __stdcall native_get_process_command_line(HANDLE processHandle, wchar_t** pCommandLine);

#endif // __COMMON_NATIVE_H_
