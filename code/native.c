#include "zmodule.h"
#include "native.h"
#include "memory.h"
#include "string.h"

NTSTATUS __stdcall native_last_status(void)
{
	return (NTSTATUS)fn_NtCurrentTeb()->LastErrorValue;
}

NTSTATUS __stdcall native_create_file_win32(PHANDLE pFileHandle, PWSTR fileName, ACCESS_MASK desiredAccess, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PULONG createStatus)
{
	NTSTATUS ntStatus;
	HANDLE fileHandle;
	UNICODE_STRING uFileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK isb;

	if (!fileAttributes) {
		fileAttributes = FILE_ATTRIBUTE_NORMAL;
	}

	if (!fn_RtlDosPathNameToNtPathName_U(fileName, &uFileName, NULL, NULL)) {
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	InitializeObjectAttributes(&oa, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = fn_NtCreateFile(&fileHandle, desiredAccess, &oa, &isb, NULL, fileAttributes, shareAccess, createDisposition, createOptions, NULL, 0);
	
	memory_free(uFileName.Buffer);

	if (NT_SUCCESS(ntStatus)) {
		*pFileHandle = fileHandle;
	}

	if (createStatus) {
		*createStatus = (ULONG)isb.Information;
	}

	return ntStatus;
}

NTSTATUS __stdcall native_delete_file_win32(PWSTR fileName)
{
	NTSTATUS ntStatus;
	HANDLE fileHandle;

	ntStatus = native_create_file_win32(&fileHandle, fileName, DELETE, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_DELETE_ON_CLOSE, NULL);

	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	fn_NtClose(fileHandle);

	return ntStatus;
}

typedef BOOLEAN(__stdcall *FnEnumDirectoryFile)(PFILE_DIRECTORY_INFORMATION Information, PVOID Context);

NTSTATUS __stdcall native_enum_directory_file(HANDLE fileHandle, PUNICODE_STRING SearchPattern, FnEnumDirectoryFile fnCallback, PVOID Context)
{
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK isb;
	BOOLEAN firstTime = TRUE;
	PVOID buffer;
	ULONG bufferSize = 0x400;
	ULONG i;
	BOOLEAN cont;

	buffer = memory_alloc(bufferSize);

	while (TRUE) {
		// Query the directory, doubling the buffer each time NtQueryDirectoryFile fails.
		while (TRUE) {
			ntStatus = fn_NtQueryDirectoryFile(fileHandle, NULL, NULL, NULL, &isb, buffer, bufferSize, FileDirectoryInformation, FALSE, SearchPattern, firstTime);

			// Our ISB is on the stack, so we have to wait for the operation to complete before continuing.
			if (ntStatus == STATUS_PENDING) {
				ntStatus = fn_NtWaitForSingleObject(fileHandle, FALSE, NULL);

				if (NT_SUCCESS(ntStatus)) {
					ntStatus = isb.Status;
				}
			}

			if (ntStatus == STATUS_BUFFER_OVERFLOW || ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
				memory_free(buffer);
				bufferSize *= 2;
				buffer = memory_alloc(bufferSize);
			}
			else {
				break;
			}
		}

		// If we don't have any entries to read, exit.
		if (ntStatus == STATUS_NO_MORE_FILES) {
			ntStatus = STATUS_SUCCESS;
			break;
		}

		if (!NT_SUCCESS(ntStatus)) {
			break;
		}

		// Read the batch and execute the callback function
		// for each file.

		i = 0;
		cont = TRUE;

		while (TRUE) {
			PFILE_DIRECTORY_INFORMATION information;

			information = (PFILE_DIRECTORY_INFORMATION)(PTR_ADD_OFFSET(buffer, i));

			if (!fnCallback(information, Context)) {
				cont = FALSE;
				break;
			}

			if (information->NextEntryOffset != 0) {
				i += information->NextEntryOffset;
			}
			else {
				break;
			}
		}

		if (!cont) {
			break;
		}

		firstTime = FALSE;
	}
	memory_free(buffer);
	return ntStatus;
}

NTSTATUS __stdcall native_open_process(PHANDLE processHandle, ACCESS_MASK desiredAccess, HANDLE processId)
{
	OBJECT_ATTRIBUTES objectAttributes;
	CLIENT_ID clientId;

	clientId.UniqueProcess = processId;
	clientId.UniqueThread = NULL;

	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
	return fn_ZwOpenProcess(processHandle, desiredAccess, &objectAttributes, &clientId);
}

NTSTATUS __stdcall native_query_token_variable_size(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS tokenInformationClass, PVOID* pBuffer)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG returnLength = 0;

	fn_NtQueryInformationToken(tokenHandle, tokenInformationClass, 0, 0, &returnLength);
	buffer = memory_alloc(returnLength);
	ntStatus = fn_NtQueryInformationToken(tokenHandle, tokenInformationClass, buffer, returnLength, &returnLength);

	if (NT_SUCCESS(ntStatus)) {
		*pBuffer = buffer;
	}
	else {
		memory_free(buffer);
	}

	return ntStatus;
}

NTSTATUS __stdcall native_get_process_path_by_id(HANDLE processId, wchar_t** filePath)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG bufferSize = 0x100;
	SYSTEM_PROCESS_ID_INFORMATION processIdInfo;

	buffer = memory_alloc(bufferSize);

	processIdInfo.ProcessId = processId;
	processIdInfo.ImageName.Length = 0;
	processIdInfo.ImageName.MaximumLength = (USHORT)bufferSize;
	processIdInfo.ImageName.Buffer = (PWSTR)buffer;

	ntStatus = fn_NtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(SYSTEM_PROCESS_ID_INFORMATION), 0);

	if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
		memory_free(buffer);
		buffer = memory_alloc(processIdInfo.ImageName.MaximumLength);
		processIdInfo.ImageName.Buffer = (PWSTR)buffer;

		ntStatus = fn_NtQuerySystemInformation(SystemProcessIdInformation, &processIdInfo, sizeof(SYSTEM_PROCESS_ID_INFORMATION), 0);
	}

	if (!NT_SUCCESS(ntStatus)) {
		memory_free(buffer);
		return ntStatus;
	}
	
	*filePath = zs_new(processIdInfo.ImageName.Buffer);
	memory_free(buffer);

	return ntStatus;
}

NTSTATUS __stdcall native_get_process_path(HANDLE hProcess, wchar_t** filePath)
{
	NTSTATUS ntStatus;
	PUNICODE_STRING uFileName;

	ntStatus = native_query_token_variable_size(hProcess, ProcessImageFileName, (PVOID*)&uFileName);

	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	*filePath = zs_new(uFileName->Buffer);
	memory_free(uFileName);

	return ntStatus;
}

NTSTATUS __stdcall native_enum_processes(pvoid_t* pProcesses, SYSTEM_INFORMATION_CLASS sic)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG bufferSize;
	
	switch (sic) {
		case SystemProcessInformation:
		case SystemExtendedProcessInformation:
		case SystemFullProcessInformation:
			break;
		default:
			return STATUS_INVALID_INFO_CLASS;
	}

	bufferSize = 0x4000;
	buffer = memory_alloc(bufferSize);

	while (TRUE) {
		ntStatus = fn_NtQuerySystemInformation(sic, buffer, bufferSize, &bufferSize);

		if (ntStatus == STATUS_BUFFER_TOO_SMALL || ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
			memory_free(buffer);
			buffer = memory_alloc(bufferSize);
		}
		else {
			break;
		}
	}

	if (!NT_SUCCESS(ntStatus)) {
		memory_free(buffer);
		return ntStatus;
	}

	*pProcesses = buffer;
	return ntStatus;
}

int __stdcall native_zms_to_unicode(const wchar_t* str, PUNICODE_STRING uStr)
{
	USHORT len = (USHORT)(zs_length(str) * sizeof(wchar_t));
	uStr->Length = len;
	uStr->MaximumLength = len + 2;
	uStr->Buffer = (PWSTR)str;

	return len <= UNICODE_STRING_MAX_BYTES;
}

NTSTATUS __stdcall native_initialize_key_object_attributes(HANDLE rootDirectory, PUNICODE_STRING objectName, ULONG attributes, POBJECT_ATTRIBUTES objectAttributes, PHANDLE needsClose)
{
	NTSTATUS ntStatus;
	ULONG predefineIndex;
	HANDLE predefineHandle;
	OBJECT_ATTRIBUTES predefineObjectAttributes;

	InitializeObjectAttributes(objectAttributes, objectName, attributes | OBJ_CASE_INSENSITIVE, rootDirectory, 0);

	*needsClose = NULL;

	if (rootDirectory && NATIVE_KEY_IS_PREDEFINED(rootDirectory)) {
		predefineIndex = NATIVE_KEY_PREDEFINE_TO_NUMBER(rootDirectory);

		if (predefineIndex < NATIVE_KEY_MAXIMUM_PREDEFINE) {
			predefineHandle = _pZmoduleBlock->predefineKeyHandles[predefineIndex];

			if (!predefineHandle) {
				// The predefined key has not been opened yet. Do so now.
				if (!_pZmoduleBlock->predefineKeyNames[predefineIndex].Buffer) { // we may have failed in getting the current user key name
					return STATUS_UNSUCCESSFUL;
				}

				InitializeObjectAttributes(&predefineObjectAttributes, &_pZmoduleBlock->predefineKeyNames[predefineIndex], OBJ_CASE_INSENSITIVE, 0, 0);

				ntStatus = fn_NtOpenKey(&predefineHandle, KEY_READ, &predefineObjectAttributes);

				if (!NT_SUCCESS(ntStatus)) {
					return ntStatus;
				}

				if (_InterlockedCompareExchangePointer(&_pZmoduleBlock->predefineKeyHandles[predefineIndex], predefineHandle, 0) != 0) {
					// Someone else already opened the key and cached it. Indicate that
					// the caller needs to close the handle later, since it isn't shared.
					*needsClose = predefineHandle;
				}
			}

			objectAttributes->RootDirectory = predefineHandle;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS __stdcall native_create_key(PHANDLE pKeyHandle, ACCESS_MASK desiredAccess, HANDLE rootDirectory, wchar_t* objectName, ULONG attributes, ULONG createOptions, PULONG disposition)
{
	NTSTATUS ntStatus;
	UNICODE_STRING uObjectName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE needsClose;

	if (!native_zms_to_unicode(objectName, &uObjectName)) {
		return STATUS_NAME_TOO_LONG;
	}

	if (!NT_SUCCESS(ntStatus = native_initialize_key_object_attributes(rootDirectory, &uObjectName, attributes, &objectAttributes, &needsClose))) {
		return ntStatus;
	}

	ntStatus = fn_NtCreateKey(pKeyHandle, desiredAccess, &objectAttributes, 0, NULL, createOptions, disposition);

	if (needsClose) {
		fn_NtClose(needsClose);
	}

	return ntStatus;
}


NTSTATUS __stdcall native_open_key(PHANDLE pKeyHandle, ACCESS_MASK desiredAccess, HANDLE rootDirectory, const wchar_t* objectName, ULONG attributes)
{
	NTSTATUS ntStatus;
	UNICODE_STRING uObjectName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE needsClose;

	if (!native_zms_to_unicode(objectName, &uObjectName)) {
		return STATUS_NAME_TOO_LONG;
	}

	if (!NT_SUCCESS(ntStatus = native_initialize_key_object_attributes(rootDirectory, &uObjectName, attributes, &objectAttributes, &needsClose))) {
		return ntStatus;
	}

	ntStatus = fn_NtOpenKey(pKeyHandle, desiredAccess, &objectAttributes);

	if (needsClose) {
		fn_NtClose(needsClose);
	}

	return ntStatus;
}

PKEY_VALUE_PARTIAL_INFORMATION __stdcall native_query_registry_value(HANDLE keyHandle, const wchar_t* valueName)
{
	NTSTATUS ntStatus;
	UNICODE_STRING uValueName;
	PKEY_VALUE_PARTIAL_INFORMATION buffer;
	ULONG bufferSize;
	ULONG attempts = 16;

	native_zms_to_unicode(valueName, &uValueName);

	bufferSize = 0x100;
	buffer = (PKEY_VALUE_PARTIAL_INFORMATION)memory_alloc(bufferSize);

	do {
		ntStatus = fn_NtQueryValueKey(keyHandle, &uValueName, KeyValuePartialInformation, buffer, bufferSize, &bufferSize);

		if (NT_SUCCESS(ntStatus)) {
			break;
		}

		if (ntStatus == STATUS_BUFFER_OVERFLOW) {
			memory_free(buffer);
			buffer = (PKEY_VALUE_PARTIAL_INFORMATION)memory_alloc(bufferSize);
		}
		else {
			memory_free(buffer);
			return 0;
		}
	} while (--attempts);

	return buffer;
}

wchar_t* __stdcall native_query_registry_string(HANDLE keyHandle, const wchar_t* valueName)
{
	wchar_t* string = NULL;
	PKEY_VALUE_PARTIAL_INFORMATION buffer;

	buffer = native_query_registry_value(keyHandle, valueName);

	if (buffer != NULL) {
		if (buffer->Type == REG_SZ || buffer->Type == REG_MULTI_SZ || buffer->Type == REG_EXPAND_SZ) {
			if (buffer->DataLength >= sizeof(wchar_t)) {
				string = zs_new((wchar_t*)buffer->Data);
			}
		}
		memory_free(buffer);
	}

	return string;
}

wchar_t* __stdcall native_complete_query_registry_string(HKEY hRoot, ACCESS_MASK desiredAccess, const wchar_t* regPath, const wchar_t* regKey)
{
	HANDLE hKey;
	NTSTATUS ntStatus;
	wchar_t* wcsRegPath = zs_new(regPath);
	wchar_t* wcsKey = zs_new(regKey);
	wchar_t* wcsValue = NULL;

	ntStatus = native_open_key(&hKey, desiredAccess, hRoot, wcsRegPath, 0);
	if (NT_SUCCESS(ntStatus)) {
		wcsValue = native_query_registry_string(hKey, wcsKey);
	}

	zs_free(wcsRegPath);
	zs_free(wcsKey);
	fn_NtClose(hKey);

	return wcsValue;
}

NTSTATUS __stdcall native_enumerate_key(HANDLE keyHandle, KEY_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG bufferSize;

	bufferSize = 0x100;
	buffer = memory_alloc(bufferSize);

	while (1) {
		ntStatus = fn_NtEnumerateKey(keyHandle, index, kvic, buffer, bufferSize, &bufferSize);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL && ntStatus != STATUS_BUFFER_OVERFLOW) {
			break;
		}
		memory_free(buffer);
		buffer = memory_alloc(bufferSize);
	}

	if (!NT_SUCCESS(ntStatus)) {
		memory_free(buffer);
		return ntStatus;
	}

	*pInfo = buffer;

	return ntStatus;
}

NTSTATUS __stdcall native_enumerate_key_value(HANDLE keyHandle, KEY_VALUE_INFORMATION_CLASS kvic, ULONG index, PVOID* pInfo)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG bufferSize;

	bufferSize = 0x100;
	buffer = memory_alloc(bufferSize);

	while (1) {
		ntStatus = fn_ZwEnumerateValueKey(keyHandle, index, kvic, buffer, bufferSize, &bufferSize);
		if (ntStatus != STATUS_BUFFER_TOO_SMALL && ntStatus != STATUS_BUFFER_OVERFLOW) {
			break;
		}
		memory_free(buffer);
		buffer = memory_alloc(bufferSize);
	}

	if (!NT_SUCCESS(ntStatus)) {
		memory_free(buffer);
		return ntStatus;
	}

	*pInfo = buffer;

	return ntStatus;
}

wchar_t* __stdcall native_convert_to_win32_path(wchar_t* filePath)
{
	wchar_t* newFileName;

	// "\??\" refers to \GLOBAL??\. Just remove it.
	if (fn_StrCmpNIW(filePath, L"\\??\\", 4) == 0) {
		newFileName = zs_new(filePath + 4);
	}
	// "\SystemRoot" means "C:\Windows".
	else if (fn_StrCmpNIW(filePath, L"\\SystemRoot", 11) == 0) {
		newFileName = zs_new(_pZmoduleBlock->systemRoot);
		zs_cat(newFileName, filePath + 11);
	}
	else if (zs_length(filePath) != 0 && filePath[0] == L'\\') {
		/*
		zgui::String resolvedName;

		resolvedName = convertNativePathThWin32Path(fileName);

		if (!resolvedName.isEmpty()) {
			newFileName = resolvedName;
		}
		else {
			// We didn't find a match.
			// If the file name starts with "\Windows", prepend the system drive.
			if (newFileName.startsWithIgnoreCase("\\Windows")) {
				newFileName << USER_SHARED_DATA->NtSystemRoot[0] << ':' << fileName;
			}
		}
		*/
	}

	return newFileName;
}

NTSTATUS __stdcall native_query_file_attributes(const wchar_t* fileName, PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
	NTSTATUS ntStatus;
	UNICODE_STRING uFileName;
	OBJECT_ATTRIBUTES oa;

	if (!fn_RtlDosPathNameToNtPathName_U(fileName, &uFileName, NULL, NULL)) {
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	InitializeObjectAttributes(&oa, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = fn_NtQueryFullAttributesFile(&oa, FileInformation);
	memory_free(uFileName.Buffer);

	return ntStatus;
}

NTSTATUS __stdcall native_set_file_attributes(const wchar_t* fileName, PFILE_BASIC_INFORMATION pFBI)
{
	NTSTATUS ntStatus;
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatusBlock;

	ntStatus = native_create_file_win32(&hFile, fileName, FILE_GENERIC_WRITE, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL);
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = fn_NtSetInformationFile(hFile, &ioStatusBlock, pFBI, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
		fn_NtClose(hFile);
	}

	return ntStatus;
}

NTSTATUS __stdcall native_get_process_peb32(HANDLE processHandle, PVOID* pPeb32)
{
	NTSTATUS ntStatus;
	ULONG_PTR wow64;

	ntStatus = fn_NtQueryInformationProcess(processHandle, ProcessWow64Information, &wow64, sizeof(ULONG_PTR), NULL);

	if (NT_SUCCESS(ntStatus)) {
		*pPeb32 = (PVOID)wow64;
	}

	return ntStatus;
}

NTSTATUS __stdcall native_query_process_variable_size(HANDLE processHandle, PROCESSINFOCLASS processInformationClass, PVOID* pBuffer)
{
	NTSTATUS ntStatus;
	PVOID buffer;
	ULONG returnLength = 0;

	fn_NtQueryInformationProcess(processHandle, processInformationClass, NULL, 0, &returnLength);
	buffer = memory_alloc(returnLength);
	ntStatus = fn_NtQueryInformationProcess(processHandle, processInformationClass, buffer, returnLength, &returnLength);

	if (NT_SUCCESS(ntStatus)) {
		*pBuffer = buffer;
	}
	else {
		memory_free(buffer);
	}

	return ntStatus;
}

NTSTATUS __stdcall native_get_process_peb_string(HANDLE processHandle, NATIVE_PEB_OFFSET pebOffset, wchar_t** pString)
{
	NTSTATUS ntStatus;
	wchar_t* string;
	ULONG offset;

#define PEB_OFFSET_CASE(Enum, Field) \
    case Enum: offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, Field); break; \
    case Enum | NpoWow64: offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, Field); break

	switch (pebOffset) {
		PEB_OFFSET_CASE(NpoCurrentDirectory, CurrentDirectory);
		PEB_OFFSET_CASE(NpoDllPath, DllPath);
		PEB_OFFSET_CASE(NpoImagePathName, ImagePathName);
		PEB_OFFSET_CASE(NpoCommandLine, CommandLine);
		PEB_OFFSET_CASE(NpoWindowTitle, WindowTitle);
		PEB_OFFSET_CASE(NpoDesktopInfo, DesktopInfo);
		PEB_OFFSET_CASE(NpoShellInfo, ShellInfo);
		PEB_OFFSET_CASE(NpoRuntimeData, RuntimeData);
	default:
		return STATUS_INVALID_PARAMETER_2;
	}

	if (!(pebOffset & NpoWow64)) {
		PROCESS_BASIC_INFORMATION basicInfo;
		PVOID processParameters;
		UNICODE_STRING unicodeString;

		// Get the PEB address.
		if (!NT_SUCCESS(ntStatus = fn_NtQueryInformationProcess(processHandle, ProcessBasicInformation, &basicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL))) {
			return ntStatus;
		}

		// Read the address of the process parameters.
		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, PTR_ADD_OFFSET(basicInfo.PebBaseAddress, FIELD_OFFSET(PEB, ProcessParameters)), &processParameters, sizeof(PVOID), NULL))) {
			return ntStatus;
		}

		// Read the string structure.
		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, PTR_ADD_OFFSET(processParameters, offset), &unicodeString, sizeof(UNICODE_STRING), NULL))) {
			return ntStatus;
		}

		string = zs_new_with_len(NULL, unicodeString.Length >> 1);
		
		// Read the string contents.
		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, unicodeString.Buffer, string, zs_length(string) << 1, NULL))) {
			zs_free(string);
			return ntStatus;
		}
	}
	else {
		PVOID peb32;
		ULONG processParameters32;
		UNICODE_STRING32 unicodeString32;

		if (!NT_SUCCESS(ntStatus = native_get_process_peb32(processHandle, &peb32))) {
			return ntStatus;
		}

		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, PTR_ADD_OFFSET(peb32, FIELD_OFFSET(PEB32, ProcessParameters)), &processParameters32, sizeof(ULONG), NULL))) {
			return ntStatus;
		}

		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, PTR_ADD_OFFSET(processParameters32, offset), &unicodeString32, sizeof(UNICODE_STRING32), NULL))) {
			return ntStatus;
		}

		string = zs_new_with_len(NULL, unicodeString32.Length >> 1);

		// Read the string contents.
		if (!NT_SUCCESS(ntStatus = fn_NtReadVirtualMemory(processHandle, UlongToPtr(unicodeString32.Buffer), string, zs_length(string) << 1, NULL))) {
			zs_free(string);
			return ntStatus;
		}
	}

	*pString = string;

	return ntStatus;
}


NTSTATUS __stdcall native_get_process_command_line(HANDLE processHandle, wchar_t** pCommandLine)
{
	NTSTATUS ntStatus;
	/*
	if (_pZmoduleBlock->sysInfo.osMajorVer == 6 && _pZmoduleBlock->sysInfo.osMinorVer == 3) {
		PUNICODE_STRING uCommandLine;

		ntStatus = native_query_process_variable_size(processHandle, ProcessCommandLineInformation, &uCommandLine);

		if (NT_SUCCESS(ntStatus)) {
			*pCommandLine = zs_new(uCommandLine->Buffer);
			memory_free(uCommandLine);

			return ntStatus;
		}
	}
	*/
	return native_get_process_peb_string(processHandle, NpoCommandLine, pCommandLine);
}
