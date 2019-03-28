#ifndef __COMMON_UTILS_H_
#define __COMMON_UTILS_H_

uint32_t __stdcall utils_unixtime(int inUTC);

uint32_t __stdcall ror(uint32_t value, int places);
uint32_t __stdcall rol(uint32_t value, int places);

uint32_t __stdcall utils_strhash(const char* str);
uint32_t __stdcall utils_wcshash(const wchar_t* str);
uint32_t __stdcall utils_wcsihash(const wchar_t* str);

DWORD __stdcall utils_create_thread(LPTHREAD_START_ROUTINE pvFunc, PVOID pvParam, PHANDLE phHandle, DWORD dwWaitSec);

void __stdcall utils_crc32_build_table(void);
uint32_t __stdcall utils_crc32_update(uint32_t crc32, const uint8_t* buffer, uint32_t size);

void __stdcall utils_str_random(char* outStr, uint32_t bufferLen);
void __stdcall utils_wcs_random(wchar_t* outStr, uint32_t bufferLen);

char* __stdcall utils_machine_guid(void);
char* __stdcall utils_get_machine_key(void);
void __stdcall utils_update_installed_software();

uint8_t* __stdcall utils_hash(ALG_ID algId, DWORD dwProvType, const uint8_t* data, uint32_t* pSize, int inHex);

int __stdcall utils_isctype(int c, wctype_t type);
int __stdcall utils_isalpha(int c);
int __stdcall utils_isalphanum(int c);
int __stdcall utils_isspace(int c);

BOOL __stdcall utils_file_write(const wchar_t* filePath, DWORD dwFlags, uint8_t* pBuffer, DWORD dwSize);
uint8_t* __stdcall utils_file_read(const wchar_t* lpFile, uint32_t* pdwSize);

ulong_t utils_random();

wchar_t* __stdcall utils_get_known_path(REFKNOWNFOLDERID rfid);

char* __stdcall utils_strdup(const char* str);
wchar_t* __stdcall utils_wcsdup(const wchar_t* str);

int __stdcall utils_utf16_to_utf8(const wchar_t* utf16Buffer, size_t utf16Size, char* utf8Buffer, size_t utf8Size);
int __stdcall utils_utf8_to_utf16(const char* utf8Buffer, wchar_t* utf16Buffer, size_t utf16Size);

wchar_t* __stdcall utils_utf16(const char* utf8Buffer);

#endif // __COMMON_UTILS_H_
