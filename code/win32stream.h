#ifndef __COMMON_STREAM_H_
#define __COMMON_STREAM_H_

typedef struct _stream_data
{
    HGLOBAL hGlobal;
    void* buffer;
    uint32_t streamSize;
} stream_data_t;

HRESULT __stdcall stream_create(LPSTREAM* ppstm);
void __stdcall stream_clear(LPSTREAM pStream);
void __stdcall stream_free(LPSTREAM pStream);
int __stdcall stream_read(LPSTREAM pStream, void* lpData, DWORD dwLen);
void __stdcall stream_safe_read_stream(LPSTREAM pStream, void* lpData, DWORD dwLen, int* lpStatusCode);
int __stdcall stream_write(LPSTREAM pStream, const void* pData, DWORD sz);
int __stdcall stream_write_dword(LPSTREAM pStream, uint32_t val);
int __stdcall stream_write_qword(LPSTREAM pStream, uint64_t val);
int __stdcall stream_write_string(LPSTREAM pStream, const char* szString);
int __stdcall stream_write_zeros(LPSTREAM pStream, uint32_t num);
//DWORD stream_write_module_header(LPSTREAM pStream, uint16_t moduleId, uint16_t moduleVer);
int __stdcall stream_write_crc64(LPSTREAM pStream);
int __stdcall stream_check_crc64(LPSTREAM pStream);
int __stdcall stream_read_check(LPSTREAM pStream, DWORD dwLen);
int stream_write_binary_string(LPSTREAM pStream, const void* str, DWORD len);
int stream_write_utf8_string(LPSTREAM pStream, const wchar_t* utf16Str);
HRESULT stream_seek_offset(LPSTREAM pStream, int pos, DWORD origin);
DWORD stream_update_module_length(LPSTREAM pStream, DWORD moduleOffset);
int stream_read_from_file(const wchar_t* filename, LPSTREAM pStream);
uint8_t stream_safe_read_byte(LPSTREAM pStream, int* lpStatusCode);
WORD stream_safe_read_word(LPSTREAM pStream, int* lpStatusCode);
uint32_t __stdcall stream_safe_read_dword(LPSTREAM pStream, int bigEndian, int* lpStatusCode);
uint64_t __stdcall stream_safe_read_qword(LPSTREAM pStream, int bigEndian, int* lpStatusCode);
void stream_safe_read_skip(LPSTREAM pStream, DWORD dwSize, int* lpStatusCode);
DWORD stream_get_pos(LPSTREAM pStream);
HRESULT stream_set_size(LPSTREAM pStream, DWORD newSize);
DWORD stream_get_length(LPSTREAM pStream);
HRESULT stream_goto_end(LPSTREAM pStream);
HRESULT stream_goto_begin(LPSTREAM pStream);
int stream_check_status(LPSTREAM stream);
int stream_save_to_file(LPSTREAM pStream, async_fs_t* pAsyncFile);
void __stdcall stream_arc4(LPSTREAM pStream, uint8_t* key, uint32_t keyLen);
stream_data_t* __stdcall stream_lock(LPSTREAM pStream);
void __stdcall stream_unlock(stream_data_t* pStreamData);

#endif // __COMMON_STREAM_H_
