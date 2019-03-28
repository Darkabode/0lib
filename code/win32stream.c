#include "zmodule.h"

//const uint8_t gModuleHdr[8] = {2,0,'M','O','D','U',1,1};
//
//
HRESULT __stdcall stream_create(LPSTREAM* ppStream)
{
    int counter;
    HRESULT hRes;

    for (counter = 0; counter < 7; ++counter) {
        hRes = fn_CreateStreamOnHGlobal(NULL, TRUE, ppStream);
        if (SUCCEEDED(hRes) && *ppStream != NULL) {
            break;
        }
        fn_Sleep(3000);
    }
    return hRes;
}

void __stdcall stream_clear(LPSTREAM pStream)
{
	stream_seek_offset(pStream, 0, STREAM_SEEK_SET);
	stream_set_size(pStream, 0);
}

void __stdcall stream_free(LPSTREAM pStream)
{
	if (pStream != NULL) {
		pStream->lpVtbl->Release(pStream);
	}
}

int __stdcall stream_write(LPSTREAM pStream, const void* pData, DWORD sz)
{
    DWORD written;
    uint8_t* ptr = (uint8_t*)pData;
    if (pStream == NULL || pData == NULL) {
        return 0;
    }

    while (sz != 0) {
        if (!SUCCEEDED(pStream->lpVtbl->Write(pStream, ptr, sz, &written)) || written == 0) {
            return 0;
        }

        sz -= written;
        ptr += written;
    }

    return 1;
}

int __stdcall stream_write_dword(LPSTREAM pStream, uint32_t val)
{
    return stream_write(pStream, (uint8_t*)&val, sizeof(uint32_t));
}

int __stdcall stream_write_qword(LPSTREAM pStream, uint64_t val)
{
    return stream_write(pStream, (uint8_t*)&val, sizeof(uint64_t));
}

int __stdcall stream_write_string(LPSTREAM pStream, const char* szString)
{
    int len = 0;
    if (szString != NULL) {
        len = fn_lstrlenA(szString);
    }

    return stream_write_binary_string(pStream, szString, len);
}

int __stdcall stream_write_zeros(LPSTREAM pStream, uint32_t num)
{
    int ret;
    uint8_t* zeroBuff = memory_alloc(num);
    ret = stream_write(pStream, zeroBuff, num);
    memory_free(zeroBuff);
    return ret;
}

int __stdcall stream_write_crc64(LPSTREAM pStream)
{
    DWORD len;
    HGLOBAL hGlobal;
    void* pMem;
    uint64_t crc = 0;

    if (SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        len = stream_get_length(pStream);
        pMem = fn_GlobalLock(hGlobal);
        if (pMem != NULL) {
            crc = crc64(0, pMem, len);
            fn_GlobalUnlock(hGlobal);
        }
    }
    stream_goto_end(pStream);

    return stream_write_qword(pStream, crc);
}

int __stdcall stream_read_check(LPSTREAM pStream, DWORD dwLen)
{
    uint32_t len;
    LARGE_INTEGER qPos;
    ULARGE_INTEGER endPos;

    qPos.LowPart = 0;
    qPos.HighPart = 0;
    pStream->lpVtbl->Seek(pStream, qPos, STREAM_SEEK_CUR, &endPos);
    len = stream_get_length(pStream);
    qPos.QuadPart = (LONGLONG)endPos.QuadPart;
    pStream->lpVtbl->Seek(pStream, qPos, STREAM_SEEK_SET, NULL);
    if (endPos.LowPart + dwLen > len) {
        return 0;
    }

    return 1;
}

int __stdcall stream_read(LPSTREAM pStream, void* lpData, DWORD dwLen)
{
    DWORD dwReadBytes;
    if (!stream_read_check(pStream, dwLen)) {
        return 0;
    }

    if (SUCCEEDED(pStream->lpVtbl->Read(pStream, lpData, dwLen, &dwReadBytes))) {
        if (dwLen == dwReadBytes) {
            return 1;
        }
    }

    return 0;
}

void __stdcall stream_safe_read_stream(LPSTREAM pStream, void* lpData, DWORD dwLen, int* lpStatusCode)
{
    // check current stream status
    if (*lpStatusCode == 0) {
        return;
    }

    // update stream status
    *lpStatusCode &= stream_read(pStream, lpData, dwLen);    
}

//uint8_t stream_safe_read_byte(LPSTREAM pStream, int* lpStatusCode)
//{
//    uint8_t bData = 0;
//    stream_safe_read_stream(pStream, &bData, 1, lpStatusCode);
//    return bData;
//}
//
//WORD stream_safe_read_word(LPSTREAM pStream, int* lpStatusCode)
//{
//    WORD wData = 0;
//    stream_safe_read_stream(pStream, &wData, sizeof(wData), lpStatusCode);
//    if (*lpStatusCode) {
//        wData = _byteswap_ushort(wData);
//    }
//
//    return wData;
//}

uint32_t __stdcall stream_safe_read_dword(LPSTREAM pStream, int bigEndian, int* lpStatusCode)
{
    uint32_t dwData = 0;

    stream_safe_read_stream(pStream, &dwData, sizeof(uint32_t), lpStatusCode);
    if (bigEndian && *lpStatusCode) {
        dwData = _byteswap_ulong(dwData);
    }

    return dwData;
}

uint64_t __stdcall stream_safe_read_qword(LPSTREAM pStream, int bigEndian, int* lpStatusCode)
{
    uint64_t qw = 0;

    stream_safe_read_stream(pStream, &qw, sizeof(uint64_t), lpStatusCode);
    if (bigEndian && *lpStatusCode) {
        qw = _byteswap_uint64(qw);
    }

    return qw;
}

//void stream_safe_read_skip(LPSTREAM pStream, DWORD dwSize, int* lpStatusCode)
//{
//    if (*lpStatusCode == 0) {
//        // previous error detected, do not continue
//        return;
//    }
//
//    if (!stream_read_check(pStream, dwSize)) {
//        *lpStatusCode = 0;
//    }
//    else {
//        stream_seek_offset(pStream, dwSize, STREAM_SEEK_CUR);
//    }
//}
//
// Validate obfuscated CRC32 checksum at the end of the stream
int __stdcall stream_check_crc64(LPSTREAM pStream)
{
    HGLOBAL hGlobal;
    DWORD len;
    void* pMem;
    int lpState = 1;
    uint64_t crc;
    uint64_t realCrc = 0;
    HRESULT hRes;

    if (SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        len = stream_get_length(pStream);
        if (len >= sizeof(uint64_t)) {
            pMem = fn_GlobalLock(hGlobal);
            if (pMem != NULL) {
                realCrc = crc64(0, pMem, len - sizeof(uint64_t));
                fn_GlobalUnlock(hGlobal);
            }
        }
        else {
            stream_goto_end(pStream);
            return 0;
        }
    }
    else {
        return 0;
    }

    hRes = stream_seek_offset(pStream, -sizeof(uint64_t), STREAM_SEEK_END);
    crc = stream_safe_read_qword(pStream, 0, &lpState);
    if (lpState) {
        if (crc == realCrc) {
            return 1;
        }
    }
    return 0;
}

DWORD stream_get_length(LPSTREAM pStream)
{
    LARGE_INTEGER pos;
    ULARGE_INTEGER sz;
    pos.QuadPart = 0ULL;
    sz.QuadPart = 0ULL;

    pStream->lpVtbl->Seek(pStream, pos, STREAM_SEEK_END, &sz);

    return sz.LowPart;
}

HRESULT stream_set_size(LPSTREAM pStream, DWORD newSize)
{
    ULARGE_INTEGER sz;
    sz.HighPart = 0;
    sz.LowPart = newSize;
    return pStream->lpVtbl->SetSize(pStream, sz);
}

DWORD stream_get_pos(LPSTREAM pStream)
{
    LARGE_INTEGER beginPos;
    ULARGE_INTEGER curPos;
    beginPos.QuadPart = 0ULL;

    pStream->lpVtbl->Seek(pStream, beginPos, STREAM_SEEK_CUR, &curPos);
    return curPos.LowPart;
}

///*
//// HEADER(8 bytes) | MODULE-SIZE DWORD | ID WORD | VERSION WORD
//// return header start offset
//DWORD stream_write_module_header(LPSTREAM pStream, uint16_t moduleId, uint16_t moduleVer)
//{
//    DWORD curPos = stream_get_pos(pStream);
//    stream_write(pStream, gModuleHdr, sizeof(gModuleHdr));
//    stream_write_dword(pStream, 0); // reserved for module size
//    stream_write(pStream, &moduleId, 2);
//    stream_write(pStream, &moduleVer, 2);
//
//    return curPos;
//}
//*/
int stream_write_binary_string(LPSTREAM pStream, const void* str, DWORD len)
{
    int ret = stream_write_dword(pStream, len);
    if (len > 0 && str != NULL) {
        ret = stream_write(pStream, str, len);
    }
    return ret;
}

//int stream_write_utf8_string(LPSTREAM pStream, const wchar_t* utf16Str)
//{
//    char* utf8String;
//    int utf16Size = fn_lstrlenW(utf16Str);
//#if (WINVER >= 0x0600)
//    DWORD dwConversionFlags = WC_ERR_INVALID_CHARS;
//#else
//    DWORD dwConversionFlags = 0;
//#endif
//    int utf8Size = fn_WideCharToMultiByte(CP_UTF8, dwConversionFlags, utf16Str, utf16Size, NULL, 0, NULL, NULL);
//    int res;
//
//    if (utf8Size != 0) {
//        utf8String = fn_memalloc(utf8Size);
//        if (utf8String != NULL) {
//            res = fn_WideCharToMultiByte(CP_UTF8, dwConversionFlags, utf16Str, utf16Size, utf8String, utf8Size, NULL, NULL);
//            if (res != 0) {
//                stream_write(pStream, utf8String, utf8Size);
//            }
//            fn_memfree(utf8String);
//        }
//    }
//
//    return utf8Size;
//}
//
HRESULT stream_seek_offset(LPSTREAM pStream, int pos, DWORD origin)
{
    LARGE_INTEGER qPos;
    qPos.QuadPart = (LONGLONG)pos;
    //     qPos.LowPart = pos;
    //     qPos.HighPart = 0;
    return pStream->lpVtbl->Seek(pStream, qPos, origin, NULL);
}

// Seek stream end
HRESULT stream_goto_end(LPSTREAM pStream)
{
    return stream_seek_offset(pStream, 0, STREAM_SEEK_END);
}

// Seek stream begin (offset=0)
HRESULT stream_goto_begin(LPSTREAM pStream)
{
    return stream_seek_offset(pStream, 0, STREAM_SEEK_SET);
}

//DWORD stream_update_module_length(LPSTREAM pStream, DWORD moduleOffset)
//{
//    DWORD len = stream_get_length(pStream) - moduleOffset;
//    moduleOffset += sizeof(gModuleHdr);
//    stream_seek_offset(pStream, moduleOffset, STREAM_SEEK_SET);
//    stream_write_dword(pStream, len);
//    stream_goto_end(pStream);
//
//    return len;
//}
//

int stream_save_to_file(LPSTREAM pStream, async_fs_t* pAsyncFile)
{
    int ret = 0;
    HGLOBAL hGlobal;
    async_buf_t asyncBuf;

    //stream_goto_begin(pStream);
    if (SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        asyncBuf.len = stream_get_length(pStream);
        asyncBuf.base = fn_GlobalLock(hGlobal);
        if (asyncBuf.base != NULL) {
            ret = (async_fs_write(async_default_loop(), pAsyncFile, pAsyncFile->hFile, &asyncBuf, 1, -1, NULL) == (int)asyncBuf.len);
            fn_GlobalUnlock(hGlobal);
        }

    }
    //stream_goto_end(pStream);

    return ret;
}

//int stream_read_from_file(const wchar_t* filename, LPSTREAM pStream)
//{
//    int ret = 0;
//    HANDLE hFile;
//    uint8_t buf[4096];
//    DWORD readed;
//
//    hFile = fn_CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
//    if (hFile == INVALID_HANDLE_VALUE) {
//        return 0;
//    }
//
//    for ( ; ; ) {
//        if (!fn_ReadFile(hFile, buf, sizeof(buf), &readed, NULL)) {
//            break;
//        }
//        if (readed == 0) {
//            ret = 1;
//            break;
//        }
//
//        if (!stream_write(pStream, buf, readed)) {
//            break;
//        }
//    }
//
//    fn_CloseHandle(hFile);
//    return ret;
//}

void __stdcall stream_arc4(LPSTREAM pStream, uint8_t* key, uint32_t keyLen)
{
    HGLOBAL hGlobal;
    DWORD len;
    void* pMem;

    if (pStream != NULL && SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        len = stream_get_length(pStream);
        pMem = fn_GlobalLock(hGlobal);
        if (pMem != NULL) {
            arc4_crypt_self(pMem, len, key, keyLen);
            fn_GlobalUnlock(hGlobal);
        }
    }
}

stream_data_t* __stdcall stream_lock(LPSTREAM pStream)
{
    HGLOBAL hGlobal;
    stream_data_t* pStreamData = NULL;

    if (pStream != NULL && SUCCEEDED(fn_GetHGlobalFromStream(pStream, &hGlobal))) {
        pStreamData  = (stream_data_t*)memory_alloc(sizeof(stream_data_t));
        pStreamData->hGlobal = hGlobal;
        pStreamData->streamSize = stream_get_length(pStream);
        pStreamData->buffer = fn_GlobalLock(hGlobal);
        if (pStreamData->buffer == NULL) {
            fn_GlobalUnlock(hGlobal);
            memory_free(pStreamData);
            pStreamData = NULL;
        }
    }

    return pStreamData;
}

void __stdcall stream_unlock(stream_data_t* pStreamData)
{
    fn_GlobalUnlock(pStreamData->hGlobal);
    memory_free(pStreamData);
}
