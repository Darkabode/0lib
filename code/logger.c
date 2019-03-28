#include "zmodule.h"
#include "logger.h"

#ifdef LOG_ON

void __cdecl logger_log(const char* dbgFormat, ...)
{
    va_list vaList;
    char formatBuffer[1024];
    char debugMessage[4 * 1024];
    SYSTEMTIME stm;
    char sDateTime[64];
    char sSysDate[32];
    char sSysTime[32];

    fn_GetLocalTime(&stm);
    fn_GetDateFormatA(0x0409, LOCALE_USE_CP_ACP, &stm, "dd-MM-yyyy", sSysDate, sizeof(sSysDate));
    fn_GetTimeFormatA(0x0409, LOCALE_USE_CP_ACP, &stm, "HH':'mm':'ss", sSysTime, sizeof(sSysTime));

    fn_wsprintfA(sDateTime, "%s %s", sSysDate, sSysTime);
	
	fn_wsprintfA(formatBuffer, "%s [%S %u] %s\n", sDateTime, _pZmoduleBlock->moduleName, fn_GetCurrentProcessId(), dbgFormat);

    va_start(vaList, dbgFormat);
    fn_wvsprintfA(debugMessage, formatBuffer, vaList);
    va_end(vaList);

    fn_OutputDebugStringA(debugMessage);
#ifdef LOG_ON_FILE
    {
        wchar_t folderPath[MAX_PATH];
        wchar_t logsFileName[MAX_PATH];
        HANDLE hFile;

        fn_GetTempPathW(MAX_PATH, folderPath);
		fn_PathCombineW(logsFileName, folderPath, L"possessor.log");

        hFile = fn_CreateFileW(logsFileName, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD dwBuffer;

            fn_SetFilePointer(hFile, 0, NULL, FILE_END);
            fn_WriteFile(hFile, debugMessage, (DWORD)fn_lstrlenA(debugMessage), &dwBuffer, NULL);
            fn_SetEndOfFile(hFile);
            fn_CloseHandle(hFile);
        }
    }
#endif // LOG_ON_FILE
}
#endif // LOG_ON