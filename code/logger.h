#ifndef __COMMON_LOGGER_H_
#define __COMMON_LOGGER_H_

void __cdecl logger_log(const char* dbgFormat, ...);

#ifdef LOG_ON
#define LOG fn_logger_log 
#else
#define LOG
#endif

#endif // __COMMON_LOGGER_H_
