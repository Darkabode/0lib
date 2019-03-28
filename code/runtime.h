#ifndef __COMMON_RUNTIME_H_
#define __COMMON_RUNTIME_H_

typedef void(__stdcall *FnAtExitCallback)(void);

void __stdcall runtime_atexit(FnAtExitCallback fnAtExitCallback);

// Эту функцию должен вызывать основной код при завершении работы.
void __stdcall runtime_shutdown();

#endif // __COMMON_ATEXIT_H_
