#ifndef __COMMON_CLIB_MEMORY_H_
#define __COMMON_CLIB_MEMORY_H_

HANDLE __stdcall memory_process_heap(void);
void* __stdcall memory_alloc(size_t sz);
void* __stdcall memory_realloc(void* ptr, size_t newSize);
BOOLEAN __stdcall memory_free(void* ptr);
void* __stdcall memory_aligned_alloc(size_t sz);
BOOLEAN __stdcall memory_aligned_free(void* ptr);


#endif // __COMMON_CLIB_MEMORY_H_
