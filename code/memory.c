#include "zmodule.h"
#include "memory.h"

HANDLE __stdcall memory_process_heap(void)
{
	return (HANDLE)fn_NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
}

void* __stdcall memory_alloc(size_t sz)
{
    void* ptr;
    do {
        ptr = fn_RtlAllocateHeap(memory_process_heap(), HEAP_ZERO_MEMORY, sz);
        if (ptr != NULL) {
            break;
        }
        fn_Sleep(1000);
    } while (1);
    
    return ptr;
}

void* __stdcall memory_aligned_alloc(size_t sz)
{
    puint_t allocBuffer = (puint_t)memory_alloc(sizeof(void*) + sz + 31);
#ifdef _WIN64
    puint_t result = (allocBuffer + sizeof(void*) + 63) & 0xFFFFFFFFFFFFFFC0ULL;
#else
    puint_t result = (allocBuffer + sizeof(void*) + 31) & 0xFFFFFFE0;
#endif // _WIN64
    *(void**)(result - sizeof(void*)) = allocBuffer;
    return result;
}

void* __stdcall memory_realloc(void* ptr, size_t newSize)
{
	if (ptr == NULL) {
		return memory_alloc(newSize);
	}
	return fn_RtlReAllocateHeap(memory_process_heap(), HEAP_ZERO_MEMORY, ptr, newSize);
}

BOOLEAN __stdcall memory_free(void* ptr)
{
	return fn_RtlFreeHeap(memory_process_heap(), 0, ptr);
}

BOOLEAN __stdcall memory_aligned_free(void* ptr)
{
    puint_t startAddr = (puint_t)ptr;
    startAddr -= sizeof(void*);
    return memory_free(*(void**)startAddr);
}
