#ifndef __COMMON_VECTOR_H_
#define __COMMON_VECTOR_H_

typedef void** iterator_t;
typedef struct _vector* vector_t;

vector_t __stdcall vector_new(void);
void __stdcall vector_destroy(vector_t vector);
void __stdcall vector_destroy_strings(vector_t vector);
void __stdcall vector_clear(vector_t vector);
uint32_t __stdcall vector_size(vector_t vector);
uint32_t __stdcall vector_count(vector_t vector);
int __stdcall vector_push_back(vector_t vector, void* elem);
void* __stdcall vector_pop_back(vector_t vector);
void* __stdcall vector_back(vector_t vector);
void* __stdcall vector_access(vector_t vector, uint32_t index);
iterator_t __stdcall vector_at(vector_t vector, size_t index);
iterator_t __stdcall vector_begin(vector_t vector);
iterator_t __stdcall vector_end(vector_t vector);
void __stdcall vector_data_set(iterator_t iterator, void* elem);
void* __stdcall vector_data_get(iterator_t iterator);

#endif // __COMMON_VECTOR_H_
