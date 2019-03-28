#include "zmodule.h"
#include "vector.h"
#include "string.h"
#include "memory.h"

#define	INITIAL_SIZE 0x0010

struct _vector
{
	uint32_t count;
	uint32_t size;
	uint32_t next;
	void** array;
};

vector_t __stdcall vector_new(void)
{
	vector_t vector = memory_alloc(sizeof(struct _vector));
	vector->next = INITIAL_SIZE;
	return vector;
}

void __stdcall vector_destroy(vector_t vector)
{
	if (vector->array != NULL) {
		memory_free(vector->array);
	}
	memory_free(vector);
}

void __stdcall vector_destroy_strings(vector_t vector)
{
    for (int i = vector->count; --i >= 0;) {
        zs_free(vector->array[i]);
    }

    vector_destroy(vector);
}

void __stdcall vector_clear(vector_t vector)
{
	if (vector->array != NULL) {
		memory_free(vector->array);
	}
	vector->array = NULL;
	vector->count = 0;
	vector->size = 0;
	vector->next = INITIAL_SIZE;
}

uint32_t __stdcall vector_size(vector_t vector)
{
	return vector->size;
}

uint32_t __stdcall vector_count(vector_t vector)
{
	return vector->count;
}

int __stdcall vector_push_back(vector_t vector, void* elem)
{
	if (vector->count == vector->size) {
		uint32_t newsize = vector->size + vector->next;
		void** array = memory_realloc(vector->array, newsize * sizeof(void*));

		if (array == NULL) {
			return 0;
		}

		vector->array = array;
		vector->size = newsize;
		vector->next <<= 1;
	}

	vector->array[vector->count] = elem;
	++vector->count;
	return 1;
}

void* __stdcall vector_pop_back(vector_t vector)
{
	return vector->array[--vector->count];
}

void* __stdcall vector_back(vector_t vector)
{
	return vector->array[vector->count - 1];
}

void* __stdcall vector_access(vector_t vector, uint32_t index)
{
	if (index >= vector->count) {
		return NULL;
	}
	return vector->array[index];
}

iterator_t __stdcall vector_at(vector_t vector, size_t index)
{
	if (index >= vector->count) {
		return NULL;
	}
	return &vector->array[index];
}

iterator_t __stdcall vector_begin(vector_t vector)
{
	return &vector->array[0];
}

iterator_t __stdcall vector_end(vector_t vector)
{
	return &vector->array[vector->count];
}

void __stdcall vector_data_set(iterator_t iterator, void* elem)
{
	*iterator = elem;
}

void* __stdcall vector_data_get(iterator_t iterator)
{
	return *iterator;
}
