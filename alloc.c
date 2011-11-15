/*
 * CS 241
 * The University of Illinois
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void *calloc(size_t nmemb, size_t size)
{
	void *ptr = malloc(nmemb * size);
	
	if (ptr)
		memset(ptr, 0x00, nmemb * size);

	return ptr;
}

void *malloc(size_t size)
{
	return NULL;
}

void free(void *ptr)
{
	/*
	 * According to the C standard:
	 *   If a null pointer is passed as argument, no action occurs.
	 */
	if (!ptr)
		return;

	return;
}

void *realloc(void *ptr, size_t size)
{
	/*
	 * According to the C standard:
	 *   In case that ptr is NULL, the function behaves exactly as malloc,
	 *   assigning a new block of size bytes and returning a pointer to
	 *   the beginning of it.
	 */
	if (!ptr)
		return malloc(size);

	/*
	 * According to the C standard:
	 *   In case that the size is 0, the memory previously allocated in ptr
	 *   is deallocated as if a call to free was made, and a NULL pointer
	 *   is returned.
	 */
	if (!size)
	{
		free(ptr);
		return NULL;
	}



	return NULL;
}
