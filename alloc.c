/*
 * CS 241
 * The University of Illinois
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define SLABSZ 4096

struct slab_data
{
	unsigned short int block_size;
	unsigned short int block_count;
	unsigned short int alloc_blocks;
	unsigned short int first_free;
	struct slab_data *next;
};

struct free_block
{
	unsigned short int next;
	unsigned short int width;
};

void *slab_get_block(struct slab_data *slab, unsigned short int index)
{
	size_t offset = sizeof(struct slab_data) + index * slab->block_size;
	return (char *)slab + offset;
}

void slab_init(struct slab_data *slab, unsigned short int block_size)
{
	slab->block_size = block_size;
	slab->block_count = (SLABSZ - sizeof(struct slab_data)) / block_size;
	slab->alloc_blocks = 0;
	slab->first_free = 0;
	slab->next = NULL;
	struct free_block *block = slab_get_block(slab, 0);
	block->next = 0;
	block->width = slab->block_count;
}

void *slab_alloc_block(struct slab_data *slab)
{
	if (slab->alloc_blocks == slab->block_count)
		return NULL;
	unsigned short int index = slab->first_free;
	struct free_block *free_data = slab_get_block(slab, index);
	if (free_data->width > 1)
	{
		free_data->width--;
		slab->first_free = index + 1;
	}
	else slab->first_free = free_data->next;
	slab->alloc_blocks++;
	return free_data;
}

void slab_free_block(struct slab_data *slab, unsigned short int index)
{
	unsigned short int next;
	if (slab->alloc_blocks == slab->block_count)
	{
		next = 0;
		slab->first_free = index;
	}
	else if (slab->first_free > index)
	{
		next = slab->first_free;
		slab->first_free = index;
	}
	else
	{
		unsigned short int i = slab->first_free;
		struct free_block *curr;
		do
		{
			curr = slab_get_block(slab, i);
			next = curr->next;
		} while (next != 0 && next < index);
		curr->next = index;
	}
	struct free_block *block = slab_get_block(slab, index);
	block->width = 1;
	block->next = next;
}

struct slab_data *head_slab = NULL;

void *malloc(size_t size)
{
	if (head_slab == NULL)
	{
		size_t break_offset = (size_t)sbrk(0) % SLABSZ;
		if (break_offset != 0)
			sbrk(SLABSZ - break_offset);
		head_slab = sbrk(SLABSZ);
		slab_init(head_slab, 4);
	}
	return slab_alloc_block(head_slab);
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr = malloc(nmemb * size);

	if (ptr)
		memset(ptr, 0x00, nmemb * size);

	return ptr;
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
