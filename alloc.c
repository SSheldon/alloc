#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define SLABSZ 4096

struct empty_slab
{
	size_t size;
	struct empty_slab *next;
};

struct empty_slab *empty_head = NULL;

void empty_slab_init(struct empty_slab *slab, size_t size)
{
	if ((size_t)slab + (size << 12) == (size_t)sbrk(0))
	{
		sbrk(-1 * (size << 12));
		return;
	}
	slab->size = size;
	struct empty_slab *prev = NULL, *curr = empty_head;
	while (curr != NULL && curr < slab)
	{
		prev = curr;
		curr = curr->next;
	}
	if (prev != NULL)
	{
		if ((size_t)prev + (prev->size << 12) == (size_t)slab)
		{
			prev->size += size;
			slab = prev;
		}
		else prev->next = slab;
	}
	else empty_head = slab;
	if ((size_t)slab + (slab->size << 12) == (size_t)curr)
	{
		slab->next = curr->next;
		slab->size += curr->size;
	}
	else slab->next = curr;
}

void *alloc_slabs(size_t slabs)
{
	if (empty_head != NULL)
	{
		struct empty_slab *prev = NULL, *curr = empty_head;
		while (curr != NULL && curr->size < slabs)
		{
			prev = curr;
			curr = curr->next;
		}
		if (curr != NULL)
		{
			if (curr->size == slabs)
			{
				if (prev != NULL)
					prev->next = curr->next;
				else
					empty_head = curr->next;
			}
			else
			{
				struct empty_slab *new_empty =
					(struct empty_slab *)((char *)curr + (slabs << 12));
				new_empty->size = curr->size - slabs;
				new_empty->next = curr->next;
				if (prev != NULL)
					prev->next = new_empty;
				else
					empty_head = new_empty;
			}
			return curr;
		}
	}
	size_t break_offset = (size_t)sbrk(0) % SLABSZ;
	if (break_offset != 0)
		sbrk(SLABSZ - break_offset);
	return sbrk(slabs * SLABSZ);
}

struct slab_data
{
	unsigned short int block_size;
	unsigned short int block_count;
	unsigned short int alloc_blocks;
	unsigned short int first_free;
	struct slab_data *next;
};

#define BSZS 13
#define BSZMAX 2040
const unsigned short int bsz_set[BSZS] =
	{4, 8, 16, 32, 48, 80, 120, 240, 340, 510, 816, 1360, 2040};
struct slab_data *head_slabs[BSZS];

size_t nearest_bsz_index(size_t size)
{
	size_t i = 0;
	while (i < BSZS && size > bsz_set[i]) ++i;
	return i;
}

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
		struct free_block *new_first = slab_get_block(slab, index + 1);
		new_first->next = free_data->next;
		new_first->width = free_data->width - 1;
		slab->first_free = index + 1;
	}
	else slab->first_free = free_data->next;
	slab->alloc_blocks++;
	return free_data;
}

void slab_free_block(struct slab_data *slab, unsigned short int index)
{
	unsigned short int bsz_index = nearest_bsz_index(slab->block_size);
	unsigned short int next;
	if (slab->alloc_blocks == slab->block_count)
	{
		next = 0;
		slab->next = head_slabs[bsz_index];
		head_slabs[bsz_index] = slab;
	}
	else
	{
		next = slab->first_free;
	}
	struct free_block *block = slab_get_block(slab, index);
	block->width = 1;
	block->next = next;
	slab->first_free = index;
	slab->alloc_blocks--;
	if (slab->alloc_blocks == 0)
	{
		if (head_slabs[bsz_index] == slab)
			head_slabs[bsz_index] = slab->next;
		else
		{
			struct slab_data *curr = head_slabs[bsz_index];
			while (curr != NULL && curr->next != slab)
				curr = curr->next;
			if (curr != NULL)
				curr->next = slab->next;
		}
		empty_slab_init((struct empty_slab *)slab, 1);
	}
}

void *alloc_block(size_t bsz_index)
{
	struct slab_data *head_slab = head_slabs[bsz_index];
	if (head_slab == NULL)
	{
		head_slab = alloc_slabs(1);
		slab_init(head_slab, bsz_set[bsz_index]);
		head_slabs[bsz_index] = head_slab;
	}
	void *ret = slab_alloc_block(head_slab);
	if (head_slab->alloc_blocks == head_slab->block_count)
	{
		head_slabs[bsz_index] = head_slab->next;
		head_slab->next = NULL;
	}
	return ret;
}

struct big_slab
{
	size_t header;
	size_t size;
};

void *alloc_big_slab(size_t size)
{
	size_t slabs = ((size + sizeof(struct big_slab) - 1) >> 12) + 1;
	struct big_slab *slab = alloc_slabs(slabs);
	slab->header = 0;
	slab->size = slabs;
	return slab + 1;
}

void big_slab_shrink(struct big_slab *slab, size_t new_slabs)
{
	size_t slabs_freed = slab->size - new_slabs;
	slab->size = new_slabs;
	struct empty_slab *empty = (struct empty_slab *)
		((char *)slab + SLABSZ * new_slabs);
	empty_slab_init(empty, slabs_freed);
}

void big_slab_free(struct big_slab *slab)
{
	empty_slab_init((struct empty_slab *)slab, slab->size);
}

void *big_slab_realloc(struct big_slab *slab, size_t size)
{
	size_t slabs = ((size + sizeof(struct big_slab) - 1) >> 12) + 1;
	if (slabs == slab->size)
	{
		return slab + 1;
	}
	else if (slabs < slab->size)
	{
		big_slab_shrink(slab, slabs);
		return slab + 1;
	}
	else if ((size_t)slab + (slab->size << 12) == (size_t)sbrk(0))
	{
		sbrk((slabs - slab->size) << 12);
		slab->size = slabs;
		return slab + 1;
	}
	else
	{
		struct big_slab *new_slab = alloc_slabs(slabs);
		memcpy(new_slab, slab, slab->size << 12);
		new_slab->size = slabs;
		big_slab_free(slab);
		return new_slab + 1;
	}
}

void *malloc(size_t size)
{
	if (size > BSZMAX)
		return alloc_big_slab(size);
	size_t bsz_index = nearest_bsz_index(size);
	return alloc_block(bsz_index);
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

	struct slab_data *slab = (struct slab_data *)((size_t)ptr & ~0xFFF);
	if (slab->block_size == 0)
	{
		big_slab_free((struct big_slab *)slab);
	}
	else
	{
		unsigned short int index =
			(((size_t)ptr & 0xFFF) - sizeof(struct slab_data)) / slab->block_size;
		slab_free_block(slab, index);
	}
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

	struct slab_data *slab = (struct slab_data *)((size_t)ptr & ~0xFFF);
	size_t old_size = slab->block_size;
	if (old_size == 0)
	{
		return big_slab_realloc((struct big_slab *)slab, size);
	}
	else if (size <= old_size)
		return ptr;
	else
	{
		unsigned short int index =
			(((size_t)ptr & 0xFFF) - sizeof(struct slab_data)) / slab->block_size;
		void *ret;
		if (size > BSZMAX)
			ret = alloc_big_slab(size);
		else
			ret = alloc_block(nearest_bsz_index(size));
		memcpy(ret, ptr, old_size);
		slab_free_block(slab, index);
		return ret;
	}
}
