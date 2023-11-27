// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <printf.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8
#define MMAP_THRESHOLD align(128 * 1024)
#define META_SIZE align(sizeof(struct block_meta))
#define SIZE_T_SIZE (align(sizeof(size_t)))
#define PAGE_BREAK "\n\n===========================================================\n\n"

struct block_meta *header_start;

bool initialized = true;

size_t align(size_t size)
{
	size_t r = size % ALIGNMENT;

	if (r == 0)
		return size;
	else
		return size + (ALIGNMENT - r);
}

void print_list(void)
{
	struct block_meta *current = header_start;

	while (current != NULL) {
		printf("size: %lld ", current->size);
		printf("status: %d - ", current->status);
		printf(" |------------| ");
		current = current->next;
	}
	printf(PAGE_BREAK);
}

void add_to_list(struct block_meta *block)
{
	if (header_start == NULL) {
		header_start = block;
		header_start->next = NULL;
		header_start->prev = NULL;
	} else {
		struct block_meta *current = header_start;

		while (current->next != NULL)
			current = current->next;
		current->next = block;
		block->prev = current;
		block->next = NULL;
	}
}

void add_between_blocks(struct block_meta *new_block, struct block_meta *prev_block, struct block_meta *next_block)
{
	prev_block->next = new_block;
	new_block->prev = prev_block;
	new_block->next = next_block;
	next_block->prev = new_block;
}

void remove_from_list(struct block_meta *block)
{
	if (block == NULL)
		return;

	if (block->prev != NULL)
		block->prev->next = block->next;
	else
		header_start = block->next;

	if (block->next != NULL)
		block->next->prev = block->prev;
}

void set_block_metadata(struct block_meta *block, size_t size, int status)
{
	block->size = size;
	block->status = status;
	block->prev = NULL;
	block->next = NULL;
}

struct block_meta *request_brk(size_t size)
{
	struct block_meta *block;

	block = sbrk(0);
	DIE(block == (struct block_meta *)-1, "sbrk failed");
	block = sbrk(align(size));
	DIE(block == (struct block_meta *)-1, "sbrk failed");

	return block;
}

struct block_meta *request_mmap(size_t size)
{
	struct block_meta *block;

	block = mmap(NULL, align(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE(block == (struct block_meta *)-1, "mmap failed");

	return block;
}

void preallocate(void)
{
	struct block_meta *block;

	block = sbrk(0);
	DIE(block == (struct block_meta *)-1, "sbrk failed");
	block = sbrk(align(MMAP_THRESHOLD));
	DIE(block == (struct block_meta *)-1, "sbrk failed");
	block->status = STATUS_FREE;
	block->size = MMAP_THRESHOLD - META_SIZE;
	block->next = NULL;
	block->prev = NULL;
	add_to_list(block);
	initialized = false;
}

struct block_meta *find_last_brk(void)
{
	struct block_meta *current = header_start;
	struct block_meta *last = NULL;

	while (current != NULL) {
		if (current->status == STATUS_FREE || current->status == STATUS_ALLOC)
			last = current;
		current = current->next;
	}

	return last;
}

struct block_meta *extend_last(size_t size)
{
	struct block_meta *last = find_last_brk();
	size_t to_be_extended = size - last->size;

	if (last->status == STATUS_FREE) {
		struct block_meta *test = NULL;

		test = sbrk(0);
		DIE(test == (struct block_meta *)-1, "sbrk failed");
		sbrk(to_be_extended);
		last->size += to_be_extended;

		return last;
	}

	return NULL;
}

struct block_meta *find_free_block(size_t size, int use)
{
	struct block_meta *current = header_start;
	struct block_meta *best = NULL;
	size_t error = 0;
	size_t smallest_error = __INT_MAX__;

	while (current != NULL)	{
		if (current->status == STATUS_FREE && current->size >= size) {
			error = current->size - size;
			if (error < smallest_error) {
				best = current;
				smallest_error = error;
			}
		}
		current = current->next;
	}
	if (best != NULL)
		return best;

	if (use == 1)
		return extend_last(size);
	else
		return NULL;
}

int coalesce_forward(struct block_meta *block)
{
	struct block_meta *find = block->next;

	while (find != NULL && find->status == STATUS_MAPPED)
		find = find->next;
	if (find != NULL && find->status == STATUS_FREE) {
		block->size = block->size + find->size + META_SIZE;

		remove_from_list(find);

		return true;
	}
	return false;
}

struct block_meta *coalesce_behind(struct block_meta *block)
{
	struct block_meta *find = block->prev;

	while (find != NULL && find->status == STATUS_MAPPED)
		find = find->prev;
	if (find != NULL && find->status == STATUS_FREE) {
		if (coalesce_forward(find) == true)
			return find;
	}
	return block;
}

void split_blocks(struct block_meta *block, size_t size)
{
	if (block->size > size + META_SIZE) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + META_SIZE + size);

		set_block_metadata(new_block, block->size - size - META_SIZE, STATUS_FREE);
		block->size = size;
		if (block->next == NULL)
			add_to_list(new_block);
		else
			add_between_blocks(new_block, block, block->next);
		coalesce_forward(new_block);
	}
}

void coalesce(struct block_meta *block)
{
	if (block != NULL) {
		coalesce_forward(block);
		coalesce_behind(block);
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	struct block_meta *block;

	size = align(size);
	if (align(size + META_SIZE) < MMAP_THRESHOLD) {
		if (initialized == true)
			preallocate();
		block = find_free_block(align(size), 1);
		if (block == NULL) {
			block = request_brk(align(size + META_SIZE));
			set_block_metadata(block, size, STATUS_ALLOC);
			add_to_list(block);
		} else {
			split_blocks(block, align(size));
			block->status = STATUS_ALLOC;
		}
	} else {
		block = request_mmap(align(size + META_SIZE));
		set_block_metadata(block, size, STATUS_MAPPED);
		add_to_list(block);
	}
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = (struct block_meta *)ptr - 1;

	if (block_ptr->status == STATUS_MAPPED) {
		remove_from_list(block_ptr);
		munmap(block_ptr, align(block_ptr->size + sizeof(struct block_meta)));
		return;
	}
	block_ptr->status = STATUS_FREE;
	coalesce(block_ptr);
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size == 0 || nmemb == 0)
		return NULL;

	size_t calloc_size = align(size * nmemb);

	struct block_meta *block;

	if (align(calloc_size + META_SIZE) >= (size_t)getpagesize()) {
		block = request_mmap(align(calloc_size + META_SIZE));
		set_block_metadata(block, calloc_size, STATUS_MAPPED);
		add_to_list(block);
		return (block + 1);
	}
	void *sulea = os_malloc(calloc_size);

	if (sulea != NULL)
		memset(sulea, 0, calloc_size);
	return sulea;
}

void *os_realloc(void *ptr, size_t size)
{
	bool check_last = false;

	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	size = align(size);
	struct block_meta *block_ptr = (struct block_meta *)ptr - 1;

	if (block_ptr->status == STATUS_FREE)
		return NULL;

	if (size + META_SIZE >= MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(size);

		if (size <= block_ptr->size)
			memmove(new_ptr, ptr, size);
		else
			memmove(new_ptr, ptr, block_ptr->size);
		os_free(ptr);
		return new_ptr;
	}

	if (block_ptr->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);

		if (size <= block_ptr->size)
			memmove(new_ptr, ptr, size);
		else
			memmove(new_ptr, ptr, block_ptr->size);
		os_free(ptr);
		return new_ptr;
	}

check_new_size:
	if (size <= block_ptr->size) {
		split_blocks(block_ptr, size);
		return block_ptr + 1;
	}
	if (coalesce_forward(block_ptr) == true) {
		check_last = true;
		goto check_new_size;
	}


	if (block_ptr == find_last_brk() && check_last == false) {
		struct block_meta *test = NULL;

		test = sbrk(size - block_ptr->size);
		DIE(test == (struct block_meta *)-1, "sbrk failed");
		block_ptr->size += (size - block_ptr->size);
		return block_ptr + 1;
	}

	if (find_free_block(size, 0) != NULL) {
		struct block_meta *new_block = find_free_block(size, 0);

		split_blocks(new_block, size);
		new_block->status = STATUS_ALLOC;

		if (size < new_block->size)
			memmove(new_block + 1, ptr, size);
		else
			memmove(new_block + 1, ptr, block_ptr->size);
		os_free(ptr);
		return new_block + 1;
	}

	void *new_ptr = os_malloc(size);

	if (size <= block_ptr->size)
		memmove(new_ptr, ptr, size);
	else
		memmove(new_ptr, ptr, block_ptr->size);

	os_free(ptr);
	return new_ptr;
}
