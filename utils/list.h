#ifndef _LIST_H_
#define _LIST_H_

struct block_meta {
    size_t size;
    int status;
    struct block_meta *prev;
    struct block_meta *next;
};

#endif