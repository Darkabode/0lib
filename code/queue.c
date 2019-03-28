#include "zmodule.h"
#include "uv-common.h"

QUEUE* queue_head(QUEUE* q)
{
    return QUEUE_NEXT(q);
}

BOOL queue_empty(QUEUE* q)
{
    return (const QUEUE *)(q) == (const QUEUE *)QUEUE_NEXT(q);
}

void queue_init(QUEUE* q)
{
    QUEUE_NEXT(q) = q;
    QUEUE_PREV(q) = q;
}

void queue_add(QUEUE* h, QUEUE* n)
{
    QUEUE_PREV_NEXT(h) = QUEUE_NEXT(n);
    QUEUE_NEXT_PREV(n) = QUEUE_PREV(h);
    QUEUE_PREV(h) = QUEUE_PREV(n);
    QUEUE_PREV_NEXT(h) = (h);
}

void queue_split(QUEUE* h, QUEUE* q, QUEUE* n)
{
    QUEUE_PREV(n) = QUEUE_PREV(h);
    QUEUE_PREV_NEXT(n) = (n);
    QUEUE_NEXT(n) = (q);
    QUEUE_PREV(h) = QUEUE_PREV(q);
    QUEUE_PREV_NEXT(h) = (h);
    QUEUE_PREV(q) = (n);
}

void queue_insert_head(QUEUE* h, QUEUE* q)
{
    QUEUE_NEXT(q) = QUEUE_NEXT(h);
    QUEUE_PREV(q) = (h);
    QUEUE_NEXT_PREV(q) = (q);
    QUEUE_NEXT(h) = (q);
}

void queue_insert_tail(QUEUE* h, QUEUE* q)
{
    QUEUE_NEXT(q) = (h);
    QUEUE_PREV(q) = QUEUE_PREV(h);
    QUEUE_PREV_NEXT(q) = (q);
    QUEUE_PREV(h) = (q);
}

void queue_remove(QUEUE* q)
{
    QUEUE_PREV_NEXT(q) = QUEUE_NEXT(q);
    QUEUE_NEXT_PREV(q) = QUEUE_PREV(q);
}
