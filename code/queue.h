#ifndef QUEUE_H_
#define QUEUE_H_

typedef void* QUEUE[2];

/* Private macros. */
#define QUEUE_NEXT(q)       (*(QUEUE **) &((*(q))[0]))
#define QUEUE_PREV(q)       (*(QUEUE **) &((*(q))[1]))
#define QUEUE_PREV_NEXT(q)  (QUEUE_NEXT(QUEUE_PREV(q)))
#define QUEUE_NEXT_PREV(q)  (QUEUE_PREV(QUEUE_NEXT(q)))

/* Public macros. */
#define QUEUE_DATA(ptr, type, field)                                          \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define QUEUE_FOREACH(q, h)                                                   \
  for ((q) = QUEUE_NEXT(h); (q) != (h); (q) = QUEUE_NEXT(q))

BOOL queue_empty(QUEUE* q);
QUEUE* queue_head(QUEUE* q);
void queue_init(QUEUE* q);
void queue_add(QUEUE* h, QUEUE* n);
void queue_split(QUEUE* h, QUEUE* q, QUEUE* n);
void queue_insert_head(QUEUE* h, QUEUE* q);
void queue_insert_tail(QUEUE* h, QUEUE* q);
void queue_remove(QUEUE* q);

#endif /* QUEUE_H_ */
