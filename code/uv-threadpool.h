#ifndef ASYNC_THREADPOOL_H_
#define ASYNC_THREADPOOL_H_

struct async__work
{
    void (*work)(struct async__work *w);
    void (*done)(struct async__work *w, int status);
    struct async_loop_s* loop;
    void* wq[2];
};

#endif /* ASYNC_THREADPOOL_H_ */
