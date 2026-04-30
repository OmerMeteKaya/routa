#ifndef ROUTA_CORE_THREADPOOL_H
#define ROUTA_CORE_THREADPOOL_H

typedef void (*job_fn_t)(void *arg);

typedef struct threadpool threadpool_t;

threadpool_t *threadpool_new(int n_threads);
int           threadpool_submit(threadpool_t *tp, job_fn_t fn, void *arg);
void          threadpool_destroy(threadpool_t *tp);

#endif // ROUTA_CORE_THREADPOOL_H
