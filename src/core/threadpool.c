#define _GNU_SOURCE
#include "core/threadpool.h"
#include "util/logger.h"
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define JOB_QUEUE_SIZE 1024

typedef struct {
    job_fn_t fn;
    void *arg;
} job_t;

struct threadpool {
    pthread_t *threads;
    int n_threads;
    
    job_t jobs[JOB_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    
    pthread_mutex_t mutex;
    pthread_cond_t job_available;
    pthread_cond_t job_completed;
    
    int should_stop;
};

static void *worker_thread(void *arg) {
    threadpool_t *tp = (threadpool_t *)arg;
    
    while (1) {
        pthread_mutex_lock(&tp->mutex);
        
        // Wait for a job or stop signal
        while (tp->count == 0 && !tp->should_stop) {
            pthread_cond_wait(&tp->job_available, &tp->mutex);
        }
        
        // Check if we should stop
        if (tp->should_stop && tp->count == 0) {
            pthread_mutex_unlock(&tp->mutex);
            break;
        }
        
        // Get job from queue
        job_t job = tp->jobs[tp->head];
        tp->head = (tp->head + 1) % JOB_QUEUE_SIZE;
        tp->count--;
        
        pthread_mutex_unlock(&tp->mutex);
        
        // Execute job
        if (job.fn) {
            job.fn(job.arg);
        }
        
        // Signal that a job was completed
        pthread_mutex_lock(&tp->mutex);
        pthread_cond_signal(&tp->job_completed);
        pthread_mutex_unlock(&tp->mutex);
    }
    
    return NULL;
}

threadpool_t *threadpool_new(int n_threads) {
    if (n_threads <= 0) {
        LOG_ERROR("Invalid number of threads: %d", n_threads);
        return NULL;
    }
    
    threadpool_t *tp = calloc(1, sizeof(threadpool_t));
    if (!tp) {
        LOG_ERROR("Failed to allocate threadpool");
        return NULL;
    }
    
    tp->n_threads = n_threads;
    tp->threads = calloc((size_t)n_threads, sizeof(pthread_t));
    if (!tp->threads) {
        LOG_ERROR("Failed to allocate thread array");
        free(tp);
        return NULL;
    }
    
    if (pthread_mutex_init(&tp->mutex, NULL) != 0) {
        LOG_ERROR("Failed to initialize mutex");
        free(tp->threads);
        free(tp);
        return NULL;
    }
    
    if (pthread_cond_init(&tp->job_available, NULL) != 0) {
        LOG_ERROR("Failed to initialize condition variable");
        pthread_mutex_destroy(&tp->mutex);
        free(tp->threads);
        free(tp);
        return NULL;
    }
    
    if (pthread_cond_init(&tp->job_completed, NULL) != 0) {
        LOG_ERROR("Failed to initialize condition variable");
        pthread_cond_destroy(&tp->job_available);
        pthread_mutex_destroy(&tp->mutex);
        free(tp->threads);
        free(tp);
        return NULL;
    }
    
    // Start worker threads
    for (int i = 0; i < n_threads; i++) {
        if (pthread_create(&tp->threads[i], NULL, worker_thread, tp) != 0) {
            LOG_ERROR("Failed to create worker thread %d", i);
            tp->n_threads = i;
            threadpool_destroy(tp);
            return NULL;
        }
    }
    
    return tp;
}

int threadpool_submit(threadpool_t *tp, job_fn_t fn, void *arg) {
    if (!tp || !fn) {
        return -1;
    }
    
    pthread_mutex_lock(&tp->mutex);
    
    // Wait if queue is full
    while (tp->count == JOB_QUEUE_SIZE && !tp->should_stop) {
        pthread_cond_wait(&tp->job_completed, &tp->mutex);
    }
    
    // Check if we should stop
    if (tp->should_stop) {
        pthread_mutex_unlock(&tp->mutex);
        return -1;
    }
    
    // Add job to queue
    tp->jobs[tp->tail] = (job_t){.fn = fn, .arg = arg};
    tp->tail = (tp->tail + 1) % JOB_QUEUE_SIZE;
    tp->count++;
    
    pthread_mutex_unlock(&tp->mutex);
    pthread_cond_signal(&tp->job_available);
    
    return 0;
}

void threadpool_destroy(threadpool_t *tp) {
    if (!tp) {
        return;
    }
    
    // Signal all threads to stop
    pthread_mutex_lock(&tp->mutex);
    tp->should_stop = 1;
    pthread_mutex_unlock(&tp->mutex);
    
    // Wake up all worker threads
    pthread_cond_broadcast(&tp->job_available);
    
    // Wait for all threads to finish
    for (int i = 0; i < tp->n_threads; i++) {
        pthread_join(tp->threads[i], NULL);
    }
    
    // Clean up
    pthread_cond_destroy(&tp->job_available);
    pthread_cond_destroy(&tp->job_completed);
    pthread_mutex_destroy(&tp->mutex);
    free(tp->threads);
    free(tp);
}
