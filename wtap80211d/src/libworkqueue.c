//
// Created by Arata Kato on AD 2020/11/22.
//

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "utils.h"
#include "libworkqueue.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libworkqueue"

#define libworkqueue_priv_of(s) ((s)?((struct libworkqueue_priv*)&((s)->priv)):(NULL))

struct libworkqueue_task {
    void* (*task_worker)(void*);
    void* arg;
};

struct libworkqueue_priv {
    struct libutils_queue_struct* queue;
    pthread_t worker_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    bool is_canceled;
};

static void* worker(void *arg)
{
    struct libworkqueue_priv *priv = (struct libworkqueue_priv*)arg;

    while (!priv->is_canceled) {
        struct libworkqueue_task *task = (struct libworkqueue_task*)libutils_queue_dequeue(priv->queue);
        if (task) {
            task->task_worker(task->arg);
            gc_free(task);
        }
    }

    return NULL;
}

int libworkqueue_enqueue_task(struct libworkqueue_struct *s,
        void* ret, void* (*task_worker)(void*), void* arg)
{
    struct libworkqueue_priv* priv = libworkqueue_priv_of(s);
    struct libworkqueue_task *new_task;

    if (!(new_task = (struct libworkqueue_task*)gc_calloc(1, sizeof(struct libworkqueue_task))))
        return -ENOMEM;

    new_task->task_worker = task_worker;
    new_task->arg = arg;

    libutils_queue_enqueue(priv->queue, new_task);

    return 0;
}

struct libworkqueue_struct* libworkqueue_new(void)
{
    struct libworkqueue_struct *s = (struct libworkqueue_struct*)gc_calloc(1,
            sizeof(struct libworkqueue_struct) + sizeof(struct libworkqueue_priv));
    if (!s)
        return NULL;

    struct libworkqueue_priv *priv = libworkqueue_priv_of(s);
    priv->queue = libutils_queue_new();
    if (pthread_create(&priv->worker_thread, NULL, worker, priv) < 0) {
        libutils_queue_release(priv->queue);
        gc_free(s);
        return NULL;
    }

    pthread_mutex_init(&priv->mutex, NULL);
    pthread_cond_init(&priv->cond, NULL);
    priv->is_canceled = false;

    return s;
}

void libworkqueue_remove(struct libworkqueue_struct *s)
{
    struct libworkqueue_priv *priv = libworkqueue_priv_of(s);
    if (priv) {
        pthread_cancel(priv->worker_thread);
        libutils_queue_release(priv->queue);
        gc_free(s);
    }
}

// This function is defined for compatibility to the previous version only.
int libworkqueue_init(void)
{
    return 0;
}

#undef DEBUG_IDENTIFIER
