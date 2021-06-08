//
// Created by Arata Kato on AD 2020/11/21.
//

#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include "utils.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libutils_queue"

#define libutils_queue_priv_of(s) ((s)?((struct libutils_queue_priv*)&((s)->priv)):(NULL))

struct queue_node {
    struct queue_node *prev;
    void *data;
};

struct libutils_queue_priv {
    struct queue_node *head;
    struct queue_node *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    size_t size;
};

static inline void priv_lock(struct libutils_queue_priv *priv)
{
    pthread_mutex_lock(&priv->mutex);
}

static inline void priv_unlock(struct libutils_queue_priv *priv)
{
    pthread_mutex_unlock(&priv->mutex);
}

static inline void priv_cond_wait(struct libutils_queue_priv *priv)
{
    pthread_cond_wait(&priv->cond, &priv->mutex);
}

static inline void priv_cond_signal(struct libutils_queue_priv *priv)
{
    pthread_cond_signal(&priv->cond);
}

static inline bool is_empty(struct libutils_queue_priv *priv)
{
    return (priv->size < 1) ? true : false;
}

int libutils_queue_is_empty(struct libutils_queue_struct *s)
{
    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);
    return (priv) ? is_empty(priv) : true;
}

static int __enqueue(struct libutils_queue_priv *priv, void* data)
{
    struct queue_node *new_node = (struct queue_node*)gc_calloc(1, sizeof(struct queue_node));
    if (!new_node)
        return -1;

    new_node->data = data;

    priv_lock(priv);

    if (priv->size == 0) {
        priv->head = new_node;
        priv->tail = new_node;
    } else {
        priv->tail->prev = new_node;
        priv->tail = new_node;
    }

    priv->size++;

    priv_unlock(priv);

    if (priv->size == 1)
        priv_cond_signal(priv);

    return 0;
}

int libutils_queue_enqueue(struct libutils_queue_struct *s, void* data)
{
    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);
    return (!priv || !data) ? -1 : __enqueue(priv, data);
}

static void* __dequeue(struct libutils_queue_priv *priv)
{
    priv_lock(priv);

    if (is_empty(priv))
        priv_cond_wait(priv);

    struct queue_node* node = priv->head;
    priv->head = (priv->head)->prev;
    priv->size--;

    priv_unlock(priv);

    return node->data;
}

void* libutils_queue_dequeue(struct libutils_queue_struct *s)
{
    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);
    return (priv) ? __dequeue(priv) : NULL;
}

static void __flush_queue(struct libutils_queue_priv *priv)
{
    while (!is_empty(priv)) {
        struct queue_node *node = __dequeue(priv);
        gc_free(node);
    }
}

void libutils_queue_flush(struct libutils_queue_struct *s)
{
    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);
    if (priv)
        __flush_queue(priv);
}

struct libutils_queue_struct* libutils_queue_new(void)
{
    struct libutils_queue_struct *s = (struct libutils_queue_struct*)gc_calloc(1,
            sizeof(struct libutils_queue_struct) + sizeof(struct libutils_queue_priv));
    if (!s)
        return NULL;

    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);

    pthread_mutex_init(&priv->mutex, NULL);
    pthread_cond_init(&priv->cond, NULL);

    return s;
}

void libutils_queue_release(struct libutils_queue_struct *s)
{
    struct libutils_queue_priv *priv = libutils_queue_priv_of(s);
    if (priv)
        __flush_queue(priv);
    gc_free(s);
}