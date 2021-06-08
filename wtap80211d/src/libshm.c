/*
 * libshm.c
 * wtap80211d - Netlink server for wtap80211
 *
 * Copyright (c) 2016 - 2017, Arata Kato <arata.kato@outlook.com>
 *
 * This program is free software under GPLv2 License; you can redistribute it
 * and/or modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include "utils.h"
#include "libworkqueue.h"
#include "libshm.h"

#define libshm_priv_of(s) ((struct libshm_priv*)&((s)->priv))

#define memory_blocks_tail_addr(priv) \
    ((struct memory_block*)((char*)((priv)->head) + (priv)->total_size))

#define next_writable_memory_block_addr(priv) \
    ((struct memory_block*)((char*)((priv)->head_writable) + (priv)->block_size))

#define next_readable_memory_block_addr(priv) \
    ((struct memory_block*)(((char*)((priv)->head_readable) + (priv)->block_size)))

#define data_field_head_addr(mb) (&(mb)->data)
#define data_field_writable_addr(mb) ((char*)(&(mb)->data) + (mb)->offset)
#define data_field_reminder(priv ,mb) ((priv)->data_size - (mb)->offset)

static struct {
    pthread_mutex_t mutex;
    bool is_initialized;
} libshm;

struct memory_block {
    sem_t semaphore;
    size_t offset;
    char data[0];
};

struct libshm_priv {
    struct libworkqueue_struct *workqueue;

    char shm_objfile[NAME_MAX];
    int shm_id;

    size_t block_size;
    size_t block_num;
    size_t data_size;
    size_t total_size;

    /* shm_size is used to release shared memory only. */
    size_t shm_size;

    struct memory_block *head;
    struct memory_block *head_writable;
    struct memory_block *head_readable;

    bool is_overwrite_enabled;

    int (*memory_writer)(struct libshm_priv*, void*, size_t);

    pthread_mutex_t mutex;
    pthread_mutex_t head_writable_mutex;
    pthread_mutex_t head_readable_mutex;
};

static int write_binary_force(struct libshm_priv *priv, void *data, size_t bytes)
{
    struct memory_block *mb = priv->head_writable;
    size_t write_bytes;

    write_bytes = (bytes > data_field_reminder(priv, mb))
                        ? data_field_reminder(priv, mb) : bytes;

    if (write_bytes < 1)
        return -ENOMEM;

    pthread_mutex_unlock(&priv->head_writable_mutex);

    sem_wait(&mb->semaphore);

    memcpy(data_field_writable_addr(mb), data, write_bytes);
    mb->offset += write_bytes;

    print_log(MSG_DBG,
            "[libshm] Wrote %zu bytes on (addr = %p, offset = %zu bytes, reminder = %zu bytes)\n",
            write_bytes, mb, mb->offset, data_field_reminder(priv, mb));

    if (data_field_reminder(priv, mb) < 1) {
        priv->head_writable =
            (next_writable_memory_block_addr(priv) < memory_blocks_tail_addr(priv))
            ? next_writable_memory_block_addr(priv)
            : priv->head;

        if (priv->is_overwrite_enabled)
            priv->head_writable->offset = 0;

        print_log(MSG_DBG,
                "[libshm] Updated writable block address (curernt: %p, next: %p)\n",
                mb, priv->head_writable);
    }

    sem_post(&mb->semaphore);

    pthread_mutex_unlock(&priv->head_writable_mutex);

    return bytes - write_bytes;
}

int libshm_write(struct libshm_struct *s, void *data, size_t bytes)
{
    struct libshm_priv *priv = NULL;
    int reminder = bytes;

    if (!s || !data)
        return -EINVAL;

    if (!bytes)
        return 0;

    priv = libshm_priv_of(s);

    while (reminder > 0) {
        char *head = (char*)data + bytes - reminder;
        reminder = priv->memory_writer(priv, head, reminder);
    }

    return reminder;
}

/* libshm_read reads data from a memory block. @bytes must be more than the block size.*/
int libshm_read(struct libshm_struct *s, void *data, size_t bytes)
{
    struct libshm_priv *priv;
    struct memory_block *mb, *next;
    size_t data_size;

    if (!s || !data)
        return -EINVAL;

    priv = libshm_priv_of(s);
    mb = priv->head_readable;

    if (bytes < 1 || bytes < priv->data_size)
        return -EINVAL;

    /* Mutex for avoiding a conflict between duplicated read calls */
    pthread_mutex_lock(&priv->head_readable_mutex);
    /* Check a semaphore for avoiding a conflict between writing and reading. */
    sem_wait(&mb->semaphore);

    print_log(MSG_DBG, "[libshm] %zu bytes on a block (addr = %p)\n", mb->offset, mb);

    memcpy(data, (char*)mb->data, mb->offset);
    data_size = mb->offset;
    mb->offset = 0;

    print_log(MSG_DBG, "[libshm] read %zu bytes (reminder: %zu bytes)\n", data_size, mb->offset);

    next = (next_readable_memory_block_addr(priv) < memory_blocks_tail_addr(priv))
                ? next_readable_memory_block_addr(priv)
                : priv->head;
    priv->head_readable = (next == priv->head_writable) ? priv->head_readable : next;

    print_log(MSG_DBG, "[libshm] a pointer to readable header updated (addr = %p))\n", priv->head_readable);

    sem_post(&mb->semaphore);
    pthread_mutex_unlock(&priv->head_readable_mutex);

    return (int)data_size;
}

__attribute__((malloc))
static void* allocate_shared_memory(const char *shm_objfile, size_t shm_size)
{
    int err, fd;

    if ((err = fd = shm_open(shm_objfile, O_CREAT | O_RDWR, 0666)) < 0)
        goto error;

    if ((err = ftruncate(fd, shm_size)) < 0)
        goto error;

    return mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

error:
    close(fd);
    print_log(MSG_ERR,
            "[libshm] Could not allocate shared memory (reason: %s, code: %d).\n",
            strerror(-err), err);
    return NULL;
}

struct memory_block* allocate_multiple_memory_blocks(struct libshm_priv *priv)
{
    priv->shm_size = priv->block_size * priv->block_num;
    return (struct memory_block*)allocate_shared_memory(priv->shm_objfile, priv->shm_size);
}

static void* do_memory_block_init(void* arg)
{
    struct libshm_priv *priv = (struct libshm_priv*)arg;
    struct memory_block *mb = NULL;
    size_t i = 0;

    if (!(mb = (struct memory_block*)allocate_multiple_memory_blocks(priv)))
        return NULL;

    priv->head = mb;
    priv->head_writable = mb;
    priv->head_readable = mb;
    priv->data_size = priv->block_size - offsetof(struct memory_block, data);
    priv->total_size = priv->block_size * priv->block_num;

    for (i = 0; i < priv->block_num; ++i) {
        struct memory_block *mb =
            (struct memory_block*)((char*)priv->head + i * priv->block_size);
        sem_init((sem_t*)&mb->semaphore, 1, 1);
        mb->offset = 0;
    }

    print_log(MSG_DBG,
            "[libshm] Memory blocks start at %p (total: %zu bytes, block size: %zu bytes, block num: %zu).\n",
            priv->head, priv->shm_size, priv->block_size, priv->block_num);

    print_log(MSG_INFO, "[libshm] Initialization completed.\n");

    return mb;
}

size_t libshm_get_data_field_size(struct libshm_struct *s)
{
    struct libshm_priv *priv = libshm_priv_of(s);
    return priv->data_size;
}

static int check_config(struct libshm_config_struct *config)
{
    if (config->block_size < sizeof(struct memory_block) + 1) {
        print_log(MSG_ERR, "[libshm] block size must be more than %zu bytes\n", sizeof(struct memory_block) + 1);
        return -1;
    }

    return 0;
}

__attribute__((malloc))
struct libshm_struct* libshm_new(struct libshm_config_struct *config)
{
    struct libshm_priv *priv;
    struct libshm_struct *s;
    int i, err = 0;

    if (!libshm.is_initialized)
        return NULL;

    if (check_config(config) < 0)
        return NULL;

    s = (struct libshm_struct*)gc_calloc(1,
            sizeof(struct libshm_struct) + sizeof(struct libshm_priv));

    if (!s)
        return NULL;

    priv = libshm_priv_of(s);

    priv->workqueue = libworkqueue_new();
    if (!priv->workqueue) {
        print_log(MSG_DBG, "[libshm] Could not initialize libworkqueue\n");
        return NULL;
    }

    if (config) {
        memcpy(priv->shm_objfile, config->shm_objfile, NAME_MAX);
        priv->block_size = config->block_size;
        priv->block_num = config->block_num;
        priv->is_overwrite_enabled = config->is_overwrite_enabled;
    } else {
        memcpy(priv->shm_objfile, LIBSHM_CONFIG_DEFAULT_OBJFILE,
                sizeof(LIBSHM_CONFIG_DEFAULT_OBJFILE));
        priv->block_size = LIBSHM_CONFIG_DEFAULT_BLOCK_SIZE;
        priv->block_num = LIBSHM_CONFIG_DEFAULT_BLOCK_NUM;
        priv->is_overwrite_enabled = LIBSHM_CONFIG_DEFAULT_OVERWRITE;
    }

    print_log(MSG_DBG,
            "[libshm] shm_objfile = %s, block size = %zu, block num = %zu, is_overwrite = %d\n",
            priv->shm_objfile, priv->block_size, priv->block_num, priv->is_overwrite_enabled);

    if (priv->is_overwrite_enabled) {
        priv->memory_writer = write_binary_force;
    } else {
        priv->memory_writer = write_binary_force;
    }

    if ((err = pthread_mutex_init(&priv->mutex, NULL)))
        goto error_in_priv_init;

    if ((err = pthread_mutex_init(&priv->head_writable_mutex, NULL)))
        goto error_in_priv_init;

    if ((err = pthread_mutex_init(&priv->head_readable_mutex, NULL)))
        goto error_in_priv_init;

    if (!do_memory_block_init(priv))
        goto error_in_priv_init;

    s->status |= LIBSHM_STATUS_INITIALIZED;

    return s;

error_in_priv_init:
    gc_free(s);
    print_log(MSG_DBG, "[libshm] Initialization incompleted (reason: %s, code: %d)\n",
            strerror(err), err);
    return NULL;
}

void libshm_init(void)
{
    libworkqueue_init();
    libshm.is_initialized = true;
}

static void release_memory_blocks(struct libshm_priv *priv)
{
    munmap(priv->head, priv->shm_size);
}

void libshm_release(struct libshm_struct *s)
{
    struct libshm_priv *priv = libshm_priv_of(s);
    release_memory_blocks(priv);
    gc_free(s);
}
