//
// Created by Arata Kato on AD 2020/11/22.
//

#ifndef LIBWORKQUEUE_H
#define LIBWORKQUEUE_H

struct libworkqueue_struct {
    unsigned int status;
    char priv[0];
};

extern int libworkqueue_enqueue_task(struct libworkqueue_struct *s,
        void *ret, void* (*task_worker)(void*), void *arg);

extern void libworkqueue_remove(struct libworkqueue_struct *s);

extern struct libworkqueue_struct* libworkqueue_new(void);

extern int libworkqueue_init(void);

#endif // LIBWORKQUEUE_H
