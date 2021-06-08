#include <stdio.h>
#include <unistd.h>
#include "libworkqueue.h"

static void* task_worker(void *arg)
{
    static unsigned int count = 0;

    printf("count = %u\n", ++count);

    return NULL;
}

int main(void)
{
    struct libworkqueue_struct *s = NULL;
    int i;

    fprintf(stderr, "test_workqueue started.\n");

    libworkqueue_init();

    if (!(s = libworkqueue_new()))
        return -1;

    for (i = 0; i < 10; ++i)
        libworkqueue_enqueue_task(s, NULL, task_worker, NULL);

    sleep(5);

    libworkqueue_remove(s);

    fprintf(stderr, "test_workqueue is shutting down.\n");

    return 0;
}
