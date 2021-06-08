#include <stdio.h>

#define __USE_GNU
#define _GNU_SOURCE
#include <dlfcn.h>

void* memcpy(void *buf1, const void *buf2, size_t n)
{
    void *handle = dlsym(RTLD_NEXT, "memcpy");
    void* (*func)(void*, const void*, size_t) = (void* (*)(void*, const void*, size_t))handle;

    if (!buf1 || !buf2 || n < 1)
        return NULL;

    return func(buf1, buf2, n);
}
