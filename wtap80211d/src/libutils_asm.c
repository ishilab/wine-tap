//
// Created by Arata Kato on AD 2020/02/06.
//

#include "utils.h"

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "libutils_asm"

inline unsigned long long int gettime_rdtsc(void)
{
    unsigned long long int ret;
    __asm__ __volatile__ ("rdtsc;" : "=A" (ret));
    return ret;
}

#undef DEBUG_IDENTIFIER
