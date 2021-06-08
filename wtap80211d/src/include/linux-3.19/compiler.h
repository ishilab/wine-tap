/*
 *
 */

#ifndef COMPILER_H
#define COMPILER_H

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef WARN_ON
#define WARN_ON(x)
#endif

#endif
