#ifndef SAFE_MEMSET_H
#define SAFE_MEMSET_H

#include <stddef.h>
#include <string.h>

__attribute__((always_inline))
static inline void
safe_memset(void *buf, int size)
{
    static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
    memset_v(buf, 0, size);
}


#endif
