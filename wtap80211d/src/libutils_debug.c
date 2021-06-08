//
// Created by Arata Kato on 2019-10-10.
//

#include <stdio.h>

#define UNW_LOCAL_ONLY
#include "libunwind.h"
#include "utils.h"

#define SYMBOL_NAME_LEN 512

#undef DEBUG_IDENTIFIER
#define DEBUG_IDENTIFIER "Debug"

void libutils_debug_print_backtrace(void)
{
#ifdef ENABLE_DEBUG
    unw_cursor_t cursor;
    unw_context_t context;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    int count = 0;

    fprintf(stderr, "===== %s BEGIN =====\n", __func__);

    do {
        char symbol_name[SYMBOL_NAME_LEN] = {0};
        unw_word_t offset, pc;

        unw_get_reg(&cursor, UNW_REG_IP, &pc);
        unw_get_proc_name(&cursor, symbol_name, ARRAY_SIZE(symbol_name), &offset);

        Dl_info info;
        dladdr((void*)pc, &info);

        char unixtime[20] = {0};
        get_timestr_unix(unixtime, 20);                                                                                          \

        fprintf(stderr,
                "[%s] msg: " DEBUG_IDENTIFIER ", order: %d, fname: %s, symbol: (%s+0x%lx) (%p+0x%lx)\n",
                unixtime, count, info.dli_fname, symbol_name, offset, (void*)pc, offset);

        count++;

    } while (unw_step(&cursor) > 0);

    fprintf(stderr, "===== %s END =======\n", __func__);

#endif /* ENABLE_DEBUG */
}

#undef DEBUG_IDENTIFIER
