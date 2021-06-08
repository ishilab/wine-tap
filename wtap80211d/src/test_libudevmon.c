#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "utils.h"
#include "libudevmon.h"

int main(int argc, char **argv)
{
    struct libudevmon_struct *s;
    char ifnames[3][IFNAMSIZ] = {{0}};

    if (argc < 3 || argc > 5) {
        print_log(MSG_ERR, "Usage: ./test_libudevmon <and|or> <ifname1> <ifname2> <ifname3>\n");
        return -1;
    }

    libudevmon_init();

    if (!(s = libudevmon_new("net")))
        goto error;

    for (int i = 2; i < argc; ++i)
        strncpy(ifnames[i-2], argv[i], strlen(argv[i]));

    if (strcmp(argv[1], "or") == 0) {
        for (int i = 0; i < argc - 2; ++i)
            print_log(MSG_INFO, "%s %s\n", ifnames[i],
                    (libudevmon_has_device(s, ifnames[i])) ? "exists" : "does not exist");
    } else if (strcmp(argv[1], "and") == 0) {
        print_log(MSG_INFO, "%s device exist\n",
                (libudevmon_has_multiple_devices(s, ifnames, argc - 2)) ? "All" : "Not all");
    } else {
        print_log(MSG_ERR, "Invalid arguments\n");
    }

    libudevmon_release(s);

    libudevmon_exit();

    return 0;

error:
    print_log(MSG_ERR, "error: %s\n", strerror(errno));
    return -1;
}
