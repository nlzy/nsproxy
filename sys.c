#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void sys_init(void) {}

unsigned sys_now(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        perror("clock_gettime()");
        abort();
    }
    return now.tv_nsec / 1000000 + now.tv_sec * 1000;
}
