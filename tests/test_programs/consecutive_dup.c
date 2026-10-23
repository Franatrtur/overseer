#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

int main(void) {
    // Duplicate 1: Consecutive getpid()
    getpid();
    getpid();

    // Duplicate 2: Consecutive close() on same fd
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        close(fd);
    }

    // Duplicate 3: Consecutive stat() on same path
    struct stat st;
    stat("/dev/null", &st);
    stat("/dev/null", &st);

    return 0;
}
