#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(void) {
    struct stat st;
    stat("/etc/hosts", &st);
    getpid();
    getuid();
    // Repeated within window
    stat("/etc/hosts", &st);
    return 0;
}
