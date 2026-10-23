#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *tmpfile = "/tmp/overseer_stateful_test.tmp";
    int fd = open(tmpfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return 1;

    struct stat st;

    // 1. Initial fstat
    fstat(fd, &st);

    // 2. Redundant fstat without state mutation -> should be flagged
    fstat(fd, &st);

    // 3. Write mutates file state
    write(fd, "hello\n", 6);

    // 4. Justified fstat following mutation -> should NOT be flagged
    fstat(fd, &st);

    // 5. Seek to beginning (offset was 6, becomes 0)
    lseek(fd, 0, SEEK_SET);

    // 6. Redundant lseek (offset is already 0) -> should be flagged
    lseek(fd, 0, SEEK_SET);

    // 7. Read moves offset to 2
    char buf[4];
    read(fd, buf, 2);

    // 8. Justified lseek (offset was 2, now rewind to 0) -> should NOT be flagged
    lseek(fd, 0, SEEK_SET);

    // 9. First close
    close(fd);

    // 10. Redundant / double close -> should be flagged as use-after-close error
    close(fd);

    unlink(tmpfile);
    return 0;
}
