#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    // 1. Allocate writable memory
    size_t sz = 4096;
    char *p = (char *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;

    // 2. Write shellcode signature into region
    const char shellcode[] = "\x90\x90\x90\x31\xc0\x48\x31\xd2\xcc\xc3OVERSEER_SHELLCODE_SIGNATURE";
    memcpy(p, shellcode, sizeof(shellcode));

    // 3. Suspicious transition to EXECUTABLE (mprotect with PROT_EXEC) -> should be detected & dumped!
    mprotect(p, sz, PROT_READ | PROT_EXEC);

    // 4. Suspicious RWX allocation (mmap with PROT_READ|PROT_WRITE|PROT_EXEC) -> should be detected & dumped!
    char *rwx = (char *)mmap(NULL, sz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rwx != MAP_FAILED) {
        memcpy(rwx, "RWX_PAYLOAD_TEST", 16);
        munmap(rwx, sz);
    }

    munmap(p, sz);
    return 0;
}
