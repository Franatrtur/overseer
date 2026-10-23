#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(void) {
    // Evasive anti-debugging trick: malware calls ptrace(PTRACE_TRACEME, ...)
    // If under debugger without spoofing: fails with -1 (EPERM).
    // If neutralized by Overseer: returns 0 (Success).
    long ret = ptrace(PTRACE_TRACEME, 0, 1, 0);

    if (ret != 0) {
        // Failed - debugger was detected and NOT neutralized
        return 42;
    }

    // Success - anti-debug check bypassed / neutralized!
    return 0;
}
