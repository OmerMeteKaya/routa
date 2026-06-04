#ifndef __AFL_HAVE_MANUAL_CONTROL
#  define __AFL_FUZZ_INIT()
#  define __AFL_INIT()
#  define __AFL_LOOP(x)           0
   static unsigned char __afl_buf[1 << 20];
static size_t        __afl_len = 0;
#  define __AFL_FUZZ_TESTCASE_BUF __afl_buf
#  define __AFL_FUZZ_TESTCASE_LEN __afl_len
#endif

#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
/* Reuse libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

__AFL_FUZZ_INIT();

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
