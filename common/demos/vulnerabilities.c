/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2018 Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <windows.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

typedef enum { SIMPLE_STACK_SMASHING = 0, FUNCTION_PTR_OVERWRITE } vuln_type_t;

static bool make_stack_executable(void) {
    int x = 0;
    DWORD old_protect;
    uintptr_t xp = (uintptr_t) &x;
    return VirtualProtect((void *) (xp & ~0xfff), 0x1000, PAGE_EXECUTE_READWRITE, &old_protect) == TRUE;
}

static void demo_stack_smashing(FILE *fp) {
#if 0
    uint8_t buffer[32];

    printf("Demoing stack smashing\n");

    size_t to_read = sizeof(buffer) * 2;
    if (fread(buffer, to_read, 1, fp) != 1) {
        fprintf(stderr, "Could not read %d bytes\n", to_read);
        return;
    }
#endif
}

static int test_func(void) {
    return 42;
}

static void demo_function_ptr_overwrite(FILE *fp) {
    int (*f_ptr)(void) = test_func;
    char buffer[32];

    printf("Demoing function pointer overwrite\n");

    size_t to_read = sizeof(buffer) * 2;
    if (fread(buffer, to_read, 1, fp) != 1) {
        fprintf(stderr, "Could not read %d bytes\n", to_read);
        return;
    }

    int value = f_ptr();
    printf("value: %d\n", value);
}

static void demo(FILE *fp, vuln_type_t vuln_type) {
    switch (vuln_type) {
        case SIMPLE_STACK_SMASHING:
            demo_stack_smashing(fp);
            break;
        case FUNCTION_PTR_OVERWRITE:
            demo_function_ptr_overwrite(fp);
            break;
        default:
            fprintf(stderr, "Invalid demo type\n");
            break;
    }
}

int main(int argc, char **argv) {
    FILE *fp = NULL;
    int ret = -1;
    vuln_type_t vuln_type;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s input_file\n", argv[0]);
        goto err;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", argv[1]);
        goto err;
    }

    if (fread(&vuln_type, sizeof(vuln_type), 1, fp) != 1) {
        fprintf(stderr, "Could not read from file\n");
        goto err;
    }

    if (!make_stack_executable()) {
        fprintf(stderr, "Could not make stack executable\n");
        goto err;
    }

    demo(fp, vuln_type);

    ret = 0;

err:

    if (fp) {
        fclose(fp);
    }

    return ret;
}
