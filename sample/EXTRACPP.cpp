#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

void buffer_overflow_demo(const char *input) {
    char buf[10];
    strcpy(buf, input); 
}

void gets_demo() {
    char buf[10];
    gets(buf);
}

void strcat_demo() {
    char dst[20];
    strcpy(dst, "this is too long for dst");
    strcat(dst, " more data");
}

void sprintf_demo(const char *input) {
    char buf[20];
    sprintf(buf, "%s", input);
}

void scanf_demo() {
    char user_input[50];
    scanf("%s", user_input);
    printf(user_input); 
}

void system_demo() {
    system("ls -la");
    popen("echo vulnerable", "r");
}

void random_demo() {
    int r = rand();
    srand(1234);
    printf("Rand=%d\n", r);
}

void secrets_demo() {
    const char* password = "SuperSecret123!";
    const char* api_key = "AKIA1234567890FAKE";
    printf("pw=%s key=%s\n", password, api_key);
}

void int_overflow_demo() {
    uint32_t a = 60000, b = 60000;
    uint32_t sz = a * b; // overflow
    char *p = (char*)malloc(sz);
    if (p) free(p);
}

void uaf_demo() {
    char *p = (char*)malloc(32);
    free(p);
    printf("Use-after-free: %s\n", p);
}

void repeat_block(int id, const char *arg) {
    buffer_overflow_demo(arg);
    gets_demo();
    strcat_demo();
    sprintf_demo(arg);
    scanf_demo();
    system_demo();
    random_demo();
    secrets_demo();
    int_overflow_demo();
    uaf_demo();
    printf("Repeat %d done\n", id);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    for (int i = 0; i < 25; i++) {
        repeat_block(i, argv[1]);
    }

    return 0;
}
