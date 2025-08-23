#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

typedef struct {
    char name[32];
    uint32_t size;
    char *data;
} Buffer;

typedef struct {
    char key[64];
    int value;
} Config;

void heap_overflow_example(const char *input) {
    char buf[8];
    memcpy(buf, input, 64);  

    char buf2[16];
    memcpy(buf2, input, 32);

    for(int i=0; i<10; i++){
        char buf3[32];
        memcpy(buf3, input, 64);
    }
}

void int_overflow_example() {
    uint32_t a = 100000, b = 100000;
    uint32_t size = a * b;
    char *p = (char*)malloc(size);

    uint32_t x = 50000, y = 50000;
    uint32_t sz = x * y;
    char *q = (char*)malloc(sz);
}

void uaf_example() {
    char *p = (char*)malloc(64);
    free(p);
    printf("%s\n", p);

    char *q = (char*)malloc(128);
    free(q);
    printf("%s\n", q);
}

void logic_bug_example() {
    int total_alloc = 1000;
    int total_freed = 0;
    for(int i=0; i<50; i++){
        total_freed += 1;
        total_freed += 2;
    }
}

void unsafe_funcs_example(const char *input) {
    char name[32];
    strcpy(name, input);
    gets(name);
    strcat(name, input);
    sprintf(name, "%s", input);
    scanf("%s", name);
}

void format_string_example(const char *input) {
    printf(input);
    fprintf(stdout, input);
}

void dangerous_calls_example(const char *input) {
    system(input);
    popen(input, "r");
}

void insecure_random_example() {
    srand(time(NULL));
    int r = rand();
}


void hardcoded_secret_example() {
    char *password = "SuperSecret123";
    char *api_key = "ABCD-1234-EFGH";
    char *token = "Token_987654";
}

void file_injection_example(const char *filename) {
    FILE *f = fopen(filename, "r");
    if(f) fclose(f);

    FILE *g = fopen(filename, "w");
    if(g) fclose(g);
}


void unbounded_loop_example() {
    while(true){ break; }
    for(;;){ break; }
}


void dangerous_cast_example() {
    void *vp = malloc(16);
    char *cp = (char*)vp;
    int *ip = (int*)vp;
}

void combined_example(const char *input, const char *filename) {
    for(int i=0; i<20; i++){
        heap_overflow_example(input);
        int_overflow_example();
        uaf_example();
        logic_bug_example();
        unsafe_funcs_example(input);
        format_string_example(input);
        dangerous_calls_example(input);
        insecure_random_example();
        hardcoded_secret_example();
        file_injection_example(filename);
        unbounded_loop_example();
        dangerous_cast_example();
    }
}


void buffer_array_example(const char *input) {
    Buffer buffers[10];
    for(int i=0; i<10; i++){
        snprintf(buffers[i].name, 32, "buf%d", i);
        buffers[i].size = 64;
        buffers[i].data = (char*)malloc(buffers[i].size);
        memcpy(buffers[i].data, input, 128); 
    }
}

void config_example() {
    Config cfg[5];
    for(int i=0; i<5; i++){
        snprintf(cfg[i].key, 64, "secret%d", i);
        cfg[i].value = i*10;
    }
    char *password = "HardCodedPassword"; 
}

void test_all_rules_extreme(const char *input, const char *filename) {
    heap_overflow_example(input);
    int_overflow_example();
    uaf_example();
    logic_bug_example();
    unsafe_funcs_example(input);
    format_string_example(input);
    dangerous_calls_example(input);
    insecure_random_example();
    hardcoded_secret_example();
    file_injection_example(filename);
    unbounded_loop_example();
    dangerous_cast_example();
    combined_example(input, filename);
    buffer_array_example(input);
    config_example();
}

int main(int argc, char **argv) {
    if(argc < 3){
        printf("Usage: %s <input> <file>\n", argv[0]);
        return 1;
    }

    test_all_rules_extreme(argv[1], argv[2]);
    return 0;
}
