#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

void test_all_rules(const char *user_input, const char *filename) {
    // HEAP_OVERFLOW
    char buf1[8];
    memcpy(buf1, user_input, 64); 

    char buf2[16];
    memcpy(buf2, user_input, 32); 

    char buf3[32];
    memcpy(buf3, user_input, 64);

    // INT_OVERFLOW
    uint32_t a = 100000, b = 100000;
    uint32_t size1 = a * b;
    char *p1 = (char*)malloc(size1);

    uint32_t x = 50000, y = 50000;
    uint32_t size2 = x * y;
    char *p2 = (char*)malloc(size2);

    // UAF
    free(p1);
    printf("%s\n", p1);  

    free(p2);
    printf("%s\n", p2);

    // LOGIC_BUG
    int total_alloc = 100, total_freed = 0;
    total_freed += 1;  
    total_freed += 2;
    total_freed += 3;

    // UNSAFE_FUNCS
    char name1[32];
    strcpy(name1, user_input);  
    gets(name1);                

    char name2[64];
    strcat(name2, user_input);
    sprintf(name2, "%s", user_input);

    scanf("%s", name2);

    // FORMAT_STRING
    printf(user_input);     
    fprintf(stdout, user_input);

    // DANG_CALL
    system(user_input);     
    popen(user_input, "r"); 

    // INSECURE_RANDOM
    srand(time(NULL));
    int r1 = rand();
    int r2 = rand();

    // HARDCODED_SECRET
    char *password1 = "SuperSecret123"; 
    char *api_key = "ABCD-1234-EFGH";

    // FILE_INJECTION
    FILE *f1 = fopen(filename, "r"); 
    if (f1) fclose(f1);

    FILE *f2 = fopen(filename, "w");
    if (f2) fclose(f2);

    // UNBOUNDED_LOOP
    while (true) { break; }
    for(;;) { break; }

    // DANG_CAST
    void *vp1 = malloc(16);
    char *cp1 = (char*)vp1; 

    void *vp2 = malloc(32);
    int *ip1 = (int*)vp2;


    for(int i=0; i<20; i++) {
        char buf[16];
        memcpy(buf, user_input, 32);
        uint32_t n = 1000, m = 1000;
        uint32_t sz = n*m;
        char *p = (char*)malloc(sz);
        free(p);
        printf("%s\n", p);

        char unsafe[32];
        strcpy(unsafe, user_input);
        gets(unsafe);
        printf(user_input);

        system(user_input);
        srand(time(NULL));
        int r = rand();
        char *secret = "HardCodedSecret";
        FILE *f = fopen(filename, "r");
        if(f) fclose(f);
        while(true) { break; }
        void *v = malloc(16);
        char *c = (char*)v;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <input> <file>\n", argv[0]);
        return 1;
    }
    test_all_rules(argv[1], argv[2]);
    return 0;
}
