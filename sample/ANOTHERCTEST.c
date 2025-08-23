#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

void test_all_rules_extreme(const char *user_input, const char *filename) {
    
    // HEAP_OVERFLOW examples
    for(int i=0; i<50; i++){
        char buf[8];
        memcpy(buf, user_input, 64); 
    }
    for(int i=0; i<50; i++){
        char buf16[16];
        memcpy(buf16, user_input, 32); 
    }
    for(int i=0; i<50; i++){
        char buf32[32];
        memcpy(buf32, user_input, 64); 
    }
    for(int i=0; i<50; i++){
        char buf64[64];
        memcpy(buf64, user_input, 128); 
    }

    // INT_OVERFLOW examples

    for(int i=0; i<30; i++){
        uint32_t a = 100000, b = 100000;
        uint32_t size = a*b;
        char *p = (char*)malloc(size);
    }
    for(int i=0; i<30; i++){
        uint32_t x = 50000, y = 50000;
        uint32_t sz = x*y;
        char *p = (char*)malloc(sz);
    }
    for(int i=0; i<30; i++){
        uint32_t m = 300000, n = 300000;
        uint32_t size = m*n;
        char *p = (char*)malloc(size);
    }

    // USE-AFTER-FREE (UAF)

    char *uaf1 = (char*)malloc(64);
    free(uaf1);
    printf("%s\n", uaf1);

    char *uaf2 = (char*)malloc(128);
    free(uaf2);
    printf("%s\n", uaf2);

    char *uaf3 = (char*)malloc(256);
    free(uaf3);
    printf("%s\n", uaf3);

    for(int i=0; i<20; i++){
        char *tmp = (char*)malloc(32);
        free(tmp);
        printf("%s\n", tmp);
    }

    // LOGIC_BUG examples

    int total_alloc = 1000, total_freed = 0;
    for(int i=0; i<100; i++){
        total_freed += 1;
        total_freed += 2;
        total_freed += 3;
    }

    // UNSAFE_FUNCS examples

    for(int i=0; i<50; i++){
        char name[32];
        strcpy(name, user_input);
        gets(name);
        strcat(name, user_input);
        sprintf(name, "%s", user_input);
        scanf("%s", name);
    }

    // FORMAT_STRING examples

    for(int i=0; i<50; i++){
        printf(user_input);
        fprintf(stdout, user_input);
    }
    // DANGEROUS CALLS
    for(int i=0; i<50; i++){
        system(user_input);
        popen(user_input, "r");
    }
    // INSECURE_RANDOM
    for(int i=0; i<50; i++){
        srand(time(NULL));
        int r = rand();
    }

    // HARDCODED_SECRET

    for(int i=0; i<50; i++){
        char *password = "SuperSecret123";
        char *api_key = "ABCD-1234-EFGH";
        char *token = "Token_987654";
    }

    // FILE_INJECTION
    for(int i=0; i<50; i++){
        FILE *f = fopen(filename, "r");
        if(f) fclose(f);
    }
    for(int i=0; i<50; i++){
        FILE *f = fopen(filename, "w");
        if(f) fclose(f);
    }
    // UNBOUNDED_LOOP
    for(int i=0; i<50; i++){
        while(true){ break; }
        for(;;){ break; }
    }

    // DANGEROUS CAST
    for(int i=0; i<50; i++){
        void *vp = malloc(16);
        char *cp = (char*)vp;
        int *ip = (int*)vp;
    }

   
    // Combine multiple vulnerabilities

    for(int i=0; i<20; i++){
        char buf[32];
        memcpy(buf, user_input, 64);  // HEAP_OVERFLOW
        uint32_t a=10000, b=10000;
        uint32_t sz = a*b;  // INT_OVERFLOW
        char *p = (char*)malloc(sz);
        free(p);
        printf("%s\n", p);  // UAF

        char name[32];
        strcpy(name, user_input);  // UNSAFE_FUNCS
        gets(name);               // UNSAFE_FUNCS
        printf(user_input);       // FORMAT_STRING
        system(user_input);       // DANG_CALL
        srand(time(NULL));        // INSECURE_RANDOM
        int r = rand();           // INSECURE_RANDOM
        char *secret = "HardCodedSecret"; // HARDCODED_SECRET
        FILE *f = fopen(filename, "r");     // FILE_INJECTION
        if(f) fclose(f);
        while(true){ break; }     // UNBOUNDED_LOOP
        void *v = malloc(16); 
        char *c = (char*)v;       // DANG_CAST
    }
}

int main(int argc, char **argv) {
    if(argc < 3){
        printf("Usage: %s <input> <file>\n", argv[0]);
        return 1;
    }
    test_all_rules_extreme(argv[1], argv[2]);
    return 0;
}
