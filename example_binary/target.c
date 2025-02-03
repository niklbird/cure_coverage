#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void branch1(int x) {
    if (x % 2 == 0) {
        printf("Branch 1A taken\n");
    } else {
        printf("Branch 1B taken\n");
    }
}

void branch2(int x) {
    if (x > 50) {
        printf("Branch 2A taken\n");
    } else {
        printf("Branch 2B taken\n");
    }
    sleep(1);
}

void branch3(int x) {
    if (x == 42) {
        printf("Magic number found! Special path!\n");
    } else {
        printf("Branch 3 taken\n");
    }
    sleep(1);
}

int main(int argc, char *argv[]) {
    int x = 0;

    if (argc > 1) {
        x = atoi(argv[1]);
    } else {
        printf("Usage: %s <number>\n", argv[0]);
        return 1;
    }

    printf("Processing input: %d\n", x);

    branch1(x);
    branch2(x);
    branch3(x);
    // int i = 0;
    for(int i = 0; i < 300; i++){
        branch1(x);

    }

    printf("Execution complete.\n");
    return 0;
}
