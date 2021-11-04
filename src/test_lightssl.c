#include <stdio.h>
#include "lightssl.h"

int main(int argc, char **argv) {
    if(argc != 1) {
        printf("%s takes no arguments.\n", argv[0]);
        return 1;
    }
    printf("This is a project\n");
    lightssl_init();

    return 0;
}
