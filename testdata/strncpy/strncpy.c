#include <assert.h>
#include <stddef.h>
#include <stdio.h>

char *strncpy(char *dest, const char *src, size_t n) {
    assert(dest != NULL && src != NULL); 

    char *original_dest = dest; 
    size_t i;


    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }


    for (; i < n; i++) {
        dest[i] = '\0';
    }

    return original_dest; 
}

int main() {
    char s1[6];
    char s2[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE";

    strncpy(s1, s2, 3);

    printf("s1: %s\n", s1);

    return 0;
}

