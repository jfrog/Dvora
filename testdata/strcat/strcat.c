#include <assert.h>
#include <stddef.h>  // For NULL
#include <stdio.h>

char *strcat(char *dest, const char *src) {
    assert(dest != NULL && src != NULL);

    char *temp = dest;

    // Move to end of `dest`
    while (*dest) {
        dest++;
    }

    // Copy `src` to `dest`
    while ((*dest++ = *src++) != '\0');

    return temp;
}

int main() {
    char s1[5];
    char s2[] = "AAAAAAAABBBBBBBBCCCCCCCC";

    strcat(s1, s2);

    printf("s1: %s\n", s1);

    return 0;
}

