#include <assert.h>
#include <stddef.h>  // For NULL
#include <stdio.h>

char *strncat(char *dest, const char *src, size_t n) {
    assert(dest != NULL && src != NULL);

    char *temp = dest;

    while (*dest) {
        dest++;
    }

    while (n-- && *src) {
        *dest++ = *src++;
    }

    *dest = '\0';

    return temp;
}

int main() {
    char s1[5] = "zzzzz";
    char s2[] = "AAAAAAAAAAAAAAAAAAAA";

    strncat(s1, s2, 20);

    printf("s1: %s\n", s1);

    return 0;
}

