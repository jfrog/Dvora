#include <stddef.h>

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n > 0 && *s1 != '\0' && *s2 != '\0') {
        if (*s1 != *s2) {
            return (*s1 - *s2);
        }
        s1++;
        s2++;
        n--;
    }
    
    if (n == 0) {
        return 0;
    }
    
    return (*s1 - *s2);
}

void main(){
    char s1[5] = "AAAA";
    char s2[] = "AAAAAAA";
    int result = strncmp(s1, s2, 4);

    if (result < 0) {
        printf("s1 < s2\n");
    } else if (result > 0) {
        printf("s1 > s2\n");
    } else {
        printf("s1 == s2\n");
    }

    return 0;
}
