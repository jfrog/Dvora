#include <stddef.h>

int strcmp(const char *s1, const char *s2) {
    while (*s1 != '\0' && *s2 != '\0') {
        if (*s1 != *s2) {
            return (*s1 - *s2);
        }
        s1++;
        s2++;
    }
    
    return (*s1 - *s2);
}

void main(){
    char s1[] = "AAAAA";
    char s2[5] = "AAAAA";
    int result = strcmp(s1, s2);
    
    if (result < 0) {
        printf("s1 < s2\n");
    } else if (result > 0) {
        printf("s1 > s2\n");
    } else {
        printf("s1 == s2\n");
    }
    
    return 0;
}
