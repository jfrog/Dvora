#include <assert.h>
#include <stddef.h>  // or #include <stdio.h>

char *strcpy(char *strDest, const char *strSrc) {
    assert(strDest != NULL && strSrc != NULL);
    
    char *temp = strDest;
    
    while ((*strDest++ = *strSrc++) != '\0');
    
    return temp;
}

int main() {
    char s1[6];
    char s2[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    strcpy(s1, s2);
    printf("s1: %s\n", s1);

    return 0;
}

