#include <stdio.h>
#include <string.h>

int main () {
    char s1[5] = "zzzzz";  
    char s2[] = "abcdefghijklmno";
    strncpy(s1, s2, 3);
    printf("s1: %s\n", s1);
}
