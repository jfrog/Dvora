#include <stdio.h>
#include <string.h>

void main(){
    char s1[5] = "zzz";
    char s2[] = "abcdefghijklmno";

    strcat(s1, s2);
    printf("s1: %s\n", s1);
}
