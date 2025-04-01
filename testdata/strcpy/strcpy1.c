#include <stdio.h>
#include <string.h>

void main(){
    char s1[5] = "zzzzz";
    char s2[] = "abcdefghijklmno";

    strcpy(s1, s2);
    printf("s1: %s\n", s1);
}
