#include <stdio.h>
#include <string.h>

int main(){
    char s1[] = "AAAAA";
    char s2[5] = "AAAAA";

    printf("%d\n", strcmp(s1, s2));

    return 0;
}
