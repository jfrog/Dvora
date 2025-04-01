#include <stdio.h>
#include <string.h>

int main(){
    char s1[] = "AAAAAABBBB";
    char s2[5] = "AAAAAAA";

    printf("%d\n", strncmp(s1, s2, 7));

    return 0;
}
