/******************************************************************************
# gcc -Wall main.c -lcrypt
# ./a.out
$6$8n./Hzqd$1ufKVaxlFjW3X8OcAgMbVX8UF6fx7HEEmhmS1zrj/M.AfmXt2Jla0tAOvfYAz0oxb10TeqPKxHuZtWT2c5SaK/
******************************************************************************/

#define SALT "8n./Hzqd"
#define PASSWORD "This is my password!"

#include <stdio.h>

char *crypt(const char *key, const char *salt);

int main(void)
{
    printf("%s\n", crypt(PASSWORD, "$6$" SALT));
    return 0;
}
