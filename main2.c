//
// $ gcc main2.c -std=c11 -Wall -lcrypt
// $ ./a.out
// $6$ziqjIomt8n./Hzqd$p0Nb/vCETx2HEKdDrlYyPrKx2axug6s6tLx6hqgfsw9ex0mQXNh9bQ2kXnHDmd/j6JdTprCuEqNZrnhDkCidj.
//
// $ ./pencrypter.py --salt ziqjIomt8n./Hzqd --password test
// $6$ziqjIomt8n./Hzqd$p0Nb/vCETx2HEKdDrlYyPrKx2axug6s6tLx6hqgfsw9ex0mQXNh9bQ2kXnHDmd/j6JdTprCuEqNZrnhDkCidj.
//

#define _XOPEN_SOURCE

#include <stdio.h>

#include <unistd.h>

int main(void)
{
        char *result = crypt("test2", "$6$ziqjIomt8n./Hzqd$");
        printf("%s\n", result);
        return 0;
}

