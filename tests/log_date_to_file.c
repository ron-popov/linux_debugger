#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>

int main (void) {
    char buff[20];
    struct tm *sTm;

    time_t now = time(0);
    sTm = gmtime(&now);

    printf("Got time struct\n");

    FILE* log_file_fd = fopen("/tmp/aaa", "w+");

    if (log_file_fd == NULL) {
        printf("Log file FD is NULL\n");
        printf("Errno is : %s\n", strerror(errno));
        return 0;
    }

    printf("Opened log file FD\n");

    strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", sTm);

    printf("Formatted datetime string\n");

    fprintf(log_file_fd, "%s\n", buff);

    printf("Written datetime to file\n");

    fclose(log_file_fd);

    printf("Closed log file FD\n");

    return 0;
}
