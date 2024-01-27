#include <stdio.h>
#include <time.h>

int main (void) {
    char buff[20];
    struct tm *sTm;

    time_t now = time(0);
    sTm = gmtime(&now);

    FILE* log_file_fd = fopen("/tmp/log_and_run.log", "a");

    strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", sTm);
    fprintf(log_file_fd, "%s\n", buff);

    fclose(log_file_fd);

    return 0;
}
