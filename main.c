#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>


int main( int argc, char *argv[] )  {
    printf("[v] Linux debugger init\n");

    int debugged_process_pid;

    // Should get 1 param (pid)
    if(argc == 1)
    {
        // TODO: Make help page prettier
        printf("[x] Not enough parameters passed!\n");
        printf("[x] Usage: ./debugger <pid>\n");
        return 0;
    }
    else if(argc == 2)
    {
        debugged_process_pid = atoi(argv[1]);
        printf("[-] Debugged process PID: %d\n", debugged_process_pid);
    }
    else
    {
        printf("[x] Too much arguments passed\n");
        printf("[x] Usage: ./debugger <pid>\n");
        return 0;
    }


    // PTrace the debugged process
    long ptrace_return_value = ptrace(PTRACE_PEEKUSER, debugged_process_pid, 1, 0);

    if(ptrace_return_value == -1)
    {
        printf("[x] An error occured in PTRACE: %s\n", strerror(errno));
    }
    else
    {
        printf("[-] Ptrace return value: %ld\n", ptrace_return_value);
    }

    return 0;
}