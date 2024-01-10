#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int main( int argc, char *argv[] )  {
    printf("[v] Linux debugger init\n");

    int debugged_process_pid;

    // Should get 1 param (pid)
    if(argc == 1) {
        printf("[x] Not enough parameters passed!\n");
        printf("[x] Usage: ./debugger <pid>\n");
        return 0;
    } else if(argc == 2) {
        debugged_process_pid = atoi(argv[1]);
        printf("[-] Debugged process PID: %d\n", debugged_process_pid);
    } else {
        printf("[x] Too much arguments passed\n");
        printf("[x] Usage: ./debugger <pid>\n");
        return 0;
    }


    // PTRACE_ATTACH the debugged process
    long ptrace_attach_ret_val = ptrace(PTRACE_ATTACH, debugged_process_pid, 0, 0);
    if(ptrace_attach_ret_val == -1)
        printf("[x] An error occured in PTRACE_ATTACH: %s\n", strerror(errno));
    else
        printf("[-] PTRACE_ATTACH return value: %ld\n", ptrace_attach_ret_val);


    // Get current RIP - instruction pointer
    long unsigned int target_addr = __builtin_offsetof(struct user, regs.rip);
    long debugged_process_ip = ptrace(PTRACE_PEEKUSER, debugged_process_pid, target_addr, 0);
    if(debugged_process_ip == -1) {
        printf("[x] An error occured in PTRACE_PEEKUSER: %s\n", strerror(errno));
    } else {
        printf("[-] PTRACE_PEEKUSER return value: %ld\n", debugged_process_ip);
    }

    // Check current instruction
    


    // Detach from process
    // long ptrace_detach_return_value

    return 0;
}