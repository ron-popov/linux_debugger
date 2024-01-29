#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STRING_MAX_LEN 1024

#define equals(a,b) strcmp(a,b) == 0

int main( int argc, char *argv[] )  {
    printf("--- Linux debugger init ---\n");

    // Verify i am root
    if(getuid() != 0)
    {
        printf("[X] YOU ARE NOT ROOT!\n");
        return 0;
    }

    // Running strtok with null will continue off from the last strtok
    // char* shell_command = "/home/ron_popov/linux_debugger/build/hello_world";
    char* shell_command = "/home/ron_popov/linux_debugger/build/log_date_to_file";

    // Here we do strtok with NULL to continue parsing the last string 
    // but with empty delimeter to reach the end of the string
    printf("[-] Executing : \"%s\"\n", shell_command);

    long fork_ret_val = fork();

    if (fork_ret_val == 0) {
        // This is the forked process, i am not doing anything with the return value
        // Because i have nothing to do with it (this is the forked process)

        // Disable stdout for forked process
        // freopen("/dev/null", "w", stdout);

        // TRACE_ME
        long traceme_ret_val = ptrace(PTRACE_TRACEME);
        // long traceme_ret_val = ptrace(PTRACE_TRACEME, PTRACE_O_TRACEEXEC);

        // EXECVE
        execve(shell_command, NULL, NULL);

    } else if (fork_ret_val == -1) {
        printf("[X] Fork failed with errno : %d\n", errno);

    } else {
        // This is the original flow
        printf("[V] Forked process pid is %d\n", fork_ret_val);

        int wait_pid_status = 0;

        waitpid(fork_ret_val, &wait_pid_status, 0);
        printf("[-] waitpid status : %d\n", wait_pid_status);
        // sleep(5);

        if (!(WIFSTOPPED(wait_pid_status) && WSTOPSIG(wait_pid_status) == SIGTRAP)) {
            printf("[X] Process is in weird state...\n");
        }

        printf("[-] WIFSTOPPED : %d\n", WIFSTOPPED(wait_pid_status));
        printf("[-] WSTOPSIG : %d\n", WSTOPSIG(wait_pid_status));
        

        // waitpid(fork_ret_val)

        // printf("[-] Sleeping for 5 seconds\n");
        // sleep(1);
        // printf("[-] Done sleeping\n");

        // long set_options_ret_val = ptrace(PTRACE_SETOPTIONS, fork_ret_val, 0, PTRACE_O_TRACEEXEC);
        // printf("[-] PTRACE SETOPTIONS return val : %d\n", set_options_ret_val);

        // printf("[x] An error occured when settings ptrace options: %s\n", strerror(errno));

        long continue_ret_val = ptrace(PTRACE_CONT, fork_ret_val, 0, 0);
        if(continue_ret_val == -1) {
            printf("[x] An error occured when trying to continue: %s\n", strerror(errno));
        } else {
            printf("[V] Continuing process\n");
        }
    }

    return 0;
}

