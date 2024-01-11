#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define STRING_MAX_LEN 1024

#define equals(debugger_command,b) strcmp(debugger_command,b) == 0

int main( int argc, char *argv[] )  {
    printf("--- Linux debugger init ---\n");

    // Verify i am root
    if(getuid() != 0)
    {
        printf("[X] YOU ARE NOT ROOT!\n");
        return 0;
    }

    printf("[-] Type \"exit\" to exit\n");
    char raw_user_input[STRING_MAX_LEN];

    long unsigned int working_pid = 0;

    // Get user input
    while (NULL == NULL)
    {
        printf(">>> ");
        fgets(raw_user_input, STRING_MAX_LEN, stdin);

        
        char* user_input = strtok(raw_user_input, "\n");
        char* debugger_command = strtok(user_input, " ");
        // printf("Debugger command is : \"%s\"\n", debugger_command);

        if(equals(debugger_command, "exit")) {
            printf("[-] Leaving, bye!\n");
            return 0;

        } else if (equals(debugger_command, "help")) {
            printf("\n--- Linux Debugger Help Page ---\n");
            printf("  help              - Display the help page\n");
            printf("  pid <pid>         - Set\\Get the pid of the process to work on\n");
            printf("  attach            - attaches to the process\n");
            printf("  detach            - detach from the process\n");
            printf("\n");

        } else if (equals(debugger_command, "attach")) {
            long attach_ret_val = ptrace(PTRACE_ATTACH, working_pid, 0, 0);
            if(attach_ret_val == -1)
                printf("[X] An error occured in PTRACE_ATTACH: %s\n", strerror(errno));
            else {
                printf("[-] Attach return value: %ld\n", attach_ret_val);
                printf("[V] Attached succesfully!\n");
            }

        } else if (equals(debugger_command, "detach")) {
            long detach_ret_val = ptrace(PTRACE_DETACH, working_pid, 0, 0);
            if(detach_ret_val == -1)
                printf("[X] An error occured in PTRACE_DETACH: %s\n", strerror(errno));
            else {
                printf("[-] Detach return value: %ld\n", detach_ret_val);
                printf("[V] Detached succesfully!\n");
            }

        } else if (equals(debugger_command, "pid")) {
            // Passing NULL to strtok just continues iterating over the last
            // string that strtok was called on, kinda weird but works
            char* pid_string = strtok(NULL, " ");
            if (pid_string == NULL || equals(pid_string, "")) {
                if (working_pid == 0) {
                    printf("[-] Working pid not set\n");
                } else {
                    printf("[-] Working pid is : %ld\n", working_pid);
                }
            } else {
                int pid = atoi(pid_string);
                working_pid = pid;
            }
        }
    }

    return 0;
}