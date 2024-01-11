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
        if (working_pid == 0) {
            printf(">>> ");
        } else {
            printf("(%ld) >>> ", working_pid);
        }

        fgets(raw_user_input, STRING_MAX_LEN, stdin);

        
        char* user_input = strtok(raw_user_input, "\n");
        char* debugger_command = strtok(user_input, " ");

        if(equals(debugger_command, "exit")) {
            printf("[-] Leaving, bye!\n");
            return 0;

        } else if (equals(debugger_command, "help")) {
            printf("\n--- Linux Debugger Help Page ---\n");
            printf("  help              - Display the help page\n");
            printf("  attach <pid>      - attaches to the specified\n");
            printf("  detach            - detach from currently attached process\n");
            printf("\n");

        } else if (equals(debugger_command, "attach")) {
            char* pid_string = strtok(NULL, " ");
            int pid = atoi(pid_string);

            long attach_ret_val = ptrace(PTRACE_ATTACH, pid, 0, 0);
            if(attach_ret_val == -1)
                printf("[X] An error occured in PTRACE_ATTACH: %s\n", strerror(errno));
            else {
                printf("[-] Attach return value: %ld\n", attach_ret_val);
                printf("[V] Attached succesfully!\n");
                working_pid = pid;
            }

        } else if (equals(debugger_command, "detach")) {
            long detach_ret_val = ptrace(PTRACE_DETACH, working_pid, 0, 0);
            if(detach_ret_val == -1)
                printf("[X] An error occured in PTRACE_DETACH: %s\n", strerror(errno));
            else {
                printf("[-] Detach return value: %ld\n", detach_ret_val);
                printf("[V] Detached succesfully!\n");
                working_pid = 0;
            }
        } else {
            printf("[X] Unknown command : \"%s\"\n", debugger_command);
        }
    }

    return 0;
}