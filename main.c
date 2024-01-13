#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

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

    long unsigned int working_pid = 0;

    char raw_user_input[STRING_MAX_LEN];
    printf("[-] Type \"exit\" to exit\n");

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

        if (debugger_command == NULL) {
            continue;
        } else if(equals(debugger_command, "exit")) {
            printf("[-] Leaving, bye!\n");
            return 0;

        } else if (equals(debugger_command, "help")) {
            printf("\n--- Linux Debugger Help Page ---\n");
            printf("  help              - Display the help page\n");
            printf("  attach <pid>      - attaches to the specified\n");
            printf("  detach            - detach from currently attached process\n");
            printf("  diss              - Print instruction pointer and current instructions\n");
            printf("  run <program>     - Run a program and attach self to it\n");
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
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to detach!\n");
                continue;
            }

            long detach_ret_val = ptrace(PTRACE_DETACH, working_pid, 0, 0);
            if(detach_ret_val == -1)
                printf("[X] An error occured in PTRACE_DETACH: %s\n", strerror(errno));
            else {
                printf("[-] Detach return value: %ld\n", detach_ret_val);
                printf("[V] Detached succesfully!\n");
                working_pid = 0;
            }
        } else if (equals(debugger_command, "run")) {
            // Running strtok with null will continue off from the last strtok
            char* shell_command = strtok(NULL, " ");

            // Here we do strtok with NULL to continue parsing the last string 
            // but with empty delimeter to reach the end of the string
            char* arguments = strtok(NULL, "");
            char *newargv[] = { NULL, arguments, NULL };


            printf("[-] Command to execute is : \"%s %s\"\n", shell_command, arguments);

            // long execve_ret_val = execve(shell_command, newargv, NULL);
            // printf("Execve return value : %ld\n", execve_ret_val);
            // printf("Errno is : %s\n", strerror(errno));

            long fork_ret_val = fork();

            if (fork_ret_val == 0) {
                printf("This is forked\n");
                // This is the forked process, i am not doing anything with the return value
                // Because i have nothing to do with it (this is the forked process)

                // TRACE_ME
                // long traceme_ret_val = ptrace(PTRACE_TRACEME);

                // EXECVE
                // long execve_ret_val = execve(shell_command, newargv, NULL);
                execve(shell_command, NULL, NULL);

            } else if (fork_ret_val == -1) {
                printf("[X] Fork failed with errno : %d\n", errno);
                continue;

            } else {
                // This is the original flow

                // Trace the process, it should have executed traceme so we could trace it
                // long attach_ret_val = ptrace(PTRACE_ATTACH, fork_ret_val, 0, 0);
                // if(attach_ret_val == -1)
                //     printf("[X] An error occured in PTRACE_ATTACH: %s\n", strerror(errno));
                // else {
                //     printf("[V] Attached succesfully!\n");
                //     working_pid = fork_ret_val;
                // }
            }

        } else if (equals(debugger_command, "diss")) {
            // Make sure there is a process attached by the debugger
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to disassemble!\n");
                continue;
            }


            // Find value of RIP - instruction pointer
            long unsigned int rip_addr_in_user_section = __builtin_offsetof(struct user, regs.rip);
            long debugged_process_ip = ptrace(PTRACE_PEEKUSER, working_pid, rip_addr_in_user_section, 0);
            if(debugged_process_ip == -1) {
                printf("[x] An error occured when finding RIP: %s\n", strerror(errno));
                continue;
            }

            for(int i = 0; i < 8; i++) {
                // Check current instruction
                long targer_addr = debugged_process_ip + i*4;
                unsigned long instructions = ptrace(PTRACE_PEEKDATA, working_pid, targer_addr, 0);
                if(instructions == -1) {
                    printf("[x] An error occured in finding current instrucion: %s\n", strerror(errno));
                    continue;
                } else {
                    printf(
                        "0x%08lx - 0x%02X 0x%02X 0x%02X 0x%02X\n", 
                        targer_addr, 
                        (unsigned int) (instructions % 0x0100), 
                        (unsigned int) (instructions % 0x010000 / 0x0100),
                        (unsigned int) (instructions % 0x01000000 / 0x010000),
                        (unsigned int) (instructions % 0x0100000000 / 0x01000000)
                    );
                }

            }
        } else {
            printf("[X] Unknown command : \"%s\"\n", debugger_command);
        }
    }

    return 0;
}