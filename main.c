#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "lib/Zydis/Zydis.c"
#include <inttypes.h>


#define STRING_MAX_LEN 1024
#define MAX_INSTRUCTION_LEN 16
#define OPCODE_BREAKPOINT 0xCC
#define OPCODE_NOP 0x90

#define equals(a,b) strcmp(a,b) == 0

typedef long unsigned int PID;
typedef unsigned long long ADDR;
typedef unsigned char BYTE;
typedef unsigned long long QWORD;
typedef uint64_t WORD;

// --- MEMORY STUFF ---
BYTE read_mem(PID pid, ADDR addr) {
    WORD result = ptrace(PTRACE_PEEKDATA, pid, addr, 0);

    if(result == -1) {
        printf("[x] An error occured during read for read: %s\n", strerror(errno));
        exit(0);
    }

    return result % 0x0100;
}

void write_mem(PID pid, ADDR addr, BYTE value) {
    // printf("[-] Writing in addr 0x%08X, value 0x%08X\n", addr, value);
    WORD result = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    printf("[-] Read in addr 0x%08X, value 0x%08X\n", addr, result);

    if(result == -1) {
        printf("[x] An error occured during read for write: %s\n", strerror(errno));
        exit(0);
    }

    result = result & 0xFFFFFFFFFFFFFF00;
    result += value;

    printf("[-] Writing to addr 0x%08X, value 0x%08X\n", addr, result);

    WORD write_mem_result = ptrace(PTRACE_POKEDATA, pid, addr, result);
    if (write_mem_result != 0) {
        printf("[x] An error occured during write for write: %s\n", strerror(errno));
        exit(0);
    }

}

// --- MAIN ---
int main( int argc, char *argv[] )  {
    printf("--- Linux debugger init ---\n");

    // Verify i am root
    if(getuid() != 0)
    {
        printf("[X] YOU ARE NOT ROOT!\n");
        return 0;
    }

    PID working_pid = 0;

    // Breakpoint stuff
    ADDR breakpoint_addr = 0;
    BYTE breakpoint_instruction_length = 0;
    BYTE original_instruction[MAX_INSTRUCTION_LEN];

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
            printf("  help                  - Display the help page\n");
            printf("  attach <pid>          - attaches to the specified\n");
            printf("  detach                - detach from currently attached process\n");
            printf("  diss                  - Disassemble the instructions about to be executed \n");
            printf("  diss_raw              - Print opcodes in addr of INSTRUCTION POINTER\n");
            printf("  diss_raw_addr <addr>  - Print opcodes in specified addr\n");
            printf("  run <program>         - Run a program and attach self to it (doesn't actually start running yet, run \"cont\")\n");
            printf("  break <addr>          - Set a breakpoint in memory address specified\n");
            printf("  clear                 - Remove all breakpoints\n");
            printf("  cont                  - Continue the program\n");
            printf("\n");

        } else if (equals(debugger_command, "attach")) {
            char* pid_string = strtok(NULL, " ");
            int pid = atoi(pid_string);

            QWORD attach_ret_val = ptrace(PTRACE_ATTACH, pid, 0, 0);
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

            // TODO : If process is defunct than detach will fail but the process is not dead
            // So it has to be killed by us

            QWORD detach_ret_val = ptrace(PTRACE_DETACH, working_pid, 0, 0);
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

            QWORD fork_ret_val = fork();

            if (fork_ret_val == 0) {
                // This is the forked process, i am not doing anything with the return value
                // Because i have nothing to do with it (this is the forked process)

                // Disable stdout for forked process
                freopen("/dev/null", "w", stdout);

                // TRACE_ME
                QWORD traceme_ret_val = ptrace(PTRACE_TRACEME);                

                // EXECVE
                // TODO: Implement support for command line arguments
                execve(shell_command, NULL, NULL);

            } else if (fork_ret_val == -1) {
                printf("[X] Fork failed with errno : %d\n", errno);
                continue;

            } else {
                // This is the original flow

                // waitpid for process to settle down
                // Make sure it is in expected state
                int wait_pid_status = 0;

                waitpid(fork_ret_val, &wait_pid_status, 0);
                working_pid = fork_ret_val;
            }


        } else if (equals(debugger_command, "diss_raw_addr")) {
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to set breakpoints!\n");
                continue;
            }

            ;

            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x401010,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x401010)
            );

            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x401012,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x401012)
            );

            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x401014,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x401014)
            );

            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x401018,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x401018)
            );

            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x40101c,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x40101c)
            );
            
            printf(
                "[-] Read in addr 0x%08X, value 0x%08X\n", 
                0x401020,
                ptrace(PTRACE_PEEKDATA, working_pid, 0x401020)
            );

            // Parse target memory addr to set breakpoint in
            char* mem_addr_string = strtok(NULL, " ");
            QWORD mem_addr = strtol(mem_addr_string, NULL, 0);
            
            for(int i = 0; i < 8; i++) {
                // Check current instruction
                QWORD target_addr = mem_addr + i*4;

                QWORD instructions = ptrace(PTRACE_PEEKDATA, working_pid, target_addr, 0);

                if(instructions == -1) {
                    printf("[x] An error occured in finding current opcode: %s\n", strerror(errno));
                    continue;
                } else {
                    printf(
                        "0x%08lx - 0x%02X 0x%02X 0x%02X 0x%02X\n", 
                        target_addr, 
                        (unsigned int) (instructions % 0x0100), 
                        (unsigned int) (instructions % 0x010000 / 0x0100),
                        (unsigned int) (instructions % 0x01000000 / 0x010000),
                        (unsigned int) (instructions % 0x0100000000 / 0x01000000)
                    );
                }
            }

        } else if (equals(debugger_command, "diss_raw")) {
            // Make sure there is a process attached by the debugger
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to disassemble!\n");
                continue;
            }


            // Find value of RIP - instruction pointer
            PID rip_addr_in_user_section = __builtin_offsetof(struct user, regs.rip);
            QWORD debugged_process_ip = ptrace(PTRACE_PEEKUSER, working_pid, rip_addr_in_user_section, 0);
            if(debugged_process_ip == -1) {
                printf("[x] An error occured when finding RIP: %s\n", strerror(errno));
                continue;
            }


            for(int i = 0; i < 8; i++) {
                // Check current instruction
                QWORD target_addr = debugged_process_ip + i*4;

                QWORD instructions = ptrace(PTRACE_PEEKDATA, working_pid, target_addr, 0);

                if(instructions == -1) {
                    printf("[x] An error occured in finding current instrucion: %s\n", strerror(errno));
                    continue;
                } else {
                    printf(
                        "0x%08lx - 0x%02X 0x%02X 0x%02X 0x%02X\n", 
                        target_addr, 
                        (unsigned int) (instructions % 0x0100), 
                        (unsigned int) (instructions % 0x010000 / 0x0100),
                        (unsigned int) (instructions % 0x01000000 / 0x010000),
                        (unsigned int) (instructions % 0x0100000000 / 0x01000000)
                    );
                }
            }

        } else if (equals(debugger_command, "diss")) {
            // Make sure there is a process attached by the debugger
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to disassemble!\n");
                continue;
            }


            // Find value of RIP - instruction pointer
            PID rip_addr_in_user_section = __builtin_offsetof(struct user, regs.rip);
            QWORD debugged_process_ip = ptrace(PTRACE_PEEKUSER, working_pid, rip_addr_in_user_section, 0);
            if(debugged_process_ip == -1) {
                printf("[x] An error occured when finding RIP: %s\n", strerror(errno));
                continue;
            }

            // Array of size 40 (decimal)
            ZyanU8 data[] =
            {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

            // The runtime address (instruction pointer) was chosen arbitrarily here in order to better
            // visualize relative addressing. In your actual program, set this to e.g. the memory address
            // that the code being disassembled was read from.
            ZyanU64 runtime_address = debugged_process_ip;

            for(int i = 0; i < 10; i++) {
                // Check current instruction
                QWORD target_addr = debugged_process_ip + i*4;

                QWORD read_result = ptrace(PTRACE_PEEKDATA, working_pid, target_addr, 0);

                if(read_result == -1) {
                    printf("[x] An error occured in finding current instrucion: %s\n", strerror(errno));
                    continue;
                } else {
                    data[i*4 + 0] = (unsigned int) (read_result % 0x0100);
                    data[i*4 + 1] = (unsigned int) (read_result % 0x010000 / 0x0100);
                    data[i*4 + 2] = (unsigned int) (read_result % 0x01000000 / 0x010000);
                    data[i*4 + 3] = (unsigned int) (read_result % 0x0100000000 / 0x01000000);
                }
            }

            // Loop over the instructions in our buffer.
            ZyanUSize offset = 0;
            ZydisDisassembledInstruction instruction;
            while (ZYAN_SUCCESS(ZydisDisassembleIntel(
                /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
                /* runtime_address: */ runtime_address,
                /* buffer:          */ data + offset,
                /* length:          */ sizeof(data) - offset,
                /* instruction:     */ &instruction
            ))) {
                char* is_breakpoint_string = "";
                if (breakpoint_addr == runtime_address) {
                    is_breakpoint_string = "-> ";
                }

                printf("0x%016" PRIX64 "  %s%s\n", runtime_address, is_breakpoint_string, instruction.text);
                offset += instruction.info.length;
                runtime_address += instruction.info.length;
            }

        } else if (equals(debugger_command, "break")) {
            // Make sure there is a process attached by the debugger
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to set breakpoints!\n");
                continue;
            }

            // Parse target memory addr to set breakpoint in
            char* breakpoint_addr_string = strtok(NULL, " ");
            breakpoint_addr = strtol(breakpoint_addr_string, NULL, 0);
            
            // Read original 16 bytes in that addr (max intel x86 instruction length is 15)
            for(int i = 0; i < 4; i++) {
                // Check current instruction
                QWORD target_addr = breakpoint_addr + i*4;

                QWORD read_result = ptrace(PTRACE_PEEKDATA, working_pid, target_addr, 0);

                if(read_result == -1) {
                    printf("[x] An error occured in finding memory in breakpoint addr : %s\n", strerror(errno));
                    continue;
                } else {
                    original_instruction[i*4 + 0] = (unsigned int) (read_result % 0x0100);
                    original_instruction[i*4 + 1] = (unsigned int) (read_result % 0x010000 / 0x0100);
                    original_instruction[i*4 + 2] = (unsigned int) (read_result % 0x01000000 / 0x010000);
                    original_instruction[i*4 + 3] = (unsigned int) (read_result % 0x0100000000 / 0x01000000);
                }
            }

            ZyanU64 runtime_address = breakpoint_addr;

            // Loop over the instructions in our buffer.
            ZyanUSize offset = 0;
            ZydisDisassembledInstruction instruction;
            ZydisDisassembleIntel(
                /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
                /* runtime_address: */ runtime_address,
                /* buffer:          */ original_instruction,
                /* length:          */ MAX_INSTRUCTION_LEN,
                /* instruction:     */ &instruction
            );

            breakpoint_instruction_length = instruction.info.length;
            printf("[-] You are trying to break on an instruction of length %d\n", breakpoint_instruction_length);
            printf("[-] %s\n", instruction.text);

        } else if (equals(debugger_command, "cont")) {
            // Make sure there is a process attached by the debugger
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before trying to continue!\n");
                continue;
            }

            if (breakpoint_addr != 0) {
                // Replace all memory addrs with breakpoints (opcode 0x33)
                write_mem(working_pid, breakpoint_addr, OPCODE_BREAKPOINT);

                for(int i = 1; i < breakpoint_instruction_length; i++) {
                    write_mem(working_pid, breakpoint_addr + i, OPCODE_NOP);
                }

                printf(
                    "[-] Read in addr 0x%08X, value 0x%02X\n", 
                    breakpoint_addr + 4, 
                    read_mem(working_pid, breakpoint_addr + 4)
                );
            }


            // Actually continue the process
            QWORD continue_ret_val = ptrace(PTRACE_CONT, working_pid, 0, 0);
            if(continue_ret_val == -1) {
                printf("[x] An error occured when trying to continue: %s\n", strerror(errno));
                continue;
            } else {
                printf("[V] Continuing process\n");
            }

            int wait_pid_status = 0;
            waitpid(working_pid, &wait_pid_status, 0);

            if (WIFSTOPPED(wait_pid_status)) {
                printf("[-] Process stopped with signal : %s\n", strsignal(WSTOPSIG(wait_pid_status)));
            }
            
        } else if (equals(debugger_command, "status")) {
            if (working_pid == 0) {
                printf("[X] Please attach debugger to a process before checking status!\n");
                continue;
            }


            char* pid_status_path = malloc(STRING_MAX_LEN);
            if (sprintf(pid_status_path, "/proc/%ld/status", working_pid) == -1) {
                printf("[X] Failed checking process status (failed to format /proc/pid/status path)");
            }
            FILE* pid_status_fd = fopen(pid_status_path, "r");
            if (pid_status_fd == NULL) {
                printf("[X] Failed checking process status (failed to open /proc/pid/status)");
            }

            free(pid_status_path);

            char* line = NULL;
            size_t len = 0;
            ssize_t read;

            // Status is on the third line
            // getline twice to read third line
            
            getline(&line, &len, pid_status_fd);
            getline(&line, &len, pid_status_fd);
            read = getline(&line, &len, pid_status_fd);

            if (read == -1) {
                printf("[X] Failed checking process status (Failed to read /proc/pid/status)");
            }

            printf("[-] %s", line);

            fclose(pid_status_fd);

        } else if (equals(debugger_command, "test")) {
            // Parse target memory addr to set breakpoint in
            char* mem_addr_string = strtok(NULL, " ");
            QWORD mem_addr = strtol(mem_addr_string, NULL, 0);

            write_mem(working_pid, mem_addr, 0x00);
        } else {
            printf("[X] Unknown command : \"%s\"\n", debugger_command);
        }
    }

    return 0;
}
