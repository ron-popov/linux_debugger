# Waits for 5 seconds and then raises SIGTRAP
# Which the debugger should catch and start debugging

        .global _start

        .text
_start:

	pushq $0    #0 nanoseconds
	pushq $5    #5 seconds

	### RSP instead of RBP in the next instruction:
	mov   %rsp, %rdi    #the time structure we just pushed
	mov   $35, %eax     #SYS_nanosleep
	xor   %esi, %esi    #rem=NULL, we don't care if we wake early

	syscall

	# Raise SIGTRAP
	int $3

	# write(1, message, 13) - this is for more stuff to happen after interrupt
	mov     $1, %rax                # system call 1 is write
	mov     $1, %rdi                # file handle 1 is stdout
	mov     $message, %rsi          # address of string to output
	mov     $13, %rdx               # number of bytes
	syscall    

message:
        .ascii  "Hello, world\n"
		