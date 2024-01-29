# Linux Debugger
### Building and Usage
```bash
make debugger

sudo build/debugger

# Choose an example
run build/log_date_to_file
run build/sleep_and_interrupt
run build/hello_world

# Disassemble the code
diss

# Set a breakpoint
break 0x401010

# Continue the flow of the program
cont
```