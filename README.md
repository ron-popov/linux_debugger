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
diss 0x40101C

# Show opcodes in RIP
diss_raw
diss_raw_addr 0x40101C
diss_raw_addr 0x401010

# Set a breakpoint
break 0x401010
break 0x40101C

# Continue the flow of the program
cont
```