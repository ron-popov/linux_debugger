.PHONY: tests

debugger: main.c
	rm -rf debugger
	gcc main.c -o debugger

tests: tests/simple_loop.s
	rm -rf tests/simple_loop
	gcc -no-pie -nostdlib tests/simple_loop.s -o tests/simple_loop
	gcc -no-pie -nostdlib tests/hello_world.s -o tests/hello_world

clean:
	rm -rf debugger
	rm -rf tests/*.o
	rm -rf tests/simple_loop

all: clean debugger tests