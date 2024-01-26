.PHONY: tests

debugger: main.c
	- mkdir build
	gcc main.c -o build/debugger

tests: tests/simple_loop.s
	- mkdir build
	gcc -no-pie -nostdlib tests/simple_loop.s -o build/simple_loop
	gcc -no-pie -nostdlib tests/hello_world.s -o build/hello_world

clean:
	rm -rf build

all: clean debugger tests