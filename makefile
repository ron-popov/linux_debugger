.PHONY: tests fun

build:
	mkdir build

debugger: build main.c
	gcc main.c -o build/debugger

tests: build tests/simple_loop.s
	gcc -no-pie -nostdlib tests/simple_loop.s -o build/simple_loop
	gcc -no-pie -nostdlib tests/hello_world.s -o build/hello_world
	gcc -no-pie -nostdlib tests/sleep_and_interrupt.s -o build/sleep_and_interrupt
	gcc tests/log_date_to_file.c -o build/log_date_to_file

fun: build
	gcc fun.c -o build/fun

clean:
	rm -rf build

all: clean debugger fun tests
