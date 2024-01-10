debugger: clean main.c
	gcc main.c -o debugger

tests: tests/simple_loop.s clean
	gcc -nostdlib tests/simple_loop.s -o ./tests/simple_loop

clean:
	rm -rf debugger
	rm -rf tests/*.o
	rm -rf tests/simple_loop

all: clean debugger tests