debugger: clean main.c
	gcc main.c -o debugger

tests: tests/simple_loop.s clean
	gcc -nostdlib tests/simple_loop.s && ./tests/simple_loop.o

clean:
	rm -rf debugger
	rm -rf tests/*.o

all: clean debugger all