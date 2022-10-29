CC = gcc

make: compile hook run

compile:
	$(CC) -c -fPIC -o target.o target.c
	$(CC) -shared target.o -o libtarget.so
	$(CC) -O0 -L. -Wall -o leet_add leet_add.c -ltarget
	rm *.o

hook:
	./../src/shooker/__main__.py ./ ./

run:
	LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ ./leet_add

gdb:
	LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ gdb -q ./leet_add
