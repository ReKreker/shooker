CC = gcc

compile:
	$(CC) -c -o test.o test.c
	$(CC) -shared test.o -o libtest.so
	$(CC) -O0 -L. -Wall -o main main.c -ltest

hook:
	./../hooker ./ ./result/

run:
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./result ./main

gdb:
	LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./result gdb -q ./main