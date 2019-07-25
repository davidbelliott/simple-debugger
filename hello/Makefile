CFLAGS=-g2 -gdwarf-4 -O0 -fno-omit-frame-pointer

.DEFAULT_GOAL := all

all: hello

hello: hello.c
	gcc $(CFLAGS) hello.c -o hello

clean:
	-/bin/rm hello
