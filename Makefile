CC = gcc
CFLAGS = -fPIC -m32 -Wall -g
LDFLAGS = -m32 -g

.PHONY: build
build: libso_loader.so

libso_loader.so: loader.o exec_parser.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

exec_parser.o: loader/exec_parser.c loader/exec_parser.h
	$(CC) $(CFLAGS) -o $@ -c $<

loader.o: loader/loader.c loader/handler.h
	$(CC) $(CFLAGS) -o $@ -c $<


.PHONY: clean
clean:
	-rm -f exec_parser.o loader.o libso_loader.so
