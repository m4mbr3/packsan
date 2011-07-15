CFLAGS = -O2 -Wall

lib%.so: lib%.o
	gcc -shared -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
