CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

all: seccomp-wrapper
static: seccomp-wrapper-static

seccomp-wrapper: seccomp-wrapper.c
	$(CC) $(CFLAGS) $(pkg-config --cflags libseccomp) -o $@ $^ $(LDFLAGS) $(pkg-config --libs libseccomp)
seccomp-wrapper-static: seccomp-wrapper.c
	$(CC) $(CFLAGS) $(pkg-config --cflags libseccomp) -o $@ $^ -static $(LDFLAGS) $(pkg-config --libs libseccomp)

clean:
	rm -f seccomp-wrapper seccomp-wrapper-static
