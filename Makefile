# VERSION = $(shell git describe --tags)

base_CFLAGS = -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE

libsystemd_CFLAGS = $(shell pkg-config --cflags libsystemd-daemon)
libsystemd_LDLIBS = $(shell pkg-config --libs libsystemd-daemon)

CFLAGS := \
	${base_CFLAGS} \
	${libsystemd_CFLAGS} \
	${CFLAGS}

LDLIBS := \
	${libsystemd_LDLIBS} \
	${LDLIBS}

all: epoxy
epoxy: epoxy.o proxy.o socket.o http_parser.o util.o

http_parser.c: http_parser.rl
	ragel -G2 -C $< -o $@

install: epoxy
	install -Dm755 epoxy ${DESTDIR}/usr/bin/epoxy
	# install -Dm644 epoxy.1 $(DESTDIR)/usr/share/man/man1/epoxy.1
	# install -Dm644 epoxy.service ${DESTDIR}/usr/lib/systemd/system/epoxy.service
	# install -Dm644 epoxy.socket ${DESTDIR}/usr/lib/systemd/system/epoxy.socket

clean:
	${RM} epoxy *.o

.PHONY: clean install uninstall
