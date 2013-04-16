# VERSION = $(shell git describe --tags)

CFLAGS := -std=c99 \
	-Wall -Wextra -pedantic \
	-D_GNU_SOURCE \
	${CFLAGS}
	# -DEPOXY_VERSION=\"${VERSION}\" \

LDLIBS = -lsystemd-daemon

all: epoxy
epoxy: epoxy.o proxy.o http_parser.o
	${CC} ${LDFLAGS} -o $@ $^ ${LDLIBS}

http_parser.c: http_parser.rl
	ragel -C $< -o $@

install: epoxy
	install -Dm755 epoxy ${DESTDIR}/usr/bin/epoxy
	# install -Dm644 epoxy.1 $(DESTDIR)/usr/share/man/man1/epoxy.1
	# install -Dm644 epoxy.service ${DESTDIR}/usr/lib/systemd/system/epoxy.service
	# install -Dm644 epoxy.socket ${DESTDIR}/usr/lib/systemd/system/epoxy.socket

clean:
	${RM} epoxy *.o

.PHONY: clean install uninstall
