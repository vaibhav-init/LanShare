CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -pthread
SRC    = src/main.c src/net.c src/http.c src/fs.c
HDR    = src/share.h src/page.h

all: lanshare

lanshare: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: test_lanshare
	./test_lanshare

test_lanshare: tests/test_lanshare.c src/fs.c $(HDR)
	$(CC) $(CFLAGS) -o $@ tests/test_lanshare.c src/fs.c

install: all
	install -D lanshare $(HOME)/.local/bin/lanshare
	install -m 755 scripts/waybar-lanshare.sh $(HOME)/.local/bin/lanshare-waybar

clean:
	rm -f lanshare test_lanshare

.PHONY: all test install clean
