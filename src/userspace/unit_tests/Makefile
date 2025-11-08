CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto

TESTS = test_metadata test_crypto test_bootparams test_dm_interface

all: $(TESTS)

test_metadata: test_metadata.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_crypto: test_crypto.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_bootparams: test_bootparams.c
	$(CC) $(CFLAGS) -o $@ $<

test_dm_interface: test_dm_interface.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@for test in $(TESTS); do ./$$test; echo; done

clean:
	rm -f $(TESTS)

.PHONY: all test clean