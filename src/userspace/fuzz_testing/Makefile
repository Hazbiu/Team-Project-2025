CC = gcc
CFLAGS = -Wall -Wextra -g

TESTS = fuzz_metadata security_test

all: $(TESTS)

fuzz_metadata: fuzz_metadata.c
	$(CC) $(CFLAGS) -o $@ $<

security_test: security_test.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@for test in $(TESTS); do ./$$test; echo; done

clean:
	rm -f $(TESTS)

.PHONY: all test clean