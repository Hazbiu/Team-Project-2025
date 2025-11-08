CC = gcc
CFLAGS = -Wall -Wextra -g

TESTS = boot_simulator veritysetup_test full_workflow_test

all: $(TESTS)

boot_simulator: boot_simulator.c
	$(CC) $(CFLAGS) -o $@ $<

veritysetup_test: veritysetup_test.c
	$(CC) $(CFLAGS) -o $@ $<

full_workflow_test: full_workflow_test.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@for test in $(TESTS); do ./$$test; echo; done

clean:
	rm -f $(TESTS)

.PHONY: all test clean