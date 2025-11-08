.PHONY: all unit integration fuzz test-env test clean

all: unit integration fuzz

unit:
	@echo "=== Building Unit Tests ==="
	$(MAKE) -C unit_tests all

integration:
	@echo "=== Building Integration Tests ==="
	$(MAKE) -C integration all

fuzz:
	@echo "=== Building Fuzz Tests ==="
	$(MAKE) -C fuzz_testing all

test-env:
	@echo "=== Setting up Test Environment ==="
	chmod +x scripts/setup_safe_test_env.sh
	./scripts/setup_safe_test_env.sh

test: test-env all
	@echo "=== Running ALL Tests ==="
	@echo "--- Unit Tests ---"
	@$(MAKE) -C unit_tests test
	@echo "--- Integration Tests ---"
	@$(MAKE) -C integration test
	@echo "--- Fuzz Tests ---"
	@$(MAKE) -C fuzz_testing test
	@echo "=== ALL TESTS COMPLETED ==="

clean:
	$(MAKE) -C unit_tests clean
	$(MAKE) -C integration clean
	$(MAKE) -C fuzz_testing clean
	chmod +x scripts/cleanup_test_env.sh
	./scripts/cleanup_test_env.sh

.PHONY: all unit integration fuzz test-env test clean