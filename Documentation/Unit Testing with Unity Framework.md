# Unit Testing with Unity Framework

## 🧪 What is Unity Testing?

Unity is a lightweight unit testing framework specifically designed for **embedded C systems**. It provides a simple yet powerful way to test individual components of our bootloaders in isolation.

## 🎯 Why We Use Unity

### For Our Secure Bootloaders:
- **Isolated Testing**: Test bootloader logic without hardware dependencies
- **Early Bug Detection**: Catch issues before they reach integration testing
- **Code Quality**: Ensure each component works correctly independently
- **Regression Prevention**: Detect when changes break existing functionality

## 📁 Project Structure

```
test/
├── unity/                 # Unity testing framework
│   ├── unity.h
│   ├── unity.c
│   └── unity_internals.h
├── unit/                  # Our unit tests
│   ├── test_primary.c     # Primary bootloader unit tests
│   └── test_secondary.c   # Secondary bootloader unit tests
└── test_verify.c          # Integration tests (existing)
```

## 🚀 How to Use

### Run All Unit Tests
```bash
make unit-tests
```

### Test Specific Bootloaders
```bash
make unit-test-primary     # Test primary bootloader only
make unit-test-secondary   # Test secondary bootloader only
```

### Complete Testing Workflow
```bash
make unit-tests    # Unit tests (code level)
make test          # Integration tests (file level)
make run           # System test (full boot chain)
```

## 🧠 What We Test with Unity

### Primary Bootloader Tests:
- Verification logic for secondary bootloader signatures
- Error handling for missing/invalid signatures
- Boot sequence state machine

### Secondary Bootloader Tests:
- Kernel image verification logic
- QEMU command generation
- Error recovery paths

## 🔧 Example Test Structure

```c
#include "unity.h"

void setUp(void) {
    // Test setup code
}

void tearDown(void) {
    // Test cleanup code
}

void test_verification_logic(void) {
    // Test specific bootloader functions
    TEST_ASSERT_EQUAL(EXPECTED, ACTUAL);
    TEST_ASSERT_NOT_NULL(pointer);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_verification_logic);
    return UNITY_END();
}
```

## 📊 Test Results

When tests pass:
```
=== TESTING PRIMARY BOOTLOADER ===
test_primary_basic:PASS
test_primary_boot_logic:PASS
-----------------------
2 Tests 0 Failures 0 Ignored
OK
```

## 🎨 Benefits for Our Project

### 1. **Faster Development**
- Test components without full boot chain
- Quick feedback during development

### 2. **More Reliable**
- Catch signature verification bugs early
- Ensure error handling works correctly

### 3. **Maintainable**
- Clear separation between unit and integration tests
- Easy to add new test cases

### 4. **CI/CD Ready**
- Automated testing in Docker/CI pipelines
- Consistent results across environments

## 🔍 Testing Strategy

| Test Type | Command | Purpose |
|-----------|---------|---------|
| **Unit Tests** | `make unit-tests` | Test individual functions |
| **Integration Tests** | `make test` | Test file-based workflows |
| **System Tests** | `make run` | Test full boot chain |

## 🛠️ Troubleshooting

If unit tests fail:
```bash
make clean
make unit-tests
```

Check Unity files exist:
```bash
ls test/unity/
```

## 📚 Learn More

- [Unity Framework GitHub](https://github.com/ThrowTheSwitch/Unity)
- [Unity Documentation](https://github.com/ThrowTheSwitch/Unity/blob/master/docs/UnityGettingStartedGuide.md)

---

**Unity testing ensures our secure bootloaders are reliable and maintainable!** 🔐✨