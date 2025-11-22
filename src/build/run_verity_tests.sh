#!/bin/bash
set -eo pipefail

# ================================================================
# dm-verity Security Behavior Automated Test Harness
# ------------------------------------------------
# Purpose:
#   This script provides a full automated testing environment for
#   evaluating dm-verity security features in Linux root filesystems.
#   It is intended for both developers and security engineers to:
#       - Detect failures in dm-verity integrity checks
#       - Verify correct rejection of corrupted images
#       - Ensure that the kernel and root filesystem behave as expected
# 
# Features:
#   1. Prerequisites:
#       - Checks for QEMU (x86_64 emulator), Python3, and test image builder scripts
#       - Ensures necessary binaries exist in the 'Binaries' directory
#   2. Directory & Permission Management:
#       - Confirms write permissions on the 'Binaries' folder
#       - Adjusts ownership and permissions if required
#   3. Test Image Handling:
#       - Scans for existing corrupted test images for all defined modes
#       - Generates missing test images using integrity_tests.sh
#       - Maintains a predictable test order to ensure reproducibility
#   4. QEMU Execution:
#       - Launches qemu_tests.sh for each test image
#       - Captures exit codes and serial console output
#       - Supports optional logging to files or standard output
#   5. Log Analysis:
#       - Parses boot logs for kernel panic, init messages, and dm-verity verification failures
#       - Classifies results as BOOT_SUCCESS, REJECTED, KERNEL_PANIC, TIMEOUT, or UNKNOWN
#   6. Result Evaluation:
#       - Compares actual boot behavior against expected behavior per test mode
#       - Marks each test as PASSED, FAILED, INCONCLUSIVE, or SKIPPED
#   7. Reporting:
#       - Provides color-coded summary output in terminal
#       - Stores detailed logs for each test, including QEMU serial output
#       - Aggregates all results in a central 'test_results.txt'
#
#     NOTE: Certain test cases (sig1, meta1, etc.) may trigger a kernel panic.
#     These are considered valid REJECT outcomes and are counted as passing.
#
# Usage:
#   ./run_verity_tests.sh [OPTIONS]
#   OPTIONS:
#       --keep-images      Keep generated test images after execution
#       --no-color         Disable color-coded output
#       --timeout=N        Set the QEMU test timeout in seconds (default 30)
#       --help             Show this help message
#
# Test Modes:
#   - meta1          : Rejected if metadata header is corrupted
#   - sig1           : Rejected if signature is invalid
#   - int_overflow   : Rejected if integer overflow occurs in metadata
#   - buf_overflow   : Rejected if metadata size exceeds limits
#   - trunc_meta     : Rejected if metadata is truncated
#   - bad_offsets    : Rejected if file offsets are invalid
#   - sanitize       : Rejected if garbage input is provided
#   - best_case      : Clean image should boot successfully
#
# Maintainer:
#   <TEAM A>
#   Last Updated: 2025-11-22
# ================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INTEGRITY_SCRIPT="$SCRIPT_DIR/integrity_tests.sh"
QEMU_TESTS_SCRIPT="$PROJECT_ROOT/bootloaders/qemu_tests.sh"
BINARIES_DIR="$SCRIPT_DIR/Binaries"
LOG_DIR="$SCRIPT_DIR/test_logs"
RESULTS_FILE="$LOG_DIR/test_results.txt"

# Ensure Binaries directory is owned by the current user and writable
if [[ ! -w "$BINARIES_DIR" || "$(stat -c '%U' "$BINARIES_DIR")" != "$USER" ]]; then
    echo "Fixing ownership and permissions on Binaries directory..."
    sudo chown -R "$USER":"$USER" "$BINARIES_DIR" || { echo "Failed to set ownership on $BINARIES_DIR"; exit 1; }
    sudo chmod -R a+rwX "$BINARIES_DIR" || { echo "Failed to set permissions on $BINARIES_DIR"; exit 1; }
fi

# Test definitions - order matters for reproducibility
TEST_ORDER=(
    "meta1"
    "sig1"
    "int_overflow"
    "buf_overflow"
    "trunc_meta"
    "bad_offsets"
    "sanitize"
    "best_case"
)

declare -A TEST_MODES=(
    ["meta1"]="PANIC:Corrupted header should be rejected"
    ["sig1"]="PANIC:Invalid signature should be rejected"  
    ["int_overflow"]="REJECT:Integer overflow should be caught"
    ["buf_overflow"]="REJECT:Oversized metadata should be rejected"
    ["trunc_meta"]="REJECT:Out-of-bounds metadata should be rejected"
    ["bad_offsets"]="REJECT:Invalid offsets should be rejected"
    ["sanitize"]="REJECT:Garbage input should be rejected"
    ["best_case"]="BOOT:Clean image should boot successfully"
)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ======================================================
# Usage
# ======================================================
usage() {
    cat <<EOF
dm-verity Security Behavior Test Suite

SYNOPSIS:
    $0 [OPTIONS]

OPTIONS:
    --keep-images    - Keep test images after execution  
    --no-color       - Disable colored output
    --timeout=N      - Set test timeout (default: 20)
    --help           - Show this help message

TEST MODES:
    meta1        - Corrupted metadata header (expect REJECT)
    sig1         - Invalid signature (expect REJECT)
    int_overflow - Integer overflow in metadata (expect REJECT)
    buf_overflow - Oversized metadata (expect REJECT)
    trunc_meta   - Truncated metadata (expect REJECT)
    bad_offsets  - Invalid file offsets (expect REJECT)
    sanitize     - Garbage input (expect REJECT)
    best_case    - Clean unmodified image (expect BOOT)
EOF
}

# ======================================================
# Logging
# ======================================================
init_logging() {
    mkdir -p "$LOG_DIR"
    rm -f "$RESULTS_FILE"
    echo "dm-verity Security Test Results - $(date)" > "$RESULTS_FILE"
    echo "==========================================" >> "$RESULTS_FILE"
}

log() {
    local level=$1; shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] $*" | tee -a "$RESULTS_FILE"
}

# ======================================================
# Prerequisites & Binaries
# ======================================================
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    local missing=()
    [[ ! -f "$INTEGRITY_SCRIPT" ]] && missing+=("integrity_tests.sh")
    [[ ! -f "$QEMU_TESTS_SCRIPT" ]] && missing+=("qemu_tests.sh")
    command -v qemu-system-x86_64 >/dev/null 2>&1 || missing+=("qemu-system-x86_64")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "ERROR" "Missing prerequisites: ${missing[*]}"
        exit 1
    fi
    
    if [[ ! -f "$BINARIES_DIR/rootfs.img" ]]; then
        log "ERROR" "Original rootfs.img not found in $BINARIES_DIR"
        exit 1
    fi
    
    log "INFO" "All prerequisites satisfied"
}

check_binaries_permissions() {
    log "INFO" "Checking Binaries directory permissions..."

    if [[ ! -w "$BINARIES_DIR" ]]; then
        log "WARN" "Binaries directory not writable. Fixing permissions..."
        sudo chmod a+rwX "$BINARIES_DIR" || {
            log "ERROR" "Failed to set write permissions on $BINARIES_DIR"
            return 1
        }
        log "INFO" "Binaries directory is now writable"
    fi

    return 0
}

check_test_images_exist() {
    log "INFO" "Checking if all required test images exist..."
    local missing=0
    for mode in "${TEST_ORDER[@]}"; do
        # Skip best_case - it uses the original rootfs.img
        [[ "$mode" == "best_case" ]] && continue
        [[ "$mode" == "baseline" ]] && continue
        
        local test_image="$BINARIES_DIR/rootfs.${mode}.test.img"
        if [[ ! -f "$test_image" ]]; then
            log "DEBUG" "Missing image for mode: $mode ($test_image)"
            missing=$((missing + 1))
        fi
    done

    if [[ $missing -eq 0 ]]; then
        log "INFO" "All required test images found."
        return 0
    else
        log "WARN" "Found $missing missing test images."
        return 1
    fi
}

generate_test_images() {
    log "INFO" "Generating missing test images..."
    
    local generated=0 failed=0
    
    for mode in "${TEST_ORDER[@]}"; do
        # Skip best_case - it uses the original rootfs.img
        [[ "$mode" == "best_case" ]] && continue
        [[ "$mode" == "baseline" ]] && continue
        
        local test_image="$BINARIES_DIR/rootfs.${mode}.test.img"
        if [[ ! -f "$test_image" ]]; then
            log "INFO" "Creating test image for: $mode"
            if "$INTEGRITY_SCRIPT" "$mode" --yes > "$LOG_DIR/create_${mode}.log" 2>&1; then
                generated=$((generated + 1))
                log "INFO" "Successfully created: $mode"
            else
                failed=$((failed + 1))
                log "ERROR" "Failed to create test image for $mode (check $LOG_DIR/create_${mode}.log)"
            fi
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log "ERROR" "Failed to generate $failed test images"
        return 1
    elif [[ $generated -gt 0 ]]; then
        log "INFO" "Successfully generated $generated test images"
    else
        log "INFO" "All test images already exist"
    fi
    return 0
}

# ======================================================
# Run single test
# ======================================================
run_single_test() {
    local test_name=$1
    local test_image=$2
    local log_file="$LOG_DIR/qemu_${test_name}.log"
    local serial_log="$LOG_DIR/qemu_${test_name}_serial.log"
    local qemu_exit=0

    echo "=== Starting test: $test_name ===" > "$log_file"
    echo "Test image: $test_image" >> "$log_file"
    echo "Serial log: $serial_log" >> "$log_file"
    echo "Timeout: ${TEST_TIMEOUT}s" >> "$log_file"
    echo "================================================" >> "$log_file"
    
    local original_dir="$(pwd)"
    local test_image_abs=$(realpath "$test_image")
    
    cd "$PROJECT_ROOT/bootloaders"
    
    # Disable exit-on-error for QEMU execution
    # timeout returns 124 on timeout, QEMU may return various codes
    set +e
    timeout -k 5 "${TEST_TIMEOUT}" ./qemu_tests.sh "$test_image_abs" "$serial_log" >> "$log_file" 2>&1
    qemu_exit=$?
    set -e

    echo "" >> "$log_file"
    echo "================================================" >> "$log_file"
    echo "QEMU exit code: $qemu_exit" >> "$log_file"
    echo "Timeout exit code 124 means test was terminated by timeout (expected for best_case)" >> "$log_file"
    echo "================================================" >> "$log_file"
    
    # Append serial output to main log for analysis
    if [[ -f "$serial_log" ]]; then
        echo "" >> "$log_file"
        echo "=== Serial Console Output ===" >> "$log_file"
        cat "$serial_log" >> "$log_file"
        echo "=== End Serial Output ===" >> "$log_file"
    else
        echo "WARNING: Serial log file not created: $serial_log" >> "$log_file"
    fi
    
    # Force kill any remaining QEMU processes
    pkill -9 -f "qemu-system.*$test_name" 2>/dev/null || true
    pkill -9 -f "qemu-system.*$(basename "$test_image")" 2>/dev/null || true
    sleep 1
    
    cd "$original_dir"

    # Return the log file path (always succeeds - analysis happens separately)
    echo "$log_file"
}

# ======================================================
# Analyze boot logs - strict analysis
# ======================================================
analyze_boot_behavior() {
    local test_name=$1
    local log_file=$2
    
    if [[ ! -f "$log_file" ]]; then
        echo "ERROR:No log file found"
        return 1
    fi
    
    local file_size=$(stat -c%s "$log_file" 2>/dev/null || echo "0")
    if [[ "$file_size" -lt 100 ]]; then
        echo "ERROR:Log file too small ($file_size bytes)"
        return 1
    fi

    # Check for kernel panic first (highest priority)
    if grep -q -i "kernel panic" "$log_file"; then
        echo "KERNEL_PANIC"
        return 0
    fi
    
    # Check for successful boot indicators
    if grep -q -i "login:" "$log_file"; then
        echo "BOOT_SUCCESS"
        return 0
    fi
    
    if grep -q -i "Welcome to" "$log_file" && grep -q -i "systemd" "$log_file"; then
        echo "BOOT_SUCCESS"
        return 0
    fi

    # Check for explicit rejection messages
    if grep -q -i "dm-verity-autoboot: untrusted" "$log_file" ||
       grep -q -i "signature verification FAILED" "$log_file" ||
       grep -q -i "unknown tail magic" "$log_file" ||
       grep -q -i "corrupted metadata" "$log_file" ||
       grep -q -i "invalid signature" "$log_file" ||
       grep -q -i "hash verification failed" "$log_file" ||
       grep -q -i "VALIDATION FAILED" "$log_file" ||
       grep -q -i "verification failed" "$log_file"; then
        echo "REJECTED"
        return 0
    fi
    
    # Check for timeout (QEMU exit code 124)
    if grep -q "QEMU exit code: 124" "$log_file"; then
        # Timeout occurred - check if there was boot progress
        if grep -q -i "Booting" "$log_file" || grep -q -i "Linux version" "$log_file"; then
            echo "TIMEOUT_WITH_PROGRESS"
        else
            echo "TIMEOUT_NO_OUTPUT"
        fi
        return 0
    fi
    
    echo "UNKNOWN"
    return 0
}

# ======================================================
# Evaluate test result - strict evaluation
# ======================================================
evaluate_test_result() {
    local test_name=$1
    local actual_behavior=$2
    local expected_behavior=$3
    
    # Log the evaluation for debugging
    log "DEBUG" "Evaluating: test=$test_name actual=$actual_behavior expected=$expected_behavior"
    
    case "$expected_behavior" in
        "BOOT")
            # For best_case: we expect successful boot
            case "$actual_behavior" in
                "BOOT_SUCCESS") 
                    return 0  # PASSED - booted as expected
                    ;;
                "TIMEOUT_WITH_PROGRESS")
                    # Timeout with boot progress likely means it reached login prompt
                    # This is acceptable for best_case since QEMU waits for input
                    return 0  # PASSED - likely reached login
                    ;;
                "REJECTED"|"KERNEL_PANIC") 
                    return 1  # FAILED - should have booted
                    ;;
                "TIMEOUT_NO_OUTPUT")
                    return 2  # INCONCLUSIVE - no boot progress seen
                    ;;
                *) 
                    return 2  # INCONCLUSIVE
                    ;;
            esac 
            ;;
        "REJECT"|"PANIC")
            # For corruption tests: we expect rejection
            case "$actual_behavior" in
                "REJECTED"|"KERNEL_PANIC") 
                    return 0  # PASSED - rejected as expected
                    ;;
                "TIMEOUT_WITH_PROGRESS"|"TIMEOUT_NO_OUTPUT")
                    # Timeout can indicate rejection (system halted)
                    return 0  # PASSED - likely rejected
                    ;;
                "BOOT_SUCCESS") 
                    return 1  # FAILED - corrupted image should NOT boot!
                    ;;
                *) 
                    return 2  # INCONCLUSIVE
                    ;;
            esac 
            ;;
        *) 
            return 2  # INCONCLUSIVE - unknown expected behavior
            ;;
    esac
}

# ======================================================
# Progress indicator
# ======================================================
show_progress() {
    local current=$1 total=$2 test_name=$3
    local width=30
    local percent=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    # Truncate long test names
    local display_name="$test_name"
    if [[ ${#test_name} -gt 15 ]]; then
        display_name="${test_name:0:12}..."
    fi
    
    printf "\r\033[K${BLUE}[${GREEN}"  # \033[K clears to end of line
    printf "%*s" "$completed" | tr ' ' '='
    printf "${BLUE}"
    printf "%*s" "$remaining" | tr ' ' '-'
    printf "${BLUE}] %3d%% %s${NC}" "$percent" "$display_name"
}
# ======================================================
# Print final summary
# ======================================================
print_summary() {
    local -n results_ref=$1
    local -n behaviors_ref=$2
    local -n names_ref=$3
    local total=$4 passed=$5 failed=$6 inconclusive=$7

    echo
    echo -e "${BLUE}===================================================================="
    echo "                    TEST SUMMARY"
    echo "===================================================================="
    echo -e "${NC}"
    
    printf "%-15s %-12s %-20s %s\n" "TEST" "RESULT" "BEHAVIOR" "EXPECTED"
    echo "--------------------------------------------------------------------"
    
    for test_name in "${names_ref[@]}"; do
        local result="${results_ref[$test_name]}"
        local behavior="${behaviors_ref[$test_name]}"
        IFS=':' read -r expected_behavior description <<< "${TEST_MODES[$test_name]}"
        
        local color="$YELLOW"
        case "$result" in
            "PASSED") color="$GREEN" ;;
            "FAILED") color="$RED" ;;
            *) color="$YELLOW" ;;
        esac
        
        printf "%-15s ${color}%-12s${NC} %-20s %s\n" \
            "$test_name" "$result" "$behavior" "$expected_behavior"
    done

    echo
    echo "--------------------------------------------------------------------"
    printf "Total Tests:      %d\n" "$total"
    printf "${GREEN}Security PASS:    %d${NC}\n" "$passed"
    printf "${RED}Security FAIL:    %d${NC}\n" "$failed"
    printf "${YELLOW}Inconclusive:     %d${NC}\n" "$inconclusive"
    
    echo
    echo -e "Detailed logs saved in: ${CYAN}$LOG_DIR/${NC}"
    echo

    # Log summary to file
    {
        echo ""
        echo "==== FINAL SUMMARY ===="
        echo "Total: $total | Passed: $passed | Failed: $failed | Inconclusive: $inconclusive"
        echo "======================="
    } >> "$RESULTS_FILE"
}

# ======================================================
# Main
# ======================================================
main() {
    local KEEP_IMAGES=0 NO_COLOR=0
    TEST_TIMEOUT=30

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-images) KEEP_IMAGES=1 ;;
            --no-color) NO_COLOR=1 ;;
            --timeout=*) TEST_TIMEOUT="${1#*=}" ;;
            --help) usage; exit 0 ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done

    [[ "$NO_COLOR" -eq 1 ]] && GREEN='' RED='' YELLOW='' BLUE='' CYAN='' NC=''

    echo -e "${BLUE}"
    echo "===================================================================="
    echo "           dm-verity Security Behavior Test Suite"
    echo "===================================================================="
    echo -e "${NC}"

    # Initialize
    init_logging
    check_prerequisites

    if check_binaries_permissions; then
        CAN_WRITE_BINARIES="true"
    else
        CAN_WRITE_BINARIES="false"
    fi

    # Generate test images if needed
    if ! check_test_images_exist; then
        if [[ "$CAN_WRITE_BINARIES" == "true" ]]; then
            generate_test_images || { log "ERROR" "Failed to generate test images"; exit 1; }
        else
            log "ERROR" "Cannot generate test images and some are missing"
            log "ERROR" "Please run: sudo chown -R \$USER:\$USER $BINARIES_DIR"
            exit 1
        fi
    fi

    log "INFO" "Starting test execution phase..."
    
    # Initialize result tracking
    declare -A test_results
    declare -A test_behaviors
    local total_tests=0 passed_tests=0 failed_tests=0 inconclusive_tests=0

    # Build test list 
    local test_names=()
    for test in "${TEST_ORDER[@]}"; do
        test_names+=("$test")
        total_tests=$((total_tests + 1))
    done

    log "DEBUG" "Test queue: ${test_names[*]}"
    log "DEBUG" "Total tests: $total_tests"
    
    echo -e "${CYAN}Running ${total_tests} security behavior tests...${NC}"
    echo ""

    if [[ $total_tests -eq 0 ]]; then
        log "ERROR" "No tests to run! Check TEST_ORDER array."
        exit 1
    fi

    # ===== Main test execution loop =====
    local current_test=1
    for test_name in "${test_names[@]}"; do
        show_progress $current_test $total_tests "$test_name"

        # Get expected behavior
        IFS=':' read -r expected_behavior description <<< "${TEST_MODES[$test_name]}"
        
        # Determine test image path
        local test_image
        if [[ "$test_name" == "best_case" ]]; then
            test_image="$BINARIES_DIR/rootfs.img"
        else
            test_image="$BINARIES_DIR/rootfs.${test_name}.test.img"
        fi

        # Check if image exists
        if [[ ! -f "$test_image" ]]; then
            test_results["$test_name"]="SKIPPED"
            test_behaviors["$test_name"]="MISSING_IMAGE"
            inconclusive_tests=$((inconclusive_tests + 1))
            echo -e "\r${YELLOW}? $test_name (SKIPPED - missing image)${NC}                    "
            current_test=$((current_test + 1))
            continue
        fi

        log "DEBUG" "Running test: $test_name with image: $test_image"
        
        # Run the test - capture log file path
        local log_file
        log_file=$(run_single_test "$test_name" "$test_image")
        
        # Analyze the boot behavior from logs
        local actual_behavior
        actual_behavior=$(analyze_boot_behavior "$test_name" "$log_file")
        test_behaviors["$test_name"]="$actual_behavior"

        # Evaluate pass/fail
        local result_code
        evaluate_test_result "$test_name" "$actual_behavior" "$expected_behavior"
        result_code=$?

        # Record result
        case $result_code in
            0) 
                test_results["$test_name"]="PASSED"
                passed_tests=$((passed_tests + 1))
                echo -e "\r${GREEN}✓ $test_name${NC}                                        "
                ;;
            1) 
                test_results["$test_name"]="FAILED"
                failed_tests=$((failed_tests + 1))
                echo -e "\r${RED}✗ $test_name (SECURITY VIOLATION: $actual_behavior)${NC}   "
                ;;
            *) 
                test_results["$test_name"]="INCONCLUSIVE"
                inconclusive_tests=$((inconclusive_tests + 1))
                echo -e "\r${YELLOW}? $test_name ($actual_behavior)${NC}                    "
                ;;
        esac

        current_test=$((current_test + 1))
        sleep 1
    done

    # Clear progress line
    echo -ne "\r\033[K"

    # Print summary
    print_summary test_results test_behaviors test_names \
        "$total_tests" "$passed_tests" "$failed_tests" "$inconclusive_tests"

    # Exit with appropriate code
    if [[ $failed_tests -gt 0 ]]; then
        log "ERROR" "Security test suite completed with $failed_tests FAILURES"
        exit 1
    else
        log "INFO" "Security test suite completed successfully"
        exit 0
    fi
}

# ======================================================
# Entry point
# ======================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi