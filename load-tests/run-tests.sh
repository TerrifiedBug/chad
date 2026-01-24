#!/bin/bash
#
# Load Test Runner
#
# Sets up test fixtures, runs k6 load tests, and cleans up.
#
# Usage:
#   ./run-tests.sh [baseline|log-ingestion|stress|all]
#
# Examples:
#   ./run-tests.sh baseline       # Run baseline test only
#   ./run-tests.sh all            # Run all tests sequentially
#   ./run-tests.sh                # Default: run baseline test

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.dev.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if backend is running
check_backend() {
    log_info "Checking if backend is running..."
    if ! curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        log_error "Backend is not running. Start it with: docker compose -f docker-compose.dev.yml up -d"
        exit 1
    fi
    log_info "Backend is running"
}

# Setup test fixtures
setup_fixtures() {
    log_info "Setting up test fixtures..."

    # Copy setup script to backend container and run it
    docker compose -f "$COMPOSE_FILE" cp \
        "$SCRIPT_DIR/scripts/setup-test-fixtures.py" \
        backend:/tmp/setup-test-fixtures.py

    docker compose -f "$COMPOSE_FILE" exec -T backend \
        python /tmp/setup-test-fixtures.py setup

    log_info "Test fixtures ready"
}

# Teardown test fixtures
teardown_fixtures() {
    log_info "Cleaning up test fixtures..."

    docker compose -f "$COMPOSE_FILE" exec -T backend \
        python /tmp/setup-test-fixtures.py teardown 2>/dev/null || true

    log_info "Cleanup complete"
}

# Run a k6 test
run_test() {
    local test_name=$1
    log_info "Running $test_name test..."

    cd "$SCRIPT_DIR"
    docker compose run --rm k6 run "/scripts/${test_name}.js" || {
        log_warn "$test_name test completed with threshold failures"
    }
}

# Main
main() {
    local test_type="${1:-baseline}"

    log_info "=== Load Test Runner ==="
    log_info "Test type: $test_type"

    # Pre-flight checks
    check_backend

    # Setup
    setup_fixtures

    # Run tests
    case "$test_type" in
        baseline)
            run_test "baseline"
            ;;
        log-ingestion)
            run_test "log-ingestion"
            ;;
        stress)
            run_test "stress"
            ;;
        all)
            run_test "baseline"
            run_test "log-ingestion"
            run_test "stress"
            ;;
        *)
            log_error "Unknown test type: $test_type"
            echo "Usage: $0 [baseline|log-ingestion|stress|all]"
            exit 1
            ;;
    esac

    # Cleanup
    teardown_fixtures

    log_info "=== Load tests complete ==="
}

# Handle cleanup on exit
trap teardown_fixtures EXIT

main "$@"
