#!/bin/bash

# Pre-Rate Limit Hook
# Checks and enforces rate limits before API calls to external services
# Prevents violations of service-specific rate limits

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[RATE-LIMIT-HOOK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[RATE-LIMIT-HOOK]${NC} $1"
}

log_error() {
    echo -e "${RED}[RATE-LIMIT-HOOK]${NC} $1"
}

# Rate limit configuration (requests per minute unless specified)
declare -A RATE_LIMITS
RATE_LIMITS["crt.sh"]=10
RATE_LIMITS["github_api"]=60  # per hour
RATE_LIMITS["general_http"]=30
RATE_LIMITS["dns_query"]=30
RATE_LIMITS["websearch"]=10

# Rate limit tracking directory
RATE_LIMIT_DIR="${HOME}/.cache/techstack_identification/rate_limits"
mkdir -p "${RATE_LIMIT_DIR}"

check_rate_limit() {
    local service=$1
    local limit=$2
    local window=60  # Default: 60 seconds (1 minute)

    # GitHub API has hourly limit
    if [[ "${service}" == "github_api" ]]; then
        window=3600  # 1 hour
    fi

    local count_file="${RATE_LIMIT_DIR}/${service}.count"
    local timestamp_file="${RATE_LIMIT_DIR}/${service}.timestamp"

    # Initialize if files don't exist
    if [[ ! -f "${count_file}" ]]; then
        echo "0" > "${count_file}"
        date +%s > "${timestamp_file}"
        return 0
    fi

    local current_time=$(date +%s)
    local last_reset=$(cat "${timestamp_file}")
    local elapsed=$((current_time - last_reset))
    local current_count=$(cat "${count_file}")

    # Reset counter if window has passed
    if [[ ${elapsed} -ge ${window} ]]; then
        echo "0" > "${count_file}"
        date +%s > "${timestamp_file}"
        log_info "Rate limit reset for ${service}"
        return 0
    fi

    # Check if limit exceeded
    if [[ ${current_count} -ge ${limit} ]]; then
        local wait_time=$((window - elapsed))
        log_error "Rate limit exceeded for ${service}"
        log_error "Current: ${current_count}/${limit} requests"
        log_error "Please wait ${wait_time} seconds before retrying"
        return 1
    fi

    # Increment counter
    echo $((current_count + 1)) > "${count_file}"
    log_info "${service}: ${current_count}/${limit} requests used"

    return 0
}

# Detect which service is being called based on command or environment
detect_service() {
    local command="$1"

    # Check environment variable
    if [[ -n "${API_SERVICE}" ]]; then
        echo "${API_SERVICE}"
        return
    fi

    # Detect from command
    if echo "${command}" | grep -qi "crt\.sh"; then
        echo "crt.sh"
    elif echo "${command}" | grep -qi "github"; then
        echo "github_api"
    elif echo "${command}" | grep -qi "dig\|nslookup\|host"; then
        echo "dns_query"
    elif echo "${command}" | grep -qi "curl\|wget\|http"; then
        echo "general_http"
    else
        echo "general_http"  # Default fallback
    fi
}

# Main execution
if [[ -z "${SKILL_NAME}" ]]; then
    log_warn "SKILL_NAME not set, skipping rate limit check"
    exit 0
fi

# Get service from environment or detect from command
SERVICE=$(detect_service "${BASH_COMMAND:-}")
LIMIT=${RATE_LIMITS[$SERVICE]:-30}

log_info "Checking rate limit for service: ${SERVICE}"

if ! check_rate_limit "${SERVICE}" "${LIMIT}"; then
    log_error "Rate limit check failed for ${SERVICE}"
    exit 1
fi

log_info "Rate limit check passed for ${SERVICE}"
exit 0
