#!/bin/bash

# Pre-Network Skill Hook
# Verifies network connectivity before executing skills that require external access
# This hook runs before any skill that uses Bash, WebSearch, WebFetch, or network operations

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[PRE-NETWORK-HOOK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[PRE-NETWORK-HOOK]${NC} $1"
}

log_error() {
    echo -e "${RED}[PRE-NETWORK-HOOK]${NC} $1"
}

# Check if we're in a network-required context
if [[ -z "${SKILL_NAME}" ]]; then
    log_warn "SKILL_NAME not set, skipping network check"
    exit 0
fi

log_info "Verifying network connectivity for skill: ${SKILL_NAME}"

# Test DNS resolution
if ! host google.com > /dev/null 2>&1; then
    log_error "DNS resolution failed - cannot reach google.com"
    log_error "Please check your internet connection"
    exit 1
fi

log_info "DNS resolution: OK"

# Test HTTP connectivity
if ! curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://www.google.com | grep -q "200"; then
    log_error "HTTP connectivity test failed"
    log_error "Cannot reach https://www.google.com"
    exit 1
fi

log_info "HTTP connectivity: OK"

# Check for rate limit environment variables
if [[ -n "${RATE_LIMIT_REMAINING}" ]] && [[ "${RATE_LIMIT_REMAINING}" -le 0 ]]; then
    log_warn "Rate limit reached: ${RATE_LIMIT_REMAINING} requests remaining"
    log_warn "Skill execution may be throttled"
fi

# Check for proxy settings if needed
if [[ -n "${HTTP_PROXY}" ]] || [[ -n "${HTTPS_PROXY}" ]]; then
    log_info "Proxy detected: ${HTTP_PROXY:-$HTTPS_PROXY}"
fi

log_info "Network connectivity verified successfully"
exit 0
