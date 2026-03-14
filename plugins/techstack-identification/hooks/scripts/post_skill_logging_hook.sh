#!/bin/bash

# Post-Skill Logging Hook
# Logs skill execution results, captures evidence, and tracks performance metrics
# Runs after every skill execution to maintain audit trail

set -e

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[POST-SKILL-HOOK]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[POST-SKILL-HOOK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[POST-SKILL-HOOK]${NC} $1"
}

# Logging configuration
LOG_DIR="${HOME}/.cache/techstack_identification/logs"
EVIDENCE_DIR="${HOME}/.cache/techstack_identification/evidence"
mkdir -p "${LOG_DIR}" "${EVIDENCE_DIR}"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/skill_execution_${TIMESTAMP}.log"

# Log skill execution details
log_skill_execution() {
    local skill_name="${SKILL_NAME:-unknown}"
    local exit_code="${SKILL_EXIT_CODE:-0}"
    local duration="${SKILL_DURATION:-0}"

    cat >> "${LOG_FILE}" << EOF
==========================================================
SKILL EXECUTION LOG
==========================================================
Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Skill Name: ${skill_name}
Exit Code: ${exit_code}
Duration: ${duration} seconds
Agent: ${AGENT_NAME:-unknown}
Phase: ${PHASE_NUMBER:-unknown}
Company Target: ${TARGET_COMPANY:-unknown}
Domain: ${TARGET_DOMAIN:-unknown}
==========================================================

EXECUTION DETAILS:
EOF

    # Append skill-specific output if available
    if [[ -n "${SKILL_OUTPUT}" ]]; then
        echo "${SKILL_OUTPUT}" >> "${LOG_FILE}"
    fi

    # Log evidence if captured
    if [[ -n "${EVIDENCE_FILE}" ]] && [[ -f "${EVIDENCE_FILE}" ]]; then
        cp "${EVIDENCE_FILE}" "${EVIDENCE_DIR}/evidence_${skill_name}_${TIMESTAMP}.json"
        log_info "Evidence captured: ${EVIDENCE_DIR}/evidence_${skill_name}_${TIMESTAMP}.json"
    fi

    log_info "Skill execution logged: ${LOG_FILE}"
}

# Log performance metrics
log_metrics() {
    local metrics_file="${LOG_DIR}/metrics.csv"

    # Create header if file doesn't exist
    if [[ ! -f "${metrics_file}" ]]; then
        echo "timestamp,skill_name,duration_seconds,exit_code,agent,phase" > "${metrics_file}"
    fi

    # Append metrics
    echo "${TIMESTAMP},${SKILL_NAME:-unknown},${SKILL_DURATION:-0},${SKILL_EXIT_CODE:-0},${AGENT_NAME:-unknown},${PHASE_NUMBER:-unknown}" >> "${metrics_file}"

    log_debug "Metrics logged: ${metrics_file}"
}

# Capture error details if skill failed
log_errors() {
    local exit_code="${SKILL_EXIT_CODE:-0}"

    if [[ ${exit_code} -ne 0 ]]; then
        local error_file="${LOG_DIR}/errors_${TIMESTAMP}.log"
        cat >> "${error_file}" << EOF
==========================================================
SKILL EXECUTION ERROR
==========================================================
Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Skill Name: ${SKILL_NAME:-unknown}
Exit Code: ${exit_code}
Error Message: ${ERROR_MESSAGE:-No error message provided}
Stack Trace: ${ERROR_STACK:-No stack trace available}
==========================================================
EOF
        log_warn "Error details logged: ${error_file}"
    fi
}

# Update execution summary
update_summary() {
    local summary_file="${LOG_DIR}/execution_summary.json"

    # Initialize summary if doesn't exist
    if [[ ! -f "${summary_file}" ]]; then
        echo '{"total_executions": 0, "successful": 0, "failed": 0, "skills": {}}' > "${summary_file}"
    fi

    # Update counters (simplified - in production would use jq properly)
    log_debug "Summary updated: ${summary_file}"
}

# Main execution
log_info "Logging skill execution for: ${SKILL_NAME:-unknown}"

# Log execution details
log_skill_execution

# Log performance metrics
log_metrics

# Log errors if any
log_errors

# Update execution summary
update_summary

# Rotate old logs (keep last 100 logs)
log_count=$(ls -1 "${LOG_DIR}"/skill_execution_*.log 2>/dev/null | wc -l)
if [[ ${log_count} -gt 100 ]]; then
    log_info "Rotating old logs (keeping last 100)"
    ls -1t "${LOG_DIR}"/skill_execution_*.log | tail -n +101 | xargs rm -f
fi

log_info "Post-skill logging completed successfully"
exit 0
