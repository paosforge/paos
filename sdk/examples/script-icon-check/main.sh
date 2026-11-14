#!/bin/bash
# Bash built-ins and the paos helper only. BEGIN lets the native launch flow
# show this app's staged form; STATUS alone does not establish readiness.
set -u
window=$(paos WINDOW) || exit 1
cursor=0

field() {
    local rest=${2#*\"$1\":}
    rest=${rest%%[,\}]*}
    printf '%s' "$rest"
}

while :; do
    reply=$(paos WAIT BEGIN "$window" "$cursor" 5000) || exit 1
    state=$(field state "$reply")
    token=$(field token "$reply")
    while [[ $state == 1 ]]; do
        reply=$(paos WAIT POLL "$window" "$token") || exit 1
        state=$(field state "$reply")
    done
    case $state in
        2|5) cursor=$(field cursor "$reply") ;;
        3) ;;  # timeout: begin another bounded wait
        4) exit 0 ;;  # cancelled
        *) exit 1 ;;
    esac
done
