#!/bin/bash
# The fixed bridge takes one admitted native frame per process; no console text.
# Only its exits for a finished or idle turn start the next one.
set -eu
if (( $# != 0 )); then exit 64; fi
while :; do
  status=0
  /bin/paos-chat-portal || status=$?
  case $status in
    0|65|75) ;;
    *) exit "$status" ;;
  esac
done
