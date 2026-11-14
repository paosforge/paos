#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The app has no command, filesystem, network or other-window authority.
set -u
field() { local rest=${2#*\"$1\":}; rest=${rest%%[,\}]*}; printf '%s' "$rest"; }
text_field() { local rest=${2#*\"$1\":\"}; rest=${rest%%\"*}; printf '%s' "$rest"; }
window=$(paos WINDOW) || exit 1
cursor=0
while :; do
    reply=$(paos WAIT BEGIN "$window" "$cursor" 5000) || exit 1
    state=$(field state "$reply"); token=$(field token "$reply")
    while [[ $state == 1 ]]; do
        reply=$(paos WAIT POLL "$window" "$token") || exit 1
        state=$(field state "$reply")
    done
    case $state in
        2)
            cursor=$(field cursor "$reply")
            action=$(text_field action "$reply"); widget=$(text_field widget "$reply")
            case "$action:$widget" in
                CONVERT:convert)
                    input=$(paos WIDGET GET "$window" fahrenheit) || exit 1
                    if [[ $input =~ ^-?(0|[1-9][0-9]{0,3})$ ]] && (( input >= -459 && input <= 9999 )); then
                        tenths=$(( (input - 32) * 50 / 9 ))
                        sign=''; (( tenths < 0 )) && sign='-'
                        (( tenths < 0 )) && tenths=$(( -tenths ))
                        output="$sign$(( tenths / 10 )).$(( tenths % 10 )) C"
                    else
                        output='Enter -459 to 9999 whole F'
                    fi
                    paos WIDGET SET "$window" result "$output" || exit 1
                    ;;
                RESTORE:restore)
                    paos WIDGET SET "$window" result 'No conversion yet' || exit 1
                    ;;
            esac
            ;;
        3) ;;
        4) exit 0 ;;
        5) exit 1 ;; # Missing events cannot authorize a later action.
        *) exit 1 ;;
    esac
done
