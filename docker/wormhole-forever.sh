#!/bin/bash

# Showing help or license then exit normally.
if [ "$1" = "-h" ] || [ "$1" = "--help" ] \
|| [ "$1" = "-l" ] || [ "$1" = "--license" ]; then
    /wormhole/bin/wormhole $*
else  # Else, run wormhole forever even the process was killed.
    trap "exit" INT  # But allow it to exit normally via Control-C.
    while true; do
        /wormhole/bin/wormhole $*
        sleep 1
    done
fi
