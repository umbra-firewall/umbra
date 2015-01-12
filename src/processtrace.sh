#!/bin/bash
#
# Usage:  ./shim-trace 8080 80 | ./processtrace.sh ./shim-trace

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 TRACE_BINARY"
	exit 1
fi

if test ! -f "$1"
then
 echo "Error: executable $1 does not exist."
 exit 1
fi

EXECUTABLE="$1"

print_n_space() {
    amt=$(echo "$1 * 2" | bc)
    python -c 'import sys;sys.stdout.write(int(sys.argv[1]) * " ")' $amt
}

depth=0
while read LINE; do
    echo "$LINE" | egrep -q '^e|x( [0-9a-fA-Fx]+){3}'
    if [[ $? == 0 ]]; then
        #LINETYPE FADDR CADDR CTIME
        LINE_ARR=(${LINE// / })   # make array
        LINETYPE="${LINE_ARR[0]}"
        FADDR="${LINE_ARR[1]}"
        CADDR="${LINE_ARR[2]}"
        CTIME="${LINE_ARR[3]}"
        FNAME="$(addr2line -f -e ${EXECUTABLE} ${FADDR}|head -1)"
        CDATE="$(date -Iseconds -d @${CTIME})"

        if test "${LINETYPE}" = "e" ; then
            CNAME="$(addr2line -f -e ${EXECUTABLE} ${CADDR}|head -1)"
            CLINE="$(addr2line -s -e ${EXECUTABLE} ${CADDR})"
            print_n_space $depth
            echo "Enter ${FNAME} at ${CDATE}, called from ${CNAME} (${CLINE})"
            depth=$(expr $depth + 1)
        elif test "${LINETYPE}" = "x"; then
            depth=$(expr $depth - 1)
            print_n_space $depth
            echo "Exit  ${FNAME} at ${CDATE}"
        fi
    else
        echo "$LINE"
    fi
done
