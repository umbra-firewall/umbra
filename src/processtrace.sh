#!/bin/bash

# Copyright 2015 Regents of the University of Michigan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
