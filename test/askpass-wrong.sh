#!/bin/bash
. $(dirname $0)/include.sh

# this lockfile keeps login from getting stuck in a loop
if [[ -e .askpass.lock ]]; then
	exit 1
fi
touch .askpass.lock
echo $TEST_WRONG_PASS
