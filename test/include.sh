#!/bin/bash

function setup()
{
	cd `dirname $0`
	. assert.sh
	export LPASS_ASKPASS=./askpass.sh
	export TEST_USER="user@example.com"
	export TEST_PASS="123456"
	export TEST_WRONG_PASS="000000"
	export TEST_LPASS="../build/lpass-test"
	export LPASS_HOME="./.lpass"
}

function setup_testcase()
{
	# start with fresh blob for every test
	rm $LPASS_HOME/blob 2>/dev/null
}

function runtests()
{
	local tests=${1:-$(compgen -A function test_)}
	local ret=0
	for fn in $tests; do
		setup_testcase
		echo "*** $fn ***"
		$fn
		this_ret=$?
		if [[ $this_ret -eq 0 ]]; then
			echo "pass"
		else
			ret=1
		fi
	done
	return $ret
}

function lpass()
{
	$TEST_LPASS "$@"
}

function login()
{
	# login and download the blob
	lpass login $TEST_USER >/dev/null 2>&1 && lpass ls >/dev/null 2>&1
}

setup
