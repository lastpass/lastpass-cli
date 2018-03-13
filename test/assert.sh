#! /bin/bash
#
# various assert functions
#
function assert_ne
{
	if [[ $1 -eq $2 ]]; then
		echo "FAIL: \"$1 != $2\" $3"
		return 1
	fi
}

function assert_eq
{
	if [[ $1 -ne $2 ]]; then
		echo "FAIL: \"$1 == $2\" $3"
		return 1
	fi
}

function assert_str_neq
{
	local s1="$(echo $1 | sed -e "s/  *$//g")"
	local s2="$(echo $2 | sed -e "s/  *$//g")"

	if [[ "$s1" == "$s2" ]]; then
		echo "FAIL: \"$1 != $2\" $3"
		return 1
	fi
}

function assert_str_eq
{
	local s1="$(echo $1 | sed -e "s/  *$//g")"
	local s2="$(echo $2 | sed -e "s/  *$//g")"

	if [[ "$s1" != "$s2" ]]; then
		echo "FAIL: \"$s1 == $s2\" $3"
		return 1
	fi
}

function assertz
{
	assert_eq $1 0 $2
}

function assert
{
	assert_ne $1 0 $2
}
