#!/bin/sh
#
# Tell sudo the user's password (based on hostname match).
# See lpass-sudo for the caller that sets up the environ.
#
# Copyright (c) 2014 LastPass.
#
PREFIX=/usr/bin
if [ -z "$HOSTNAME" ]; then
	HOSTNAME=`hostname`
fi

$PREFIX/lpass show --password $HOSTNAME
