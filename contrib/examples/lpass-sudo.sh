#!/bin/sh
#
# Run sudo using lpass-sudo-askpass
#
# Copyright (c) 2014 LastPass.
#
PREFIX=/usr/bin
SUDO_ASKPASS=$PREFIX/lpass-sudo-askpass.sh
export SUDO_ASKPASS
exec $PREFIX/sudo -A "$@"
