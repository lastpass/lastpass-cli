#!/bin/bash
#
# Run sudo using lpass-sudo-askpass
#
# Copyright (c) 2014 LastPass. All Rights Reserved.
#
PREFIX=/usr/bin
export SUDO_ASKPASS=$PREFIX/lpass-sudo-askpass.sh
exec $PREFIX/sudo -A "$@"
