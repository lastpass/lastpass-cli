#!/bin/bash

#
# Changes MySQL passwords.
#
# Copyright (c) 2014 LastPass.
#

if [[ $# != 1 ]]; then
	echo "Usage: $0 hostname"
	exit 1
fi

hostname="$1"
username="$(lpass show --username "$hostname")"
password="$(lpass show --password "$hostname")"

if [[ -z $username || -z $password || -z $hostname ]]; then
	echo "Could not fetch credentials."
	exit 1
fi

temporary_password_name="temporary-passwords/${hostname}_$RANDOM$RANDOM$RANDOM"
number_of_characters="$(shuf -i 15-30 -n 1)"
new_password="$(lpass generate "$temporary_password_name" "$number_of_characters")"

if [[ -z $new_password ]]; then
	echo "Could not generate new password."
	exit 1
fi

lpass sync

if ! mysqladmin -h "$hostname" -u "$username" "-p$password" password "$new_password"; then
	lpass rm "$temporary_password_name"
	echo "Failed to change password for ${hostname}."
	exit 1
fi

if ! lpass edit --non-interactive --password "$hostname" <<<"$new_password"; then
	echo "Warning: could not change password of $hostname entry. Current password lives in ${temporary_password_name}."
	exit 1
fi

lpass sync
lpass rm "$temporary_password_name"
