#!/bin/bash

#
# Changes unix passwords by sshing in and calling passwd.
#
# Copyright (c) 2014 LastPass.
#

if [[ $# != 1 ]]; then
	echo "Usage: $0 hostname"
	exit 1
fi

change_password() {
	HOST="$2@$1" OLD_PASSWORD="$3" NEW_PASSWORD="$4" expect <<-_EOF
	set timeout 15
	set old_password \$env(OLD_PASSWORD)
	set new_password \$env(NEW_PASSWORD)
	set host \$env(HOST)
	spawn ssh "\$host"
	expect {
		"(yes/no)?" {
			send_user "Host key is not recognized. Exiting early.\n"
			send "no\\n"
			exit 1
		}
		"assword:" {
			send -- "\$old_password\n"
		}
	}
	expect {
		"assword:" {
			send_user "Invalid password.\n"
			exit 1
		}
		-re "\\\$|#" {
			send "passwd\n"
			expect "assword:"
			send -- "\$old_password\n"
			expect {
				"failure" {
					send_user "Old password did not work.\n"
					exit 1
				}
				"assword:" {
					send -- "\$new_password\n"
				}
			}
			expect {
				"BAD PASSWORD" {
					send_user "Bad password.\n"
					exit 1
				}
				"unchanged" {
					send_user "New password is not new.\n"
					exit 1
				}
				"assword:" {
					send "\$new_password\n"
				}
			}
			expect {
				"successfully" {
					send_user "Password successfully updated.\n"
					exit 0
				}
				default {
					send_user "Could not update password.\n"
					exit 1
				}
			}
		}
	}
	exit 1
	_EOF
	return $?
}

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

if ! change_password "$hostname" "$username" "$password" "$new_password"; then
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
