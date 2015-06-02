#!/usr/bin/env bash
awk 'BEGIN {printf "#define CERTIFICATE_THAWTE \""} {printf "%s\\n", $0} END {printf "\"\n"}' $1 > $2
