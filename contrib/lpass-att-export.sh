#!/bin/bash
##
## Usage: lpass-att-export.sh
##
##

usage() { echo "Usage: $0 [-l <email>] [-o <outdir>] [-i <id>]" 1>&2; exit 1; }

while getopts ":i:o:hl:" o; do
    case "${o}" in
        i)
            id=${OPTARG}
            ;;
        o)
            outdir=${OPTARG}
            ;;
        l)
            email=${OPTARG}
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${outdir}" ]; then
    usage
fi

command -v lpass >/dev/null 2>&1 || { echo >&2 "I require lpass but it's not installed.  Aborting."; exit 1; }

if [ ! -d ${outdir} ]; then
  echo "${outdir} does not exist. Exiting."
  exit 1
fi

if ! lpass status; then
  if [ -z ${email} ]; then
    echo "No login data found, Please login with -l or use lpass login before."
    exit 1;
  fi
  lpass login ${email}
fi

if [ -z ${id} ]; then
  ids=$(lpass ls | sed -n "s/^.*id:[[:space:]]*\([0-9]*\).*$/\1/p")
else
  ids=${id}
fi

for id in ${ids}; do
  show=$(lpass show ${id})
  attcount=$(echo "${show}" | grep -c "att-")
  path=$(lpass show --format="%/as%/ag%an" ${id} | uniq | tail -1)

  until [  ${attcount} -lt 1 ]; do
    att=`lpass show ${id} | grep att- | sed "${attcount}q;d" | tr -d :`
    attid=$(echo ${att} | awk '{print $1}')
    attname=$(echo ${att} | awk '{print $2}')

    if [[ -z  ${attname}  ]]; then
      attname=${path#*/}
    fi

    path=${path//\\//}
    mkdir -p "${outdir}/${path}"
    out=${outdir}/${path}/${attname}

    if [[ -f ${out} ]]; then
        out=${outdir}/${path}/${attcount}_${attname}
    fi

    echo ${id} - ${path} ": " ${attid} "-" ${attname} " > " ${out}

    lpass show --attach=${attid} ${id} --quiet > "${out}"

    let attcount-=1
  done
done

