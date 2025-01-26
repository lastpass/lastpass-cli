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

if [ ! -d "${outdir}" ]; then
  echo "${outdir} does not exist. Exiting."
  exit 1
fi

if ! lpass status; then
  if [ -z "${email}" ]; then
    echo "No login data found, Please login with -l or use lpass login before."
    exit 1;
  fi
  lpass login "${email}"
fi

if [ -z "${id}" ]; then
  # Get the ids of items that might have an attachment
  # remove trailing carriage return if it's there
  ids=$(lpass export --fields=id,attachpresent | grep ',1' | sed 's/,1\r\{0,1\}//')
else
  ids=${id}
fi

for id in ${ids}; do
  show=$(lpass show "${id}")
  attcount=$(echo "${show}" | grep -c "att-")
  path=$(lpass show --format="%/as%/ag%an" "${id}" | uniq | tail -1)

  until [ "${attcount}" -lt 1 ]; do
    # switch to read because the original way truncated filenames containing spaces
    read -r attid attname <<< "$(lpass show "${id}" | grep att- | sed "${attcount}q;d" | tr -d :)"

    if [[ -z  ${attname}  ]]; then
      attname=${path#*/}
    fi

    path=${path//\\//}
    mkdir -p "${outdir}/${path}"
    out=${outdir}/${path}/${attname}

    if [[ -f ${out} ]]; then
        out=${outdir}/${path}/${attcount}_${attname}
    fi

    echo "${id} - ${path} :  ${attid} - ${attname}  >  ${out}"

    lpass show "--attach=${attid}" "${id}" --quiet > "${out}"

    (( attcount-=1 )) || true
  done
done

