__lpass_complete_fieldname()
{
    local acct=$1
    local cur=$2
    local matches

    matches=$(lpass show $acct --format='%fn' --title-format=' ' | \
              egrep -v '^ $')

    local IFS=$'\n'
    COMPREPLY=($(compgen -W "$matches" "$cur"))
    if [[ ! -z $COMPREPLY ]]; then
        COMPREPLY=($(printf "%q\n" "${COMPREPLY[@]}"))
    fi
}

__lpass_complete_name()
{
    local cur=$1
    local matches

    # matches on full path
    matches=$(lpass ls | egrep "^$cur" | sed -e "s/ \[id.*//g")
    # matches on leaves
    matches+=$(lpass ls | egrep "/$cur" | sed -e "s/ \[id.*//g" | \
               awk -F '/' '{print $NF}')

    local IFS=$'\n'
    COMPREPLY=($(compgen -W "$matches" "$cur"))
    if [[ ! -z $COMPREPLY ]]; then
        COMPREPLY=($(printf "%q\n" "${COMPREPLY[@]}"))
    fi
}

__lpass_complete_group()
{
    local cur=$1
    local matches
    matches=$(lpass ls | egrep "^$cur.*/" | awk -F '/' '{print $1}')

    local IFS=$'\n'
    COMPREPLY=($(compgen -W "$matches" "$cur"))
    if [[ ! -z $COMPREPLY ]]; then
        COMPREPLY=($(printf "%q\n" "${COMPREPLY[@]}"))
    fi
}

__lpass_complete_opt()
{
    local cmd=$1
    local cur=$2
    local name=$3
    opts=""

    case "$cmd" in
        login)
            opts="--trust --plaintext-key --force --color"
            ;;
        logout)
            opts="--force --color"
            ;;
        show)
            opts="--sync --clip --expand-multi --all --username --password --url --notes --field --id --name --basic-regexp --fixed-strings --color"
            ;;
        ls)
            opts="--sync --long --color"
            ;;
        mv|duplicate|rm|export|import)
            opts="--sync --color"
            ;;
        edit)
            opts="--sync --non-interactive --name --username --password --url --notes --field --color"
            ;;
        generate)
            opts="--sync --clip --username --url --no-symbols --color"
            ;;
        share)
            opts="--read_only --hidden --admin"
    esac

    COMPREPLY=($(compgen -W "$opts" -- $cur))
}

_lpass()
{
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local cmd="${COMP_WORDS[1]}"
    local subcmd="${COMP_WORDS[2]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local optind=1

    for i in `seq 2 $COMP_CWORD`; do
        if [[ ${COMP_WORDS[COMP_CWORD]} != "-*" ]]; then
            optind=i
            break
        fi
    done

    local name="${COMP_WORDS[$optind]}"

    local all_cmds="
        login logout passwd show ls mv add edit generate
        duplicate rm sync export import share
    "
    local share_cmds="
        userls useradd usermod userdel create rm
    "

    # include aliases (although we can't really do much with them)
    for a in ~/.lpass/alias.*; do
        all_cmds="$all_cmds ${a#*alias.}"
    done

    # subcommands
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$all_cmds" $cur))
        return
    # share subcommands
    elif [[ $COMP_CWORD -eq 2 && $cmd == "share" ]]; then
        COMPREPLY=($(compgen -W "$share_cmds" $cur))
        return
    fi

    COMPREPLY=()

    case "$prev" in
        --field)
            __lpass_complete_fieldname $name $cur
            return
            ;;
    esac

    case "$cur" in
        -*)
            __lpass_complete_opt $cmd $cur
            return
            ;;
    esac

    case "$cmd" in
        show|rm|edit|duplicate|generate)
            __lpass_complete_name $cur
            ;;
        mv)
            if [[ $COMP_CWORD -eq $optind ]]; then
                __lpass_complete_name $cur
            else
                __lpass_complete_group $cur
            fi
            ;;
        ls|add)
            __lpass_complete_group $cur
            ;;
        share)
            case "$subcmd" in
                userls|useradd|usermod|userdel|rm)
                    if [[ $cur != "Shared-*" ]]; then
                        cur="Shared-$cur"
                    fi
                    __lpass_complete_group $cur
                    ;;
                create)
                    ;;
            esac
            ;;
        *)
            ;;
    esac
}

complete -o default -F _lpass lpass
