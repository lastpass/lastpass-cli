# fish-shell completion for lastpass-cli
# for single-user installation, copy this file to ~/.config/fish/completions/lpass.fish
function __lpass_subcommands
    lpass --help \
        | grep lpass \
        | grep -v -- '--help' \
        | sed -n 's/^  //p' \
        | cut -f 2 -d" "
end

function __lpass_entries
    set -l id_re '\[id: ([0-9][0-9]*)\]$'
    set -l id_re_escaped '\[id: \([0-9][0-9]*\)\]$'
    for entry in (lpass ls --sync auto)
        if not begin; echo $entry | grep -e '. '$id_re_escaped > /dev/null; end;
            # Entry has no name
            set -l out (string replace -r '.* '$id_re '$1' $entry)
            echo $out
        else
            # Strip '(none)/' from output since it's printed by `lpass ls`, but
            # not accepted by `lpass show`
            set -l out (string replace -r '\(none\)/(.*) '$id_re '$1' $entry)
            echo $out
        end
    end
end

function __lpass_needs_command
    set cmd (commandline -opc)

    if test (count $cmd) -eq 1
        return 0
    end

    return 1
end

function __lpass_has_command
    if __lpass_needs_command
        return 1
    else
        return 0
    end
end

function __lpass_using_command
    set cmd (commandline -opc)

    if test (count $cmd) -gt 1
        for arg in $argv
            if test "$arg" = "$cmd[2]"
                return 0
            end
        end
    end

    return 1
end

complete -f -c lpass -l help -d "Print usage"
complete -f -c lpass -n '__lpass_needs_command' -a login -d 'Login to LastPass'
complete -f -c lpass -n '__lpass_needs_command' -a show -d 'Show entry details'
complete -f -c lpass -n '__lpass_needs_command' -a generate -d 'Generate password'
complete -f -c lpass -n '__lpass_needs_command' -a add -d 'Add entry'
complete -f -c lpass -n '__lpass_needs_command' -a edit -d 'Edit entry'
complete -f -c lpass -n '__lpass_needs_command' -a sync -d 'Synchronize local cache with server'

# {UNIQUENAME|UNIQUEID}
complete -f -c lpass \
    -n '__lpass_using_command show mv edit generate duplicate rm' \
    -a '(__lpass_entries)'

# --background
complete -f -c lpass \
    -n '__lpass_using_command sync' \
    -s b -l background \
    -d 'Synchronize in background'

# --sync=SYNC
complete -f -c lpass \
    -n '__lpass_using_command show ls add edit generate dubplicate rm export' \
    -r -l sync \
    -d 'Synchronize local cache with server: auto | now | no'

# --color=COLOR
complete -f -c lpass \
    -n '__lpass_using_command login logout show ls mv add edit duplicate rm sync export' \
    -r -l color \
    -d 'Color: auto | never | always'

# --clip
complete -f -c lpass -n '__lpass_using_command show generate' \
    -s c -l clip \
    -d 'Copy output to clipboard'

# --expand-multi
complete -f -c lpass -n '__lpass_using_command show' \
    -s x -l expand-multi \
    -d 'Expand multi'

# --all
complete -f -c lpass -n '__lpass_using_command show' \
    -l all \
    -d 'All fields'

# --url
complete -f -c lpass -n '__lpass_using_command show add' \
    -l url \
    -d 'URL'

# --url=URL
complete -f -c lpass -n '__lpass_using_command generate' \
    -r -l url \
    -d 'URL'

# --field=FIELD
complete -f -c lpass -n '__lpass_using_command show add' \
    -r -l field \
    -d 'Field'

# --notes
complete -f -c lpass -n '__lpass_using_command show add' \
    -l notes \
    -d 'Notes'

# --username
complete -f -c lpass -n '__lpass_using_command show add' \
    -l username \
    -d 'Username'

# --username=USERNAME
complete -f -c lpass -n '__lpass_using_command generate' \
    -r -l username \
    -d 'Username'

# --password
complete -f -c lpass -n '__lpass_using_command show' \
    -l password \
    -d 'Password'
