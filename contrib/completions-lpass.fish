# fish-shell completion for lastpass-cli
#
# for single-user installation, copy this file to
# ~/.config/fish/completions/lpass.fish

function __lpass_entries
    lpass ls --sync auto --color never \
        | string replace -r '^(\(none\)/)?(.*)' '$2' \
        | string replace -r '^ \[id: (\d+)\]$' '$1' \
        | string replace -r '^(.*) \[id: \d+\]$' '$1'
end

function __lpass_needs_command
    set cmd (commandline -opc)
    test (count $cmd) -eq 1
end

function __lpass_using_command
    set cmd (commandline -opc)
    test (count $cmd) -gt 1
    and contains -- $cmd[2] $argv
end

complete -f -c lpass -l help -n '__lpass_needs_command' -d 'Print usage'
complete -f -c lpass -l version -n '__lpass_needs_command' -d 'Print version'

# Commands
complete -f -c lpass -n '__lpass_needs_command' -a add \
    -d 'Add entry'
complete -f -c lpass -n '__lpass_needs_command' -a duplicate \
    -d 'Duplicate password'
complete -f -c lpass -n '__lpass_needs_command' -a edit \
    -d 'Edit entry'
complete -f -c lpass -n '__lpass_needs_command' -a export \
    -d 'Export passwords as CSV'
complete -f -c lpass -n '__lpass_needs_command' -a generate \
    -d 'Create a new entry with a generated password'
complete -f -c lpass -n '__lpass_needs_command' -a import \
    -d 'Import CSV as passwords'
complete -f -c lpass -n '__lpass_needs_command' -a login \
    -d 'Login to LastPass'
complete -f -c lpass -n '__lpass_needs_command' -a logout \
    -d 'Logout from LastPass'
complete -f -c lpass -n '__lpass_needs_command' -a ls \
    -d 'List entries'
complete -f -c lpass -n '__lpass_needs_command' -a mv \
    -d 'Move entry to group'
complete -f -c lpass -n '__lpass_needs_command' -a passwd \
    -d 'Change your LastPass master password'
complete -f -c lpass -n '__lpass_needs_command' -a rm \
    -d 'Remove entry'
complete -f -c lpass -n '__lpass_needs_command' -a share \
    -d 'Perform operations on a share'
complete -f -c lpass -n '__lpass_needs_command' -a show \
    -d 'Show entry details'
complete -f -c lpass -n '__lpass_needs_command' -a status \
    -d 'Show status'
complete -f -c lpass -n '__lpass_needs_command' -a sync \
    -d 'Synchronize local cache with server'

# {UNIQUENAME|UNIQUEID}
complete -f -c lpass \
    -n '__lpass_using_command show mv edit generate duplicate rm' \
    -a '(__lpass_entries)'

# --all
complete -f -c lpass -n '__lpass_using_command show' \
    -l all \
    -d 'All fields'

# --attach=ATTACHID
complete -f -c lpass -n '__lpass_using_command show' \
    -l attach \
    -d 'Attach'

# --background -b
complete -f -c lpass -n '__lpass_using_command sync' \
    -s b -l background \
    -d 'Synchronize in background'

# --basic-regexp -G
complete -f -c lpass -n '__lpass_using_command show' \
    -s G -l basic-regexp \
    -d 'Search with regular expression'

# --clip -c
complete -f -c lpass -n '__lpass_using_command show generate' \
    -s c -l clip \
    -d 'Copy output to clipboard'

# --color=COLOR
complete -f -c lpass \
    -n '__lpass_using_command login logout show ls mv add edit duplicate rm sync export status' \
    -r -l color \
    -a 'auto never always' \
    -d 'When to use colors'

# --expand-multi
complete -f -c lpass -n '__lpass_using_command show' \
    -s x -l expand-multi \
    -d 'Expand multi'

# --field=FIELD
complete -f -c lpass -n '__lpass_using_command show add edit' \
    -r -l field \
    -d 'Custom field'

# --fields=FIELDLIST
complete -f -c lpass -n '__lpass_using_command export' \
    -r -l fields \
    -d 'Field list'

# --fixed-strings -F
complete -f -c lpass -n '__lpass_using_command show' \
    -s F -l fixed-strings \
    -d 'Search substrings'

# --force -f
complete -f -c lpass -n '__lpass_using_command login logout' \
    -s f -l force \
    -d 'Do not ask for confirmation'

# --format=FMTSTR
complete -f -c lpass -n '__lpass_using_command show ls' \
    -l format \
    -d 'Format string'

# --id
complete -f -c lpass -n '__lpass_using_command show' \
    -l id \
    -d 'ID'

# --long -l
complete -f -c lpass -n '__lpass_using_command ls' \
    -s l -l long \
    -d 'More info'

# -m
complete -f -c lpass -n '__lpass_using_command ls' \
    -s m \
    -d 'Modified time'

# --name
complete -f -c lpass -n '__lpass_using_command edit show' \
    -l name \
    -d 'Name'

# --non-interactive
complete -f -c lpass -n '__lpass_using_command add edit' \
    -l non-interactive \
    -d 'Use standard input instead of $EDITOR'

# --no-symbols
complete -f -c lpass -n '__lpass_using_command generate' \
    -l no-symbols \
    -d 'No symbols'

# --note-type=NOTETYPE
complete -f -c lpass -n '__lpass_using_command add' \
    -r -l note-type \
    -d 'Note type'

# --notes
complete -f -c lpass -n '__lpass_using_command show add edit' \
    -l notes \
    -d 'Notes'

# --password
complete -f -c lpass -n '__lpass_using_command show add edit' \
    -l password \
    -d 'Password'

# --plaintext-key
complete -f -c lpass -n '__lpass_using_command login' \
    -l plaintext-key \
    -d 'Store key in plain text'

# --quiet -q
complete -f -c lpass -n '__lpass_using_command status' \
    -s q -l quiet \
    -d 'No output'

# --sync=SYNC
complete -f -c lpass \
    -n '__lpass_using_command show ls add edit generate duplicate rm export import' \
    -r -l sync \
    -a 'auto now no' \
    -d 'Synchronize local cache with server'

# --trust
complete -f -c lpass -n '__lpass_using_command login' \
    -l trust \
    -d 'Do not require multifactor authentication for next logins'

# -u
complete -f -c lpass -n '__lpass_using_command ls' \
    -s u \
    -d 'Last used time'

# --url=URL
complete -f -c lpass -n '__lpass_using_command generate' \
    -r -l url \
    -d 'URL'

# --url
complete -f -c lpass -n '__lpass_using_command show add edit' \
    -l url \
    -d 'URL'

# --username
complete -f -c lpass -n '__lpass_using_command show add edit' \
    -l username \
    -d 'Username'

# --username=USERNAME
complete -f -c lpass -n '__lpass_using_command generate' \
    -r -l username \
    -d 'Username'
