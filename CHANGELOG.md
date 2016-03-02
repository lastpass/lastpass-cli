# Version 0.8.1, 0.7.2, 0.6.1, 0.5.1
 * This update to all recent versions switches to the platform certificate
   store and adds pinning of LastPass public keys, in preparation for
   certificate changes at lastpass.com. Upgrade will be needed to avoid "Peer
   certificate cannot be authenticated with given CA certificates" errors
   when the cert changes are made.

# Version 0.8.0
 * New command ```lpass add``` works like ```lpass edit``` for new accounts
 * New command ```lpass mv``` can be used to move an account into a different (possibly shared) folder
 * New command ```lpass passwd``` can be used to change master password
 * Tab-completion for bash is now available; to use, source ```contrib/lpass_bash_completion``` from a bash startup file
 * ```lpass ls``` now interprets backslash properly for subfolder display
 * ```lpass edit``` gained the ability to edit all fields of an account at once by using a specially-formatted edit buffer
 * ```lpass show``` gained the ability to show multiple accounts at once, from Angus Galloway
 * ```lpass show``` now reformats SSH private key fields in secure notes into a usable form
 * ```lpass share useradd``` gained the ability to specify group names
 * ```lpass share``` got better documentation
 * Bugfix: logins with certain multifactors that support out-of-band authentication will now work correctly
 * Blob edits no longer reencrypt the entire database, just the changed accounts
 * Syncing operation is now much more robust in the face of server errors or
   invalid transactions.
 * OSX builds fixed for Xcode-less installations, with help from Wael Nasreddine
 * Corrections to FSF address from Tom Prince

# Version 0.7.1
 * This bugfix release fixes a build issue on OSX platforms without XCode. It is otherwise identical to 0.7.0.

# Version 0.7.0
 * ```lpass``` now supports aliases in order to set preferred switches or nicknames for commands. ```echo 'show -G' > ~/.lpass/alias.show```, for example, will turn regex matching on for ```lpass show```.
 * In addition to pinentry and in-process prompting, the ```LPASS_ASKPASS``` environment variable/config value is now checked for a binary to ask for passwords.  It uses the same conventions as ssh-askpass.
 * ```lpass show``` will now match account id when using regex or substring matching
 * ```lpass ls``` learned the ```-l [-u]```switches to show mod and use times, from Lloyd Zusman
 * Secure notes are now created by default when empty sites are edited with --notes, from Lloyd Zusman
 * The new ```LPASS_CLIPBOARD_COMMAND``` environment variable/config value can be used to configure the helper application for the system clipboard, from Tom Prince.  Among other things, you can use this to clear the clipboard after a certain number of pastes with ```xclip -l```.
 * Various code cleanups and documentation fixes from Tom Prince.
 * The license has been clarified to GPLv2 or later, plus the OpenSSL exception; please see individual files and the LICENSE.OpenSSL / COPYING files for details.  This was the intended license all along but it was not spelled out consistently.

# Version 0.6.0
 *  New share sub-command allows automating some common tasks with shared folders
 *  PBKDF2 speedups from Thomas Hurst
 *  Ungrouped entries now fall under "(none)" heading, from Gordon Celesta
 *  Documentation updates from Eli Young
 *  Cleanups from Björn Ketelaars

# Version 0.5.1
 * Update Thawte CA cert to support lastpass.com's new SHA-256 cert.

# Version 0.5.0
 *  OpenBSD support
 *  Updated build/install instructions for Cygwin, Debian, and RPM-based distributions
 *  Regex and substring searching for cmd-show
 *  Secure note parsing and field display
 *  Fixes for pinentry errors and hangs
