# LastPass CLI
#### by Jason A. Donenfeld <jasond@lastpass.com>

C99 command line interface to [LastPass.com](https://lastpass.com/).


## Operating System Support

`lpass` is designed to run on GNU/Linux, Cygwin and Mac OS X.

## Dependencies 

* [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/)
* [libcurl](http://curl.haxx.se/)
* [libxml2](http://xmlsoft.org/)
* [pinentry](https://www.gnupg.org/related_software/pinentry/index.en.html) (optional)
* [AsciiDoc](http://www.methods.co.nz/asciidoc/) (build-time documentation generation only)
* [xclip](http://sourceforge.net/projects/xclip/), [xsel](http://www.vergenet.net/~conrad/software/xsel/), or [pbcopy](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/pbcopy.1.html) for clipboard support (optional)

## Building

    $ make

## Installing

    $ sudo make install

These environment variables can be passed to make to do the right thing: `PREFIX`, `DESTDIR`, `BINDIR`, `LIBDIR`, `MANDIR`.

## Running

If you've installed it:

    $ lpass

Otherwise, from the build directory:

    $ ./lpass

## Documentation

The `install-doc` target builds and installs the documentation.  It requires
AsciiDoc as a prerequisite.

    $ make install-doc

Once installed,

    $ man lpass


## Contributing

Contributions are welcome!  Please send a pull request at github:

    https://github.com/lastpass/lastpass-cli

The project is licensed under the GPL version 2 (see COPYING) and
requires acceptance of the Developer's Certificate of Origin for
contributions (see below).

To indicate your acceptance of Developer's Certificate of Origin 1.1
terms, please add the following line to the end of the commit message
for each contribution you make to the project:

Signed-off-by: Your Name <your@email.example.org>

using your real name. Pseudonyms or anonymous contributions cannot
unfortunately be accepted.

---------------------------------------------------------------------------

Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.

---------------------------------------------------------------------------
