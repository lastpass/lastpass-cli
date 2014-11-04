# LastPass CLI
#### (c) 2014 LastPass.

C99 command line interface to [LastPass.com](https://lastpass.com/).

## Operating System Support

`lpass` is designed to run on GNU/Linux, Cygwin and Mac OS X.

## Dependencies

* [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/)
* [libcurl](http://curl.haxx.se/)
* [libxml2](http://xmlsoft.org/)
* [pinentry](https://www.gnupg.org/related_software/pinentry/index.en.html) (optional)
* [AsciiDoc](http://www.methods.co.nz/asciidoc/) (build-time documentation generation only)
* [xclip](http://sourceforge.net/projects/xclip/), [xsel](http://www.vergenet.net/~conrad/software/xsel/), [pbcopy](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/pbcopy.1.html), or [putclip from cygutils-extra](https://cygwin.com/cgi-bin2/package-grep.cgi?grep=cygutils-extra) for clipboard support (optional)

### Installing on Linux
#### Redhat/Centos
* Install the needed dependencies

```
sudo yum install openssl libcurl libxml2 pinentry xclip openssl-devel libxml2-devel libcurl-devel
```


##### Debian/Ubuntu
* Debian: Install the needed dependencies

```
sudo apt-get install openssl libcurl3 libxml2 libssl-dev libxml2-dev libcurl4-openssl-dev pinentry-curses xclip
```

* Ubuntu: Install the needed dependencies

```
sudo apt-get install openssl libcurl4-openssl-dev libxml2 libssl-dev libxml2-dev pinentry-curses xclip
```

#### Gentoo
* Install the package
```
sudo emerge lastpass-cli
```

##### Other Linux Distros
Install the packages listed in the Dependencies section of this document.

### Installing on OS X
* Install homebrew following the instructions at http://brew.sh/
* Install lastpass-cli using homebrew:

```
brew install lastpass-cli --with-pinentry
```

Optionally you can add `--with-doc` to install the documentation.

### Installing on FreeBSD
* Install the binary package

```
sudo pkg install security/lastpass-cli
```

* Or build the port yourself
```
sudo make -C /usr/ports/security/lastpass-cli all install clean
```

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

The `install-doc` target builds and installs the documentation.
It requires AsciiDoc as a prerequisite.

    $ sudo make install-doc

Once installed,

    $ man lpass
