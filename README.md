# LastPass CLI
#### (c) 2014-2015 LastPass.

Command line interface to [LastPass.com](https://lastpass.com/).

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
#### Arch
* Binary packages are available in the Arch User Repository [AUR](https://aur.archlinux.org/packages.php?O=0&L=0&C=0&K=lastpass-cli).


#### Redhat/Centos
* Install the needed build dependencies, and then follow instructions in
  the 'Building' section.

```
sudo yum install openssl libcurl libxml2 pinentry xclip openssl-devel libxml2-devel libcurl-devel
```


#### Debian/Ubuntu
* Install the needed build dependencies, and then follow instructions in
  the 'Building' section.

* For Debian:

```
sudo apt-get install openssl libcurl3 libxml2 libssl-dev libxml2-dev libcurl4-openssl-dev pinentry-curses xclip
```

* For Ubuntu:

```
sudo apt-get install openssl libcurl4-openssl-dev libxml2 libssl-dev libxml2-dev pinentry-curses xclip
```

#### Gentoo
* Install the package

```
sudo emerge lastpass-cli
```

#### Other Linux Distros
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

### Installing on Cygwin
* Install [apt-cyg](https://github.com/transcode-open/apt-cyg)
* Using apt-cyg, install the needed dependencies

```
apt-cyg install wget make gcc-core openssl-devel libcurl-devel libxml2-devel cygutils-extra
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
