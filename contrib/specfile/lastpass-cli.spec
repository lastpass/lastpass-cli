Name:           lastpass-cli
Version:        0.4.0
Release:        2%{?dist}
Summary:        C99 command line interface to LastPass.com

License:        GPLv2
URL:            https://github.com/LastPass/lastpass-cli
Source0:        lastpass-cli-0.4.0.tgz

BuildRequires:  openssl-devel,libxml2-devel,libcurl-devel,asciidoc
Requires:       openssl,libcurl,libxml2,pinentry,xclip

%description
A command line interface to LastPass.com. Made open source and available on
github.

%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
make install-doc DESTDIR=%{?buildroot}


%files
/usr/bin/lpass
/usr/share/man/man1/lpass.1.gz
%doc



%changelog
* Tue Dec 30 2014 Rohan Ferris - 0.4.0-2
- Include asciidoc

* Tue Dec 30 2014 Rohan Ferris - 0.4.0-1
- Version number bump

* Fri Nov  7 2014 Rohan Ferris
- 
