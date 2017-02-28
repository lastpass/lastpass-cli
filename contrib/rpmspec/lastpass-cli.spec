Name:           lastpass-cli
Version:        0.3.0
Release:        1%{?dist}
Summary:        C99 command line interface to LastPass.com

License:        GPLv2
URL:            https://github.com/LastPass/lastpass-cli
Source0:        lastpass-cli-0.3.0.tgz

BuildRequires:  openssl-devel,libxml2-devel,libcurl-devel
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


%files
/usr/bin/lpass
%doc



%changelog
* Fri Nov  7 2014 Rohan Ferris
- 
