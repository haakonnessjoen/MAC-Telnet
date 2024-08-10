Name:     mactelnet
Version:  0.5.3
Release:  1%{?gitrev:.%{gitrev}git}%{?dist}
Summary:  Console tools for connecting to, and serving, devices using MikroTik RouterOS MAC-Telnet protocol.
Epoch:    7

License:  GPL-2.0-or-later WITH Autoconf-exception-generic
Group:    Applications/System
URL:      https://salsa.debian.org/debian/mactelnet

BuildRequires:  automake autoconf make
BuildRequires:  coreutils
BuildRequires:  gcc
BuildRequires:  gettext-devel
BuildRequires:  openssl-devel
BuildRequires:  libbsd-devel
BuildRequires:  sed

# Generated with:
# git archive --prefix=%{name}-%{version}/ v%{version} | gzip > %{name}-%{version}.tar.gz
#
# Pre-release build tarballs should be generated with:
# git archive --prefix=%{name}-%{version}/ %{gitrev} | gzip > %{name}-%{version}-%{gitrev}.tar.gz
#
Source0: %{name}-%{version}%{?gitrev:-%{gitrev}}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%define	_prefix	/usr/local

%description
%{summary}

%package daemon
Group: Applications/System
Summary: Testing

BuildRequires:  redhat-rpm-config

%description daemon
%{summary}


%package client
Group: Applications/System
Summary: Testing

BuildRequires:  redhat-rpm-config

%description client
%{summary}


%prep
%setup -q

%build
./autogen.sh
make all

%clean
rm -rf $RPM_BUILD_ROOT

%install
make DESTDIR=$RPM_BUILD_ROOT install

%files client
%defattr(-,root,root,-)
%attr(755,root,root) %{_bindir}/*
%doc %{_prefix}/share/*

%files daemon
%defattr(-,root,root,-)
%config(noreplace) %{_prefix}/%{_sysconfdir}/mactelnetd.users
%attr(755,root,root) %{_sbindir}/*
%doc %{_prefix}/share/*


