Name:     mactelnet
Version:  0.4.5
Release:  1%{?gitrev:.%{gitrev}git}%{?dist}
Summary:  Console tools for connecting to, and serving, devices using MikroTik RouterOS MAC-Telnet protocol.
Epoch:    7

License:  
Group:    Applications/System
URL:      http://lunatic.no/2010/10/routeros-mac-telnet-application-for-linux-users/


# Generated with:
# git archive --prefix=%{name}-%{version}/ v%{version} | gzip > %{name}-%{version}.tar.gz
#
# Pre-release build tarballs should be generated with:
# git archive --prefix=%{name}-%{version}/ %{gitrev} | gzip > %{name}-%{version}-%{gitrev}.tar.gz
#
Source0: %{name}-%{version}%{?gitrev:-%{gitrev}}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

