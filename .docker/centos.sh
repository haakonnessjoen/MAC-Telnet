#!/bin/sh -xe 

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

# Epel Repo
rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

yum -y install yum-plugin-priorities

yum -y groupinstall 'Development Tools'

gcc --version


# Prepare the RPM environment
mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# TODO: Macro /etc/rpm/macros.dist
## dist macros.
#%centos_ver 7
#%centos 7
#%rhel 7
#%dist .el7
#%el7 1

# Source repo version
cd /MAC-Telnet

# Test build
./autogen.sh
make all

