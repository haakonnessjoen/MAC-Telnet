#!/bin/sh -xe 

# TODO: Check folder
ls -al /MAC-Telnet/

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

# Epel Repo
rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

yum -y install yum-plugin-priorities

#yum -y install rpm-build gcc gcc-c++ cmake git tar gzip make autotools
yum -y groupinstall 'Development Tools'

gcc --version


# Prepare the RPM environment
mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# TODO: Testing
cat /etc/rpm/macros.dist


# Source repo version
cd /home
git clone --depth=50 --branch=master https://github.com/antwal/MAC-Telnet.git antwal/MAC-Telnet

cd antwal/MAC-Telnet

./autogen.sh
make all

