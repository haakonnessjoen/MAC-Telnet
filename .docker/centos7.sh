#!/bin/sh -xe 

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

yum -y groupinstall 'Development Tools'

gcc --version

# TODO: Check for git tags, deploy RPM only on release

# Prepare the RPM environment
mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Macros - /etc/rpm/macros.dist
cat >> /etc/rpm/macros.dist << EOF
%dist .centos.el7
%mactelnet 1
EOF

# Copy SPEC file
cp MAC-Telnet/config/mactelnet.spec /tmp/rpmbuild/SPECS

# Get latest version of release
package_version=`grep Version MAC-Telnet/config/mactelnet.spec | awk '{print $2}'`

# Create source archive for RPM Build
pushd MAC-Telnet
git archive --prefix=mactelnet-${package_version}/ HEAD | gzip > /tmp/rpmbuild/SOURCES/mactelnet-${package_version}.tar.gz
popd

# Build RPM
rpmbuild --define '_topdir /tmp/rpmbuild' -ba -vv /tmp/rpmbuild/SPECS/mactelnet.spec

# After building the RPM, try to install it
# Fix the lock file error on EL7.  /var/lock is a symlink to /var/run/lock
mkdir -p /var/run/lock

# Testing packages
yum localinstall -y /tmp/rpmbuild/RPMS/x86_64/mactelnet-*


#
# TODO: Removed for testing rpm builder
#
# Source repo version
#pushd MAC-Telnet
# Test build
#./autogen.sh
#make all

