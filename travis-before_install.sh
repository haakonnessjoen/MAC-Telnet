#!/bin/bash

set -e

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then

    sudo apt-get update
    sudo apt-get install -y gettext autopoint

fi


if [[ $TRAVIS_OS_NAME == 'osx' ]]; then

    case "${OSBUILD}" in
        brew)
            # Install some custom requirements on OS X from brew
            # Force update homebrew
            cd "$(brew --repo)"
            git fetch
            git reset --hard origin/master
            brew update
            # Try install gettext
            brew install gettext
            brew link --force gettext
            echo 'export PATH="/usr/local/opt/gettext/bin:$PATH"' >> ~/.bash_profile
            # Check what paths it tells you to use, for a standard install, the following should suffice:
            export PATH="/usr/local/opt/gettext/bin:$PATH"
            cd ~/
            ;;
        sources)
            # Install some custom requirements on OS X from sources
            export build=~/devtools
            mkdir -p $build
            ##
            # Autoconf
            ##
            cd $build
            echo "Build autoconf..." >&2
            curl -OL https://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
            tar xzf autoconf-2.69.tar.gz
            cd autoconf-2.69
            ./configure --prefix=/usr/local
            make
            sudo make install
            export PATH=$PATH:/usr/local/bin
            ##
            # Automake
            ##
            cd $build
            echo "Build automake..." >&2
            curl -OL https://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
            tar xzf automake-1.15.tar.gz
            cd automake-1.15
            ./configure --prefix=/usr/local
            make
            sudo make install
            ##
            # Libtool
            ##
            cd $build
            echo "Build libtool..." >&2
            curl -OL https://ftp.gnu.org/gnu/libtool/libtool-2.4.6.tar.gz
            tar xzf libtool-2.4.6.tar.gz
            cd libtool-2.4.6
            ./configure --prefix=/usr/local
            make
            sudo make install
            ##
            # GetText
            #
            cd $build
            echo "Build gettext..." >&2
            curl -OL https://ftp.gnu.org/gnu/gettext/gettext-0.19.8.1.tar.gz
            tar zxf gettext-0.19.8.1.tar.gz
            cd gettext-0.19.8.1
            ./autogen.sh
            ./configure --prefix=/usr/local
            make
            sudo make install
            ##
            # Installation Complete
            ##
            echo "Installation Complete." >&2
            cd ~/
            ;;
    esac

fi
