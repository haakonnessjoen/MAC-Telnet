MAC-Telnet for Posix systems
============================
[![Build Status](https://travis-ci.org/haakonnessjoen/MAC-Telnet.svg?branch=master)](https://travis-ci.org/haakonnessjoen/MAC-Telnet)

Console tools for connecting to, and serving, devices using MikroTik RouterOS MAC-Telnet protocol.

Installation
------------

### Docker ###

[`haakonn/mactelnet`](https://hub.docker.com/r/haakonn/mactelnet/) contains all four programs:

    docker run -it --rm --net=host haakonn/mactelnet mactelnet …
    docker run -it --rm --net=host haakonn/mactelnet macping …
    docker run -it --rm --net=host haakonn/mactelnet mndp …
    docker run -it --rm --net=host haakonn/mactelnet mactelnetd …

Note that Docker runs containers on isolated internal networks by default. [`--net=host`](https://docs.docker.com/network/host/) instructs Docker to provide `mactelnet` direct access to the host machine's network interfaces.

See [Usage](#usage) for more.

### CentOS 7 ###

To install dependencies:

    yum -y install wget automake gettext gettext-devel gcc make
       
    
Download source tarball, extract, compile and install:
    
    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all install

### Linux / kfreebsd ###

Dependencies: gcc (or similar), automake, autoconf

To install dependencies on Debian/Ubuntu based systems:

    apt-get install build-essential automake autoconf

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all install

### FreeBSD ###

Dependencies: clang (gcc or similar), automake, autoconf

To install dependencies on Debian/Ubuntu based systems:

    pkg install automake autoconf gettext-tools

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    ./configure LDFLAGS=" -L/usr/local/lib"
    gmake all install

### Mac OS X ###

Install dependencies, download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/

    # Install dependencies
    brew install gettext autoconf automake libtool

    # Get proper gettext path from brew
    export GETTEXT_PATH=$(brew --prefix gettext)

    # Check what paths it tells you to use, for a standard install, the following should suffice:
    export PATH="$GETTEXT_PATH"/bin:$PATH

    ./autogen.sh
    export LDFLAGS=-L"$GETTEXT_PATH"/lib
    export CPPFLAGS=-I"$GETTEXT_PATH"/include
    ./configure --with-libintl-prefix="$GETTEXT_PATH"/include
    make all install

And you are ready..

### Mac OS X (without Homebrew) ###

Install dependencies, download source tarball, extract, compile and install:

    export build=~/devtools # or wherever you'd like to build
    mkdir -p $build

    cd $build
    wget https://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
    tar xzf autoconf-2.69.tar.gz
    cd autoconf-2.69
    ./configure --prefix=/usr/local
    make
    sudo make install
    export PATH=$PATH:/usr/local/bin

    cd $build
    wget https://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz
    tar xzf automake-1.15.tar.gz
    cd automake-1.15
    ./configure --prefix=/usr/local
    make
    sudo make install

    cd $build
    wget https://ftp.gnu.org/gnu/libtool/libtool-2.4.6.tar.gz
    tar xzf libtool-2.4.6.tar.gz
    cd libtool-2.4.6
    ./configure --prefix=/usr/local
    make
    sudo make install

    cd $build
    wget https://ftp.gnu.org/gnu/gettext/gettext-0.19.8.1.tar.gz
    tar zxf gettext-0.19.8.1.tar.gz
    cd gettext-0.19.8.1
    ./configure --prefix=/usr/local
    make
    sudo make install

    cd $build
    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all
    sudo make install

And you are ready.


Usage
-----

    # mactelnet -h
    Usage: mactelnet <MAC|identity> [-h] [-n] [-a <path>] [-A] [-t <timeout>] [-u <user>] [-p <password>] [-U <user>] | -l [-B] [-t <timeout>]

    Parameters:
      MAC            MAC-Address of the RouterOS/mactelnetd device. Use mndp to
                     discover it.
      identity       The identity/name of your destination device. Uses
                     MNDP protocol to find it.
      -l             List/Search for routers nearby (MNDP). You may use -t to set timeout.
      -B             Batch mode. Use computer readable output (CSV), for use with -l.
      -n             Do not use broadcast packets. Less insecure but requires
                     root privileges.
      -a <path>      Use specified path instead of the default: ~/.mactelnet for autologin config file.
      -A             Disable autologin feature.
      -t <timeout>   Amount of seconds to wait for a response on each interface.
      -u <user>      Specify username on command line.
      -p <password>  Specify password on command line.
      -U <user>      Drop privileges to this user. Used in conjunction with -n
                     for security.
      -q             Quiet mode.
      -h             This help.

Example using identity:

    $ mactelnet main-router
    Searching for 'main-router'...found
    Login: admin
    Password:
    Connecting to d4:ca:6d:12:47:13...done

Example using mac address:

    $ mactelnet 0:c:42:43:58:a5 -u admin
    Password:
    Connecting to 0:c:42:43:58:a5...done


      MMM      MMM       KKK                          TTTTTTTTTTT      KKK
      MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
      MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
      MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
      MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
      MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

      MikroTik RouterOS 4.0 (c) 1999-2009       http://www.mikrotik.com/


     [admin@HMG] >

### Tips

You can use the well known "expect" tool to automate/script dialogues via mactelnet!

### List available hosts ###

    # mactelnet -l

MAC-Ping usage
--------------

    # macping -h
    Usage: macping <MAC> [-h] [-c <count>] [-s <packet size>]

    Parameters:
      MAC       MAC-Address of the RouterOS/mactelnetd device.
      -s        Specify size of ping packet.
      -c        Number of packets to send. (0 = for ever)
      -h        This help.

Example:

    # macping 0:c:42:43:58:a5
    0:c:42:43:58:a5 56 byte, ping time 1.17 ms
    0:c:42:43:58:a5 56 byte, ping time 1.07 ms
    0:c:42:43:58:a5 56 byte, ping time 1.20 ms
    0:c:42:43:58:a5 56 byte, ping time 0.65 ms
    0:c:42:43:58:a5 56 byte, ping time 1.19 ms

    5 packets transmitted, 5 packets received, 0% packet loss
    round-trip min/avg/max = 0.65/1.06/1.20 ms

Or for use in bash-scripting:

    # macping 0:c:42:43:58:a5 -c 2 >/dev/null 2>&1 || ( echo "No answer for 2 pings" | mail -s "router down" my.email@address.com )
