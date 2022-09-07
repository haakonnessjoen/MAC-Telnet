MAC-Telnet for Posix systems
============================

Console tools for connecting to, and serving, devices using MikroTik RouterOS MAC-Telnet protocol.

## CURRENTLY UNDER DEVELOPMENT

> **Warning**
> This repository is in mid-way of adding support for RouterOS v6.43 and up, which does not support the old MD5 authentication method.
> Expect this to be "alpha quality" for now. The new EC-SRP key sharing and authentication protocol is **not** implemented in `mactelnetd` yet.

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

> **Warning**
> Currently untested in new version.

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

    apt-get install build-essential automake autoconf openssl-dev

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all install

### FreeBSD ###

> **Warning**
> Currently untested in new version.

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
    brew install gettext autoconf automake libtool openssl

    export GETTEXT_PATH=$(brew --prefix gettext)
    export OPENSSL_PATH=$(brew --prefix openssl)

    export PATH="${GETTEXT_PATH}/bin:${OPENSSL_PATH}/bin:$PATH"
    export LDFLAGS="-L${GETTEXT_PATH}/lib"
    export CPPFLAGS="-I${GETTEXT_PATH}/include -I${OPENSSL_PATH}/include"
    export CRYPTO_CFLAGS="-I${OPENSSL_PATH}/include"
    export CRYPTO_LIBS="-L${OPENSSL_PATH}/lib ${OPENSSL_PATH}/lib/libcrypto.3.dylib"
    ./autogen.sh
    make all install


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
      -o             Force old authentication algorithm.
      -h             This help.

Example using identity:

    $ mactelnet main-router
    Searching for 'main-router'...found
    Login: admin
    Password:
    Connecting to d4:ca:6d:12:47:13...done

Example using mac address:

    $ mactelnet -u admin 0:c:42:43:58:a5
    Password:
    Connecting to 0:c:42:43:58:a5...done


      MMM      MMM       KKK                          TTTTTTTTTTT      KKK
      MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
      MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
      MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
      MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
      MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

      MikroTik RouterOS 6.49 (c) 1999-2021       http://www.mikrotik.com/


     [admin@Mikrotik] >

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

## Huge thanks

Thanks to [@comed-ian](https://github.com/comed-ian) for creating a working proof of concept python script that successfully authenticated using the new authentication method in RouterOS 4.43+, and [@kmeaw](https://github.com/kmeaw) for porting the code to C, and implementing it in mactelnet.