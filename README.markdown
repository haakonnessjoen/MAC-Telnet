[![Build](https://github.com/haakonnessjoen/MAC-Telnet/actions/workflows/build.yaml/badge.svg?branch=master)](https://github.com/haakonnessjoen/MAC-Telnet/actions/workflows/build.yaml)
[![Docker release](https://github.com/haakonnessjoen/MAC-Telnet/actions/workflows/docker.yaml/badge.svg)](https://github.com/haakonnessjoen/MAC-Telnet/actions/workflows/docker.yaml)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL_v2%2b-blue)](https://github.com/haakonnessjoen/MAC-Telnet/blob/master/LICENSE)

# MAC-Telnet for Posix systems

This project contains a set of console tools for connecting to and serving devices using the MikroTik RouterOS MAC-Telnet protocol. This is a proprietary network protocol used by MikroTik RouterOS devices to provide shell access to their devices even if the device is not configured with an ip address.

The protocol is based on sending and receiving udp broadcast packets, so it is **not secure** in any means. It should only be used as a last resort for configuring a device lacking an ip address, or in a secure network environment.

In addition to a client and server, this project also includes a ping tool, that can be used to ping RouterOS devices using their MAC address, and a MNDP tool, that can be used to discover RouterOS and MAC-Telnet devices on the local network.

## New EC-SRP key sharing and authentication support (RouterOS >= v6.43)

The MAC-Telnet client and server now supports the new EC-SRP authentication that is mandatory after Mikrotik removed support for MD5 authentication in RouterOS v6.43 and forward. Support for using the old MD5 authentication is still possible via command line flags for backwards comatibility.

## Support for password hashing on the server side

With the new EC-SRP authentication, the MAC-Telnet server now supports password hashing for the user file. This means that the server can store hashed passwords in a file, instead of plaintext passwords. To add/update users with the new hashed password support, use the `-a` flag with the `mactelnetd` command. You can also list users with the `-l` flag, or delete users from the user file with `-d`. 

**Note:** These commands can be used while the server is running to update the user database without restarting the server.

## Installation

> [!TIP]
> If you only want the `mactelnet` client tools, and not the `mactelnetd` server when compiling from source, you can add the `--without-mactelnetd` flag to the `./configure` command before compiling.

### Docker

[`ghcr.io/haakonnessjoen/mac-telnet`](https://github.com/haakonnessjoen/MAC-Telnet/pkgs/container/mac-telnet) contains the latest release of all four programs:

    docker run -it --rm --net=host haakonn/mactelnet mactelnet …
    docker run -it --rm --net=host haakonn/mactelnet macping …
    docker run -it --rm --net=host haakonn/mactelnet mndp …
    docker run -it --rm --net=host haakonn/mactelnet mactelnetd …

Note that Docker runs containers on isolated internal networks by default. [`--net=host`](https://docs.docker.com/network/host/) instructs Docker to provide `mactelnet` direct access to the host machine's network interfaces.

See [Usage](#usage) for more.

### CentOS 7

To install dependencies:

    yum -y install wget automake gettext gettext-devel libbsd-devel gcc make

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all install

### Linux (Debian/Ubuntu)

The latest releases are usually available in the lastest versions of Debian and Ubuntu. You can install them with `apt install mactelnet-client` or `apt install mactelnet-server`.

To install the lastest `master` branch *from source*, use the following instructions:

    apt-get install build-essential autopoint automake autoconf libbsd-dev libssl-dev gettext

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    make all install

### FreeBSD

Dependencies: clang (gcc or similar), automake, autoconf

To install dependencies on FreeBSD:

    pkg install automake autoconf gettext-tools

Download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/
    ./autogen.sh
    ./configure LDFLAGS=" -L/usr/local/lib"
    gmake all install

### Mac OS X

Download source tarball and extract:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master -O mactelnet.tar.gz
    tar zxvf mactelnet.tar.gz
    cd haakonness*/

Install dependencies

    brew install gettext autoconf automake libtool openssl pkg-config

Set up build environment, compile and install:

    export GETTEXT_PATH=$(brew --prefix gettext)
    export OPENSSL_PATH=$(brew --prefix openssl)
    export PATH="${GETTEXT_PATH}/bin:${OPENSSL_PATH}/bin:$PATH"
    export LDFLAGS="-L${GETTEXT_PATH}/lib"
    export CPPFLAGS="-I${GETTEXT_PATH}/include -I${OPENSSL_PATH}/include"
    export CRYPTO_CFLAGS="-I${OPENSSL_PATH}/include"
    export CRYPTO_LIBS="-L${OPENSSL_PATH}/lib ${OPENSSL_PATH}/lib/libcrypto.3.dylib"
    ./autogen.sh
    make all install

## Usage

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
      -o             Force old MD5 authentication method.
      -h             This help.

Example using identity:

    $ mactelnet main-router
    Searching for 'main-router'...found
    Login: admin
    Password:
    Connecting to d4:ca:6d:12:47:13...done

Example using mac address:

    $ mactelnet 0:c:42:43:58:a5
    Login: admin
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

### List available hosts using MNDP Discovery

    # mactelnet -l

## MAC-Ping usage

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

- Thanks to [@comed-ian](https://github.com/comed-ian) for creating a working proof of concept python script that successfully authenticated using the new authentication method in RouterOS 4.43+, and [@kmeaw](https://github.com/kmeaw) for porting the code to C, and implementing it in mactelnet and mactelnetd.
- Thanks to Omni Flux for doing [the initial reverse engineering](https://omniflux.com/devel/mikrotik/Mikrotik_MAC_Telnet_Procotol.txt) of the MAC Telnet protocol, that inspired me to write these programs, as well as the mactelnet Wireshark plugin.
