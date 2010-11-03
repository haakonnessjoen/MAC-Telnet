MAC-Telnet for Linux
====================

A linux console tool for connecting to MikroTik RouterOS devices via their
ethernet address.

NB: Beta stage code. Do not expect to run flawlessy.

Installation
------------

Then download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master
    tar zxvf haakonness*.tar.gz
    cd haakonness*/
    make all install

Now you're ready.

Usage
-----

    # mactelnet -h
    Usage: ./mactelnet <MAC|identity> [-h] [-n] [-t <timeout>] [-u <username>] [-p <password>]
    
    Parameters:
      MAC       MAC-Address of the RouterOS device. Use mndp to discover them.
      identity  The identity/name of your RouterOS device. Uses MNDP protocol to find it..
      -n        Do not use broadcast packets. Less insecure but requires root privileges.
      -t        Amount of seconds to wait for a response on each interface.
      -u        Specify username on command line.
      -p        Specify password on command line.
      -h        This help.


    Example:

    $ ./mactelnet 0:c:42:43:58:a5 -u admin
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

