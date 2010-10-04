MAC-Telnet for Linux
====================

A linux console tool for connecting to MikroTik RouterOS devices via their
ethernet address.

NB: Alpha stage code. Do not expect to run flawlessy.

Installation
------------

Make sure you have installed openssl development files.

For Ubuntu users:
    sudo apt-get install libssl-dev

Then download source tarball, extract, compile and install:

    wget http://github.com/haakonnessjoen/MAC-Telnet/tarball/master
    tar zxvf haakonness*.tar.gz
    cd haakonness*/
    make all install

Now you're ready.

Usage
-----

    $ ./mactelnet eth0 0:c:42:43:58:a5 -u admin
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

