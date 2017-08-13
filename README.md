About
=========

This module is designed to fetch your external IP address from the internet.
It is used mostly when behind a NAT.
It picks your IP randomly from a serverlist to minimize request overhead on a single server.
Further on it tries to check what your IPv6 is, if available.

If you want to add or remove your server from the list contact me on github.

Copyright © 2017 steve@localhost.lu
Copyright © 2014 phoemur@gmail.com
This work is free. You can redistribute it and/or modify it under the
terms of the Do What The Fuck You Want To Public License, Version 2,
as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.


API Usage
=========

    >>> import ipgetter
    >>> myip = ipgetter.myip()
    >>> myip
       '8.8.8.8'

If IPv6 available

    >>> import ipgetter
    >>> myip = ipgetter.myip()
    >>> myip
       [ '8.8.8.8', '2001:4860:4860::8888' ]

If only IPv6 found

    >>> import ipgetter
    >>> myip = ipgetter.myip()
    >>> myip
       '2001:4860:4860::8888'

Shell Usage
===========

    $ python -m ipgetter
    '8.8.8.8'

Installation
============

    # pip install git+https://github.com/SteveClement/ipgetter/tree/IPv6

Or download the tarball or git clone the repository and then:

    # python setup.py install

ChangeLog
=========

0.6v6 (2017-08-12)
 * Added rudimentary IPv6 support

0.6 (2014-10-30)
 * 45 servers
 * Simpler is better

0.5.2 (2014-08-12)
 * Fix servers (current 42 servers)
 * License

0.4 (2014-03-01)
 * Serverlist = 44 servers
 * Added timeout for getting the IP

0.3.2 (2014-03-01)
 * Fix distutils issues

0.2 (2014-03-01)
 * Fix python 2 backwards compatibility

0.1 (2014-02-28)
 * You can retrieve your IP.
 * Serverlist = 16 servers
