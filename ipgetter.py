#!/usr/bin/env python
"""
This module is designed to fetch your external IP address from the internet.
It is used mostly when behind a NAT.
It picks your IP randomly from a serverlist to minimize request
overhead on a single server

If you want to add or remove your server from the list contact me on github


API Usage
=========

    >>> import ipgetter
    >>> myip = ipgetter.myip()
    >>> myip
    '8.8.8.8'

    >>> ipgetter.IPgetter().test()

    Number of servers: 47
    IP's :
    8.8.8.8 = 47 ocurrencies


Copyright 2017 steve@localhost.lu
Copyright 2014 phoemur@gmail.com
This work is free. You can redistribute it and/or modify it under the
terms of the Do What The Fuck You Want To Public License, Version 2,
as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
"""

import re
import random
import socket

from sys import version_info

PY3K = version_info >= (3, 0)

if PY3K:
    import urllib.request as urllib
    from urllib.parse import urlparse
else:
    import urllib2 as urllib
    from urlparse import urlparse

# Check if we have python > 3.3 and be gentle to python2 users (who should really make their code py3k only)
try:
    # Python 3.3+
    import ipaddress

    def ip_kind(addr):
        return ipaddress.ip_address(addr).version

except ImportError:
    # Fallback
    import socket

    def ip_kind(addr):
        try:
            socket.inet_aton(addr)
            return 4
        except socket.error: pass
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return 6
        except socket.error: pass
        raise ValueError(addr)

'''
Checking if google is reachable via IPv6. If no default IPv6 route, this will be false.
'''

haveIPv6 = True
try:
    socket.create_connection(("ipv6.google.com",80))
except:
    haveIPv6 = False

__version__ = "0.6v6"


def myip():
    return IPgetter().get_externalip()


class IPgetter(object):

    '''
    This class is designed to fetch your external IP address from the internet.
    It is used mostly when behind a NAT.
    It picks your IP randomly from a serverlist to minimize request overhead
    on a single server
    '''

    def __init__(self):
        '''
        Temporary server_list of known v6 (resolvable) servers, doesn't mean
        they return an intelligible v6 response
        '''
        self.server_list_v6 = ['http://whatismyipaddress.com/',
                               'http://myexternalip.com/raw',
                               'http://www.trackip.net/',
                               'http://icanhazip.com/',
                               'http://whatsmyip.net/',
                               'http://ip.pid.lu/',
                               'http://[2001:470:1f14:910::2]/', # IP of ip.pid.lu
                               'http://www.dslreports.com/whatismyip',
                               'http://www.myip.ru',
                               'http://myexternalip.com/',
                               'https://wtfismyip.com/text',
                               'https://diagnostic.opendns.com/myip',
                               ]

        self.server_list = ['http://ip.dnsexit.com',
                            'http://ip.ion.lu',
                            'http://ipecho.net/plain',
                            'http://checkip.dyndns.org/plain',
                            'http://whatismyipaddress.com/',
                            'http://websiteipaddress.com/WhatIsMyIp',
                            'http://getmyipaddress.org/',
                            'http://www.my-ip-address.net/',
                            'http://myexternalip.com/raw',
                            'http://www.canyouseeme.org/',
                            'http://www.trackip.net/',
                            'http://icanhazip.com/',
                            'http://www.iplocation.net/',
                            'http://www.howtofindmyipaddress.com/',
                            'http://www.ipchicken.com/',
                            'http://whatsmyip.net/',
                            'http://www.ip-adress.com/',
                            'http://checkmyip.com/',
                            'http://www.tracemyip.org/',
                            'http://www.lawrencegoetz.com/programs/ipinfo/',
                            'http://www.findmyip.co/',
                            'http://ip-lookup.net/',
                            'https://www.dslreports.com/whatismyip',
                            'http://www.mon-ip.com/en/my-ip/',
                            'http://ipgoat.com/',
                            'http://www.myipnumber.com/my-ip-address.asp',
                            'http://formyip.com/',
                            'https://check.torproject.org/',
                            'http://www.displaymyip.com/',
                            'http://www.bobborst.com/tools/whatsmyip/',
                            'http://www.geoiptool.com/',
                            'https://www.whatsmydns.net/whats-my-ip-address.html',
                            'https://www.privateinternetaccess.com/pages/whats-my-ip/',
                            'http://checkip.dyndns.com/',
                            'http://myexternalip.com/',
                            'http://www.ip-adress.eu/',
                            'http://www.infosniper.net/',
                            'https://wtfismyip.com/text',
                            'http://ipinfo.io/',
                            'http://httpbin.org/ip',
                            'https://diagnostic.opendns.com/myip',
                            'http://checkip.amazonaws.com',
                            'https://api.ipify.org',
                            'http://v4.ident.me']

        self.server_broken_list = ['http://ifconfig.me/ip', 'http://www.myip.ru', "http://www.whatsmyipaddress.net/"]

    def get_externalip(self):
        '''
        This function gets your IP from a random server
        '''

        myip = ''
        myV6ip = ''
        for i in range(7):
            if haveIPv6:
                myV6ip = self.fetch(random.choice(self.server_list_v6), haveIPv6=haveIPv6)
            myip = self.fetch(random.choice(self.server_list))
            if myip != '' and myV6ip != '':
                myip = [myip, myV6ip]
                return myip
            elif myip != '':
                return myip
            elif myV6ip !=  '':
                return myV6ip
            else:
                continue
        return ''

    def fetch(self, server, haveIPv6=False):
        '''
        This function gets your IP from a specific server.
        '''

        # Ugly hack to get either IPv4 or IPv6 response from server
        parsed_uri = urlparse(server)
        fqdn = "{uri.netloc}".format(uri=parsed_uri)
        scheme = "{uri.scheme}".format(uri=parsed_uri)
        path = "{uri.path}".format(uri=parsed_uri)
        try:
            ipVersion = ip_kind(fqdn[1:-1])
            ip = fqdn
        except ValueError:
            addrs = socket.getaddrinfo(fqdn, 80)
            if haveIPv6:
                ipv6_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET6]
                ip = "[" + ipv6_addrs[0] + "]"
            else:
                ipv4_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET]
                ip = ipv4_addrs[0]

        server = "{}://{}{}".format(scheme, ip, path)
        url = None
        OSX_Agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"
        win_Agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5'
        userAgent = OSX_Agent

        try:
            url = urllib.Request(server, None, {'User-agent' : userAgent})
            # Next line adds the host header
            url.host = fqdn
            content = urllib.urlopen(url).read()

            # Didn't want to import chardet. Prefered to stick to stdlib
            if PY3K:
                try:
                    content = content.decode('UTF-8')
                except UnicodeDecodeError:
                    content = content.decode('ISO-8859-1')

            # Python regular expressions for IPv4 and IPv6 addresses and URI-references,
            # based on RFC 3986's ABNF.
            #
            # ipv4_address and ipv6_address are self-explanatory.
            # ipv6_addrz requires a zone ID (RFC 6874) follow the IPv6 address.
            # ipv6_address_or_addrz allows an IPv6 address with optional zone ID.
            # uri_reference is what you think of as a URI. (It uses ipv6_address_or_addrz.)
            ipv4_address = re.compile('(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
            ipv6_address = re.compile('(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)')
            ipv6_addrz = re.compile('(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+')
            ipv6_address_or_addrz = re.compile('(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?')
            uri_reference = re.compile("(?:([A-Za-z][A-Za-z0-9+\\-.]*):(?://((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|:)*@)?(?:\\[(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?|[Vv][0-9A-Fa-f]+\\.(?:[!$&'()*+,;=A-Za-z0-9\\-._~]|:)+)\\]|(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])*)(?::[0-9]*)?)((?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|(/(?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)?)|((?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|())(?:\\?((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?(?:#((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?|(?://((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|:)*@)?(?:\\[(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?|[Vv][0-9A-Fa-f]+\\.(?:[!$&'()*+,;=A-Za-z0-9\\-._~]|:)+)\\]|(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])*)(?::[0-9]*)?)((?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|(/(?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)?)|((?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|@)+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|())(?:\\?((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?(?:#((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?)")
            # len(ipv4_address) == 111
            # len(ipv6_address) == 1501
            # len(ipv6_addrz) == 1541
            # len(ipv6_address_or_addrz) == 1546
            # len(uri_reference) == 4445

            if haveIPv6:
                m = ipv6_address.search(content)
            else:
                m = re.search(
                    '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                    content)
            myip = m.group(0)
            return myip if len(myip) > 0 else ''
        except Exception:
            return ''

    def test(self):
        '''
        This functions tests the consistency of the servers
        on the list when retrieving your IP.
        All results should be the same.
        '''

        resultdict = {}
        for server in self.server_list:
            resultdict.update(**{server: self.fetch(server)})

        ips = sorted(resultdict.values())
        ips_set = set(ips)
        print('\nNumber of servers: {}'.format(len(self.server_list)))
        print("IP's :")
        for ip, ocorrencia in zip(ips_set, map(lambda x: ips.count(x), ips_set)):
            print('{0} = {1} ocurrenc{2}'.format(ip if len(ip) > 0 else 'broken server', ocorrencia, 'y' if ocorrencia == 1 else 'ies'))
        print('\n')
        print(resultdict)

    def testV6(self, server=None):
        '''
        This function tests IPv6 capabilities of the remote servers.
        It is a poor-persons attempt by resolving the FQDN to an IPv6 address.
        Takes a random server if no server given.
        '''
        if server is None:
            server = random.choice(self.server_list)
        # Extract the FQDN from server
        fqdn = parsed_uri = urlparse(server)
        print("{uri.netloc}".format(uri=parsed_uri))

        try:
            v6 = socket.getaddrinfo(fqdn, None, socket.AF_INET6)
            v6 = v6[0][4][0]
        except:
            v6 = False

        try:
            v4 = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            v4 = v4[0][4][0]
        except:
            v4 = False

if __name__ == '__main__':
    print(myip())
