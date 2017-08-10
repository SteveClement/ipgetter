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
                               'http://checkmyip.com/',
                               'http://www.dslreports.com/whois',
                               'http://www.myip.ru',
                               'http://ipgoat.com/',
                               'http://myexternalip.com/',
                               'https://wtfismyip.com/text',
                               'https://diagnostic.opendns.com/myip']

        self.server_list = ['http://ip.dnsexit.com',
                            'http://ifconfig.me/ip',
                            'http://echoip.com',
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
                            'http://www.dslreports.com/whois',
                            'http://www.mon-ip.com/en/my-ip/',
                            'http://www.myip.ru',
                            'http://ipgoat.com/',
                            'http://www.myipnumber.com/my-ip-address.asp',
                            'http://www.whatsmyipaddress.net/',
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
                            'https://v4.ident.me']

    def get_externalip(self):
        '''
        This function gets your IP from a random server
        '''

        myip = ''
        myV6ip = ''
        for i in range(7):
            if haveIPv6:
                myV6ip = self.fetch(random.choice(self.server_list_v6))
                if myV6ip != '':
                    return myV6ip
                else:
                    continue
            myip = self.fetch(random.choice(self.server_list))
            if myip != '':
                return myip
            else:
                continue
        return ''

    def fetch(self, server, haveIPv6=False):
        '''
        This function gets your IP from a specific server.
        '''
        url = None
        opener = urllib.build_opener()
        opener.addheaders = [('User-agent',
                              "Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0")]

        try:
            url = opener.open(server, timeout=2)
            content = url.read()

            # Didn't want to import chardet. Prefered to stick to stdlib
            if PY3K:
                try:
                    content = content.decode('UTF-8')
                except UnicodeDecodeError:
                    content = content.decode('ISO-8859-1')

            m = re.search(
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
                content)
            myip = m.group(0)
            return myip if len(myip) > 0 else ''
        except Exception:
            return ''
        finally:
            if url:
                url.close()

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
        # Yeah, this could be mor beautiful, but it is not.
        fqdn = parsed_uri = urlparse(server)
        print("{uri.netloc}".format(uri=parsed_uri))

        try:
            v6 = socket.getaddrinfo(fqdn, None, socket.AF_INET6)
            v6 = v6[0][4][0]
            print(f"""Results for {fqdn} v6: {v6}""")
        except:
            v6 = False

        try:
            v4 = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            v4 = v4[0][4][0]
        except:
            v4 = False

if __name__ == '__main__':
    print(myip())
