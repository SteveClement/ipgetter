#!/usr/bin/env python3
import ipgetter

import socket
from sys import version_info

PY3K = version_info >= (3, 0)

if PY3K:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

showV4 = False
showV6 = True
showFail = False

pg = ipgetter.IPgetter()

for url in pg.server_list:
    parsed_uri = urlparse(url)
    fqdn = parsed_uri.netloc

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

    #print(f"""Results for {fqdn} v4: {v4} v6: {v6}""")
