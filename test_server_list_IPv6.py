#!/usr/bin/env python3
import ipgetter

import socket

showV4 = False
showV6 = True
showFail = False

pg = ipgetter.IPgetter()

for url in pg.server_list:
    # Yeah, this could be mor beautiful, but it is not.
    fqdn = url.replace('http://','')
    fqdn = fqdn.replace('https://','')
    fqdn = fqdn.split('/',1)[0]

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
