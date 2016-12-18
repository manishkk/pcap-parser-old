from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
import dpkt
import scapy
import socket
import struct

from django.http import HttpResponse
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii


testcap = open("/home/manish/PycharmProjects/pcap/webapp/Test.pcap")
capfile = savefile.load_savefile(testcap, verbose=True)



def index(request):
    answer = [
        str(ip.IP(binascii.unhexlify(ethernet.Ethernet(capfile.packets[0].raw()).payload))),
        str(capfile.packets[0].timestamp),

    ]

    return HttpResponse("\n".join(answer))


