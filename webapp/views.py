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

ip_packet =ip.IP(binascii.unhexlify(ethernet.Ethernet(capfile.packets[0].raw()).payload));
mac_packet = ethernet.Ethernet(capfile.packets[0].raw());
packet = capfile.packets[0];



def index(request):
        answer = [

                 str(packet.timestamp),
                 str(mac_packet.src),
                 str(mac_packet.dst),
                 str(ip_packet.src),
                 str(ip_packet.dst),
                 str(packet.packet_len),


                ]
        return HttpResponse("<br>".join(answer))
