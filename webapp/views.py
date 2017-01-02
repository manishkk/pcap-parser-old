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

testcap = open("/home/manish/PycharmProjects/pcap/webapp/Test_2.pcap")
capfile = savefile.load_savefile(testcap, verbose=True)





def index(request):
                answer = []
                for packet in capfile.packets:
                    try:
                        ip_packet = ip.IP(binascii.unhexlify(ethernet.Ethernet(packet.raw()).payload))
                        mac_packet = ethernet.Ethernet(packet.raw());
                        answer.extend([

                             str(packet.timestamp),   #timestamp
                             str(mac_packet.src),   #Sender Mac Address
                             str(mac_packet.dst),   #Receiver Mac Address
                             str(ip_packet.src),    #Sender IP
                             str(ip_packet.dst),    #Receiver IP
                             str(ip_packet.len),    #Payload lenght with IP header
                             str(ip_packet),        #Print whole packet information
                             str(mac_packet.type),  #Protocol Type
                             str(len(capfile.packets)), #Lenght of Pcacp file

                            ""

                            ])
                    except:
                        import traceback
                        traceback.print_exc()

                return HttpResponse("<br>" . join(answer))
