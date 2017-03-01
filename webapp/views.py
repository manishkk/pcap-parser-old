from django.shortcuts import render
# Create your views here.
from django.shortcuts import render
from django.http import HttpResponse
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import udp

import binascii

testcap = open("/home/manish/PycharmProjects/pcap/webapp/Test_1.pcap")
capfile = savefile.load_savefile(testcap, verbose=True)


def index(request):
                answer = []
                for packet in capfile.packets:
                    try:
                        udp_packet = None
                        ptype = " "
                        mac_packet = ethernet.Ethernet(packet.raw());
                        if mac_packet.type == 2048:
                            ip_packet = ip.IP(binascii.unhexlify(ethernet.Ethernet(packet.raw()).payload))
                            ptype = "IPv4"
                            if ip_packet.p == 17:
                                udp_packet = udp.UDP(binascii.unhexlify(ethernet.Ethernet(packet.raw()).payload))
                                ptype = "UDP"
                        else:
                                ptype = "unknown"
                        answer.extend([

                             str(packet.timestamp),   #timestamp
                             str(mac_packet.src),   #Sender Mac Address
                             str(mac_packet.dst),   #Receiver Mac Address
                             str(ip_packet.src),    #Sender IP
                             str(ip_packet.dst),    #Receiver IP
                             str(ip_packet.len)+ " " +"byte",    #Payload lenght with IP header
                           #  str(ip_packet),        #Print whole packet information

                             str(mac_packet.type),  #Protocol Type


                             str(len(capfile.packets)) + " " + "Packets",  # Lenght of Pcacp file
                             str(ptype),
                            ])

                        if udp_packet is not None:
                            answer.extend([
                                str(udp_packet.dst_port),
                                str(udp_packet.src_port)
                            ])
                        else:
                            answer.extend([
                                str(ptype)   #add port details of TCP packets
                            ])

                        answer.append("")

                    except:
                        import traceback
                        traceback.print_exc()

                return HttpResponse("<br>" . join(answer))
