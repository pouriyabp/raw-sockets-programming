import binascii
import socket
import string
import struct
import uuid
import fcntl

"""
ARP  packet format:
Octet offset 	0                               1
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
0 	            |                    Hardware type (HTYPE)                      |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2 	            |                    Protocol type (PTYPE)                      |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
4 	            |Hardware address length (HLEN) | Protocol address length (PLEN)|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
6 	            |                       Operation (OPER)                        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
8 	            |         Sender hardware address (SHA) (first 2 bytes)         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
10 	            |                        (next 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 	            |                        (last 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
14 	            |         Sender protocol address (SPA) (first 2 bytes)         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 	            |                        (last 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
18 	            |         Target hardware address (THA) (first 2 bytes)         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 	            |                        (next 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
22 	            |                        (last 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 	            |         Target protocol address (TPA) (first 2 bytes)         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
26 	            |                        (last 2 bytes)                         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
HARDWARE_TYPE = 0X0001  # for Ethernet is 1 (use https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
PROTOCOL_TYPE = 0X0800  # This field specifies the internetwork protocol for which the ARP request is intended.
# For IPv4, this has the value 0x0800 and for ARP, 0x0806
HARDWARE_ADDRESS_LENGTH = 0X06  # Ethernet address length is 6 (6*8=48).
PROTOCOL_ADDRESS_LENGTH = 0X04  # IPv4 address length is 4 (4*8=32)
OPERATION = 0X0001  # Specifies the operation that the sender is performing: 1 for request, 2 for reply.
ARP_TYPE = 0x0806  # ARP code protocol
BROADCAST_MAC = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]  # broadcast address
TARGET_MAC = [0, 0, 0, 0, 0, 0]


# # only work in linux
# # find mac address use linux files
# def get_mac(interface):
#     try:
#         mac_address = open('/sys/class/net/' + interface + '/address').readline()
#     except Exception as e:
#         mac_address = "00:00:00:00:00"
#     return mac_address

def get_mac_address(interface):
    """
    find MAC address of interface
    string :param interface: the interface want to get mac address
    list :return: mac address
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interface = interface.encode('utf-8')
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface[:15]))
    info = info[18:24]
    info = list(info)
    return info


def get_ip_address(interface):
    """
    find ip address of interface
    string :param interface: the interface want to get ip address
    list :return: list of ip address
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interface = interface.encode('utf-8')
    result = socket.inet_ntoa(
        fcntl.ioctl(s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack('256s', interface[:15])
                    )[20:24])
    result = result.split(".")
    return result


def crate_arp_request_frame(local_mac, local_ip, dst_ip):
    packet = struct.pack("!6B6BHHHBBH6B4B6B4B", *BROADCAST_MAC, *local_mac, ARP_TYPE, HARDWARE_TYPE, PROTOCOL_TYPE,
                         HARDWARE_ADDRESS_LENGTH, PROTOCOL_ADDRESS_LENGTH, OPERATION, *local_mac, *local_ip,
                         *TARGET_MAC, *dst_ip)
    return packet


interface = 'wlo1'
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((interface, socket.SOCK_RAW))
local_mac = get_mac_address(interface)
print(local_mac)
local_ip = get_ip_address(interface)
local_ip = [int(x) for x in local_ip]
# dst_ip = [0x0a, 0x0a, 0x18, 0xef]
dst_ip = [10, 10, 24, 1]
frame = crate_arp_request_frame(local_mac, local_ip, dst_ip)
print(frame)
s.send(frame)

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
import re

while True:
    packet = rawSocket.recvfrom(2048)
    ethernet_header = packet[0][0:14]
    ethernet_data = struct.unpack("!6B6BH", ethernet_header)
    dst_mac_address = ethernet_data[:6]
    src_mac_address = ethernet_data[6:12]
    frame_type = ethernet_data[12]

    # dst_first_two_byte, dst_second_two_byte, dst_third_two_byte, src_first_two_byte, src_second_two_byte, \
    # src_third_two_byte, frame_type = struct.unpack("!3H3HH", ethernet_header)

    if hex(frame_type) == hex(ARP_TYPE):
        if list(dst_mac_address) == local_mac:
            arp_header = packet[0][14:42]
            arp_detailed = struct.unpack("!HHBBH6B4B6B4B", arp_header)
            print(arp_detailed)
            arp_operation = arp_detailed[4]
            print(arp_operation)
            print(hex(arp_operation))
            print(packet)
            if hex(arp_detailed[4]) == hex(0x002):
                arp_src_hardware_address = arp_detailed[5:11]
                arp_src_protocol_address = arp_detailed[11:15]
                arp_dst_hardware_address = arp_detailed[15:21]
                arp_dst_protocol_address = arp_detailed[21:25]
                print(arp_dst_hardware_address)
                print(arp_src_hardware_address)
                break
            else:
                continue
        else:
            continue
    else:
        continue

    # skip non-ARP packets
    # ethertype = ethernet_detailed[2]
    # if ethertype != (0x0806):
    #     # print(bytes(ethertype))
    #     continue

    # print("****************_ETHERNET_FRAME_****************")
    # print("Dest MAC:        ", binascii.hexlify(ethernet_detailed[0]))
    # print("Source MAC:      ", binascii.hexlify(ethernet_detailed[1]))
    # print("Type:            ", binascii.hexlify(ethertype))
    # print("************************************************")
    # print("******************_ARP_HEADER_******************")
    # print("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
    # print("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
    # print("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
    # print("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
    # print("Opcode:          ", binascii.hexlify(arp_detailed[4]))
    # print("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
    # print("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
    # print("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
    # print("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))
    # print("*************************************************\n")
# ----------------------------------------------------------------------------------------------------------------------
# hostMac = [0xc0, 0xf8, 0xda, 0x05, 0x9b, 0x74]
# src_ip = [0x0a, 0x0a, 0x18, 0xf7]
# dst_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
# dst_ip = [int (x) for x in dst_ip]
# from  struct import pack
#
# bcast_mac = pack('!6B', *(0xFF,)*6)
# zero_mac = pack('!6B', *(0x00,)*6)
# ARPOP_REQUEST = pack('!H', 0x0001)
# ARPOP_REPLY = pack('!H', 0x0002)
# # Ethernet protocol type (=ARP)
# ETHERNET_PROTOCOL_TYPE_ARP = pack('!H', 0x0806)
# # ARP logical protocol type (Ethernet/IP)
# ARP_PROTOCOL_TYPE_ETHERNET_IP = pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004)
#
#
# def send_arp(ip, device, sender_mac, broadcast, netmask, arptype,
#              request_target_mac=zero_mac):
#     #if_ipaddr = socket.gethostbyname(socket.gethostname())
#     sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
#     sock.bind((device, socket.SOCK_RAW))
#
#     socket_mac = sock.getsockname()[4]
#     if sender_mac == 'auto':
#         sender_mac = socket_mac
#     else:
#         raise Exception("Can't ARP this: " + sender_mac)
#
#     arpop = None
#     target_mac = None
#     if arptype == 'REQUEST':
#         target_mac = request_target_mac
#         arpop = ARPOP_REQUEST
#     else:
#         target_mac = sender_mac
#         arpop = ARPOP_REPLY
#
#     sender_ip = pack('!4B', *[int(x) for x in ip.split('.')])
#     target_ip = pack('!4B', *[int(x) for x in ip.split('.')])
#
#     arpframe = [
#         # ## ETHERNET
#         # destination MAC addr
#         bcast_mac,
#         # source MAC addr
#         socket_mac,
#         ETHERNET_PROTOCOL_TYPE_ARP,
#
#         # ## ARP
#         ARP_PROTOCOL_TYPE_ETHERNET_IP,
#         # operation type
#         arpop,
#         # sender MAC addr
#         sender_mac,
#         # sender IP addr
#         sender_ip,
#         # target hardware addr
#         target_mac,
#         # target IP addr
#         target_ip
#         ]
#
#     # send the ARP
#     sock.send(''.join(arpframe))
