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


def crate_arp_request_packet(local_mac, local_ip, dst_mac, dst_ip):
    # arp_packet = struct.pack('!HH'
    #                          'BB'
    #                          'H'
    #                          'HHH'
    #                          'HH'
    #                          'HHH'
    #                          'HH',
    #                          HARDWARE_TYPE, PROTOCOL_TYPE,
    #                          HARDWARE_ADDRESS_LENGTH,PROTOCOL_ADDRESS_LENGTH,
    #                          OPERATION,
    #                          hex(local_mac[0]), hex(local_mac[1]), hex(local_mac[2]),
    #                          local_ip[0],local_ip[1],
    #                          dst_mac[0], dst_mac[1], dst_mac[2],
    #                          dst_ip[0], dst_ip[1]
    #                          )
    ARP_FRAME = [
        struct.pack('!H', HARDWARE_TYPE),  # HRD
        struct.pack('!H', PROTOCOL_TYPE),  # PRO
        struct.pack('!B', HARDWARE_ADDRESS_LENGTH),  # HLN
        struct.pack('!B', PROTOCOL_ADDRESS_LENGTH),  # PLN
        struct.pack('!H', OPERATION),  # OP
        struct.pack('!6B', *local_mac),  # SHA
        struct.pack('!4B', *local_ip),  # SPA
        struct.pack('!6B', *(0x00,) * 6),  # THA
        struct.pack('!4B', *dst_ip),  # TPA
    ]
    return ARP_FRAME


local_mac = get_mac_address('wlo1')
local_ip = get_ip_address('wlo1')
print(local_mac)
print(local_ip)
dst_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
dst_ip = [10, 10, 24, 1]
local_ip = [0x0a, 0x0a, 0x18, 0xf7]
packet = crate_arp_request_packet(local_mac, local_ip, dst_mac, dst_ip)
print(packet)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("wlo1", socket.SOCK_RAW))
str = "  \x0a \x0a \x18 \xef"
# packet = struct.pack("!2B2B2B6B4B6B4B", *str)
brdCastMac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
hostMac = [0xc0, 0xf8, 0xda, 0x05, 0x9b, 0x74]
src_ip = [0x0a, 0x0a, 0x18, 0xf7]
dst_mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
dst_ip = [0x0a, 0x0a, 0x18, 0xef]
ARP_TYPE = 0x0806
packtet = struct.pack("!6B6BHHHBBH6B4B6B4B", *brdCastMac, *hostMac, ARP_TYPE, HARDWARE_TYPE, PROTOCOL_TYPE,
                      HARDWARE_ADDRESS_LENGTH, PROTOCOL_ADDRESS_LENGTH, OPERATION, *hostMac, *src_ip, *dst_mac, *dst_ip)
print(packtet)
s.send(packtet)
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
