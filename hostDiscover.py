import binascii
import ipaddress
import socket
import string
import struct
import time
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
OPERATION_REQUEST = 0X0001  # Specifies the operation that the sender is performing: 1 for request, 2 for reply.
OPERATION_REPLAY = 0x0002
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
                         HARDWARE_ADDRESS_LENGTH, PROTOCOL_ADDRESS_LENGTH, OPERATION_REQUEST, *local_mac, *local_ip,
                         *TARGET_MAC, *dst_ip)
    return packet


def find_host(nic, dst_ip, timeout=1):
    interface = nic
    local_mac = get_mac_address(interface)
    local_ip = get_ip_address(interface)
    local_ip = [int(x) for x in local_ip]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((interface, socket.SOCK_RAW))
    frame = crate_arp_request_frame(local_mac, local_ip, dst_ip)
    s.send(frame)
    send_time = time.time()
    # return send_time
    mac, ip = recive_arp_frame(interface, send_time, timeout)
    return mac, ip


def recive_arp_frame(nic, send_time, timeout=1):
    interface = nic
    local_mac = get_mac_address(interface)
    local_ip = get_ip_address(interface)
    local_ip = [int(x) for x in local_ip]
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    while True:
        receive_time = time.time()
        if receive_time - send_time > timeout:
            return None, None
        packet = raw_socket.recvfrom(2048)
        ethernet_header = packet[0][0:14]
        ethernet_data = struct.unpack("!6B6BH", ethernet_header)
        dst_mac_address = ethernet_data[:6]
        src_mac_address = ethernet_data[6:12]
        frame_type = ethernet_data[12]
        if hex(frame_type) == hex(ARP_TYPE):
            if list(dst_mac_address) == local_mac:
                arp_header = packet[0][14:42]
                arp_detailed = struct.unpack("!HHBBH6B4B6B4B", arp_header)
                arp_operation = arp_detailed[4]
                if hex(arp_operation) == hex(OPERATION_REPLAY):
                    arp_src_hardware_address = arp_detailed[5:11]
                    arp_src_protocol_address = arp_detailed[11:15]
                    arp_dst_hardware_address = arp_detailed[15:21]
                    arp_dst_protocol_address = arp_detailed[21:25]
                    if list(arp_dst_hardware_address) == local_mac and list(arp_dst_protocol_address) == local_ip:
                        receive_time = time.time()
                        if receive_time - send_time > timeout:
                            return None, None
                        return arp_src_hardware_address, arp_src_protocol_address
                else:
                    continue
            else:
                continue
        else:
            continue


def print_result(mac, ip):
    if mac is not None or ip is not None:
        ip = [str(x) for x in ip]
        ip = ".".join(ip)
        mac = [hex(x) for x in mac]
        mac = ":".join(mac)
        mac = mac.replace("0x", "")
        mac = mac.split(":")
        mac = [("0" + x if len(x) == 1 else "".join(x)) for x in mac]
        mac = ":".join(mac)
        return f"interface with {mac} MAC address have {ip} IP address."
    else:
        return


def convert_ip_to_range(ip_address_with_cidr):
    address, cidr = ip_address_with_cidr.split('/')
    address = [int(x) for x in address.split(".")]
    cidr = int(cidr)
    mask = [(((1 << 32) - 1) << (32 - cidr) >> i) & 255 for i in reversed(range(0, 32, 8))]
    network_address = [address[i] & mask[i] for i in range(4)]
    boradcast_address = [(address[i] & mask[i]) | (255 ^ mask[i]) for i in range(4)]
    # print("Address: {0}".format('.'.join(map(str, address))))
    # print("Mask: {0}".format('.'.join(map(str, mask))))
    # print("Cidr: {0}".format(cidr))
    # print("Network: {0}".format('.'.join(map(str, network_address))))
    # print("Broadcast: {0}".format('.'.join(map(str, boradcast_address))))
    return network_address, boradcast_address


def find_range(network_address, broadcast_address):
    list_of_ip_addresses = []
    temp_address = network_address
    temp_address[3] = temp_address[3] + 1
    # print(temp_address)

    list_of_ip_addresses.append(tuple(temp_address))

    print(list_of_ip_addresses)
    while True:
        if temp_address[3] + 1 < 256:
            temp_address[3] += 1
        elif temp_address[2] + 1 < 256:
            temp_address[3] = 0
            temp_address[2] += 1
        elif temp_address[1] + 1 < 256:
            temp_address[2] = 0
            temp_address[3] = 0
            temp_address[1] += 1
        if temp_address != broadcast_address:
            list_of_ip_addresses.append(tuple(temp_address))
        else:
            break
    return list_of_ip_addresses

    # while temp_address != broadcast_address:
    #     if temp_address[3] + 1 < 256:
    #         temp_address[3] += 1


def try_to_find(list_of_ip, NIC, timeout=1):
    for ip in list_of_ip:
        ip = list(ip)
        mac, ip = find_host(NIC, ip, timeout)
        if mac is not None and ip is not None:
            print(print_result(mac, ip))


net, brd = convert_ip_to_range('10.10.24.215/24')
list_of_addr = find_range(net, brd)
print(list_of_addr)
interface = 'wlo1'
# dst_ip = [0x0a, 0x0a, 0x18, 0xef]
dst_ip = [10, 10, 24, 244]
mac, ip = find_host(interface, dst_ip)
print(print_result(mac, ip))
try_to_find(list_of_addr, interface)
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
