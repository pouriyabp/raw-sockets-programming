import random
import struct
import socket
import sys
import os
import time

# ======================================================================================================================
# ICMP protocol


ICMP_ECHO_REQUEST = 8


# crate ICMP packet with this function
# default packet size is 60 byte.
def crate_packet(identifier, sequence_number=1, packet_size=18):  # default packet size is 18 byte.
    # Maximum for an unsigned short int c object counts to 65535(0xFFFF). we have to sure that our packet id is not
    # greater than that.
    identifier = identifier & 0xFFFF

    # cod is 0 for icmp echo request
    code = 0
    # checksum is 0 for now
    checksum = 0
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)
    # Payload Generation
    payload_byte = []
    if packet_size > 0:
        for i in range(0x42, 0x42 + packet_size):  # 0x42 = 66 decimal
            payload_byte += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(payload_byte)
    checksum = calculate_checksum(header + data)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)
    packet = header + data
    return packet


# copy form github https://github.com/Akhavi/pyping/blob/master/pyping/core.py with few changes.
# The checksum calculation is as follows RFC1071 (https://tools.ietf.org/html/rfc1071)
# this function is only calculate checksum of packet.
def calculate_checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        sum += loByte

    sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)  # Add high 16 bits to low 16 bits
    sum += (sum >> 16)  # Add carry from above (if any)
    answer = ~sum & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


def send_one_icmp_packet(destination, request_packet, udp_socket):
    send_time = time.time()
    try:
        udp_socket.sendto(request_packet, (destination, 1))
    except socket.error as e:
        print(e)
        return
    return send_time


# test--->
dst = "8.8.8.8"
packet_id = os.getpid() + int(random.randint(1, 1000))
packet = crate_packet(packet_id, packet_size=18)
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 4)
send_one_icmp_packet(dst, packet, udp_socket)
recvPacket, addr = udp_socket.recvfrom(1024)
print(recvPacket)
print(addr)
