import socket
import struct
import random
import os
import sys

"""  
 ICMP Echo Request packets:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type(8)   |     Code(0)   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Payload                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""
ICMP_ECHO_REQUEST = 8


def crate_packet(sequence_number=1, packet_size=0):
    # Maximum for an unsigned short int c object counts to 65535(0xFFFF) we have to sure that our packet id is not
    # greater than that.
    identifier = os.getpid() & 0xFFFF
    # cod is 0 for icmp echo request
    code = 0
    # checksum is 0 for now
    checksum = 0
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('BBHHH', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)

    # Payload Generation
    payload_byte = []
    if packet_size > 0:
        for i in range(0, packet_size):
            payload_byte += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(payload_byte)
    #checksum = calculate_checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)
    packet = header + data
    return packet


def calculate_checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2
    if count_to < len(source_string):
        print(source_string)
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff  # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    answer = socket.htons(answer)
    return answer

def change_to_ip(host_name):
    try:
        server_ip = socket.gethostbyname(host_name)
        return server_ip
    except socket.error as e:
        print(e)
        return None


if __name__ == "__main__":
    print(change_to_ip('www.google.com'))
    print(socket.getprotobyname('icmp'))
    print(crate_packet(packet_size=5))
