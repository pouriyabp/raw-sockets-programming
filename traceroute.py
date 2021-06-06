import random
import struct
import socket
import sys
import os
import time
import select
import argparse


class TextColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[m'
    YELLOW = '\033[93m'
    ORANGE = '\033[91m'
    PURPLE = '\033[35m'


# ======================================================================================================================
# ICMP protocol


ICMP_ECHO_REQUEST = 8
ICMP_MAX_HOP = 30  # maximum hop that we go.
ICMP_TRIES = 3  # default tries for each hop.


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


def send_one_icmp_packet(destination, request_packet, udp_socket, port_number=0):
    send_time = time.time()
    try:
        udp_socket.sendto(request_packet, (destination, port_number))
    except socket.error as e:
        print(e)
        return
    return send_time


def receive_one_icmp_packet(udp_socket, send_time, timeout):
    while True:
        r_list, w_list, x_list = select.select([udp_socket], [], [], timeout)
        start_time_for_receive = time.time()
        total_time = start_time_for_receive - send_time
        timeout = timeout - total_time
        if not r_list:
            return None
        if timeout <= 0:
            return None
        reply_packet, address = udp_socket.recvfrom(2048)
        total_time *= 1000  # change it to ms
        # total_time = int(total_time)
        total_time = "{:.5f}".format(total_time)  # for floating point
        return reply_packet, address, total_time


# function that send one icmp packet each time.
# TODO try to send 3 icmp pakcet each time.
def traceroute_use_icmp(dst, timeout=1, port_number=0, start_ttl=1, max_ttl=ICMP_MAX_HOP, max_tries=ICMP_TRIES,
                        packet_size=18):
    address = ()
    prv_address = ("0.0.0.0", port_number)
    rcv_packet = None
    total_time = -float('inf')
    ip = socket.gethostbyname(dst)
    tries = 0
    print(
        f"traceroute {TextColors.BOLD}{TextColors.ORANGE}<{ip}>{TextColors.RESET} use {TextColors.BOLD}ICMP{TextColors.RESET}:")
    for ttl in range(start_ttl, max_ttl):
        for tries in range(max_tries):
            packet_id = os.getpid() + int(random.randint(1, 1000))
            packet = crate_packet(packet_id, packet_size=packet_size)
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            try:
                udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                send_time = send_one_icmp_packet(ip, packet, udp_socket, port_number)
                rcv_packet, address, total_time = receive_one_icmp_packet(udp_socket, send_time, timeout)
                if address[0]:
                    break

            except socket.error as e:
                print(e)
            except TypeError:
                continue
            finally:
                udp_socket.close()
        if prv_address[0] != "0.0.0.0":
            if tries + 1 == ICMP_TRIES and prv_address[0] == address[0]:
                print(
                    f"HOP<{TextColors.PURPLE}{ttl}{TextColors.RESET}> <==> NO REPLY after {TextColors.ORANGE}{tries + 1}{TextColors.RESET} tries.")
                continue
        prv_address = address
        if ttl == 1:
            print(
                f"HOP<{TextColors.PURPLE}{ttl}{TextColors.RESET}> <==> GATEWAY<{TextColors.ORANGE}{address[0]}{TextColors.RESET}> in {TextColors.CYAN}{total_time}{TextColors.RESET} after {TextColors.ORANGE}{tries + 1}{TextColors.RESET} tries.")
            continue
        if address[0] == ip:
            print(
                f"HOP<{TextColors.PURPLE}{ttl}{TextColors.RESET}> <==> DESTINATION<{TextColors.ORANGE}{address[0]}{TextColors.RESET}> in {TextColors.CYAN}{total_time}{TextColors.RESET} after {TextColors.ORANGE}{tries + 1}{TextColors.RESET} tries.")
            return
        print(
            f"HOP<{TextColors.PURPLE}{ttl}{TextColors.RESET}> <==> <{TextColors.ORANGE}{address[0]}{TextColors.RESET}> in {TextColors.CYAN}{total_time}{TextColors.RESET} after {TextColors.ORANGE}{tries + 1}{TextColors.RESET} tries.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=" *traceroute* ")
    parser.add_argument("host", help="The host that you want trace.", type=str)
    parser.add_argument("-t", "--timeout", help="timeout for each ping reply (default is 1 second).", type=float)
    parser.add_argument("-s", "--size",
                        help="size of payload part of each ICMP request packet (default payload is 18).",
                        type=int)
    parser.add_argument("-l", "--maxHop", help="the max hop or max TTL.", type=int)
    parser.add_argument("-f", "--startTTL", help="the number of TTL that we start trace with it.", type=int)
    parser.add_argument("-e", "--tries", help="the number of tries for each TTL.", type=int)
    parser.add_argument("-p", "--port", help="the port number that send packet.", type=int)
    parser.add_argument("mode", help="choose mode like TCP or UDP or ICMP", type=str)
    args = parser.parse_args()

    host = args.host
    mode = args.mode
    timeout = args.timeout
    packet_size = args.size
    max_hop = args.maxHop
    start_TTL = args.startTTL
    tries_for_each_TTL = args.tries
    send_port = args.port
    if timeout is None:
        timeout = 1
    if packet_size is None:
        packet_size = 18
    if max_hop is None:
        if mode == "ICMP":
            max_hop = ICMP_MAX_HOP
    if start_TTL is None:
        start_TTL = 1
    if tries_for_each_TTL is None:
        if mode == "ICMP":
            tries_for_each_TTL = ICMP_TRIES
    if send_port is None:
        send_port = 0

    if mode == "ICMP":
        traceroute_use_icmp(host, timeout, send_port, start_TTL, max_hop, tries_for_each_TTL, packet_size)
