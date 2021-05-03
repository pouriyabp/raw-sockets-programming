import socket
import struct
import select
import os
import sys
import time
import signal

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


def crate_packet(identifier, sequence_number=1, packet_size=10):  # default packet size is 10 byte.
    # Maximum for an unsigned short int c object counts to 65535(0xFFFF) we have to sure that our packet id is not
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


def open_packet(reply_packet, identifier, sequence_number, rtt, address):
    type_of_message, code, checksum, pid, sequence = struct.unpack('!BBHHH', reply_packet[20:28])
    # first we have to check the checksum:
    reply_header = struct.pack('!BBHHH', type_of_message, code, 0, pid, sequence)
    if calculate_checksum(reply_header + reply_packet[:20]) == checksum:
        # second we check the header of reply packet:
        if type_of_message == 0 and code == 0 and pid == identifier and sequence == sequence_number:
            return f"Reply form IP<{TextColors.GREEN}{address}{TextColors.RESET}> in {TextColors.CYAN}{rtt}ms{TextColors.RESET} seq={TextColors.CYAN}{sequence}{TextColors.RESET}."


def change_to_ip(host_name):
    try:
        server_ip = socket.gethostbyname(host_name)
        return server_ip
    except socket.error as e:
        print(e)
        return None

# handle sigint
def signal_handler(sig, frame):
    print(f'\n{TextColors.CYAN}--------------------statistics--------------------{TextColors.RESET}\n')

    sys.exit(0)


def ping_one_host(host_name, timeout=20, icmp_packet_size=0):
    ip_of_host = change_to_ip(host_name)
    pid = os.getpid()
    seq_number = 1
    while True:
        request_icmp_packet = crate_packet(pid, seq_number, icmp_packet_size)
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            send_time = send_one_icmp_packet(ip_of_host, request_icmp_packet, my_socket)
            reply_icmp_packet, address, rtt = receive_one_icmp_packet(my_socket, send_time, timeout)
            if reply_icmp_packet is not None and address[0] == ip_of_host:
                result = open_packet(reply_icmp_packet, pid, seq_number, rtt, ip_of_host)
                print(result)
            my_socket.close()
        except socket.error as e:
            print(e)
        except TypeError as e:
            print(f"Reply Timeout.")
        seq_number += 1
        time.sleep(0.5)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    ping_one_host('www.google.com', 1)


if __name__ == "__main__":
    main()
