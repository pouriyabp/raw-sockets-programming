import socket
import struct
import select
import os
import sys
import time
import signal
import asyncio
import argparse
from operator import attrgetter

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
ARRAY_OF_REQUEST = []
ARRAY_OF_RESPONSE = []
ARRAY_OF_HOSTS = []


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


# set information of each icmp reply in this class
class Response:
    def __init__(self, address, packet, rtt, pid, seq):
        self.address = address
        self.packet = packet
        self.rtt = rtt
        self.id = pid
        self.sequence = seq

    def __repr__(self):
        return f"{self.sequence}"
        # return f"IP={self.address} RTT={self.rtt} seq={self.sequence}"


# set information of each icmp request in this class
class Request:
    def __init__(self, address, packet, send_time, pid, seq):
        self.address = address
        self.packet = packet
        self.sendTime = send_time
        self.id = pid
        self.sequence = seq

    def __repr__(self):
        return f"{self.sequence}"
        # return f"IP={self.address} RTT={self.sendTime} seq={self.sequence}"


def crate_packet(identifier, sequence_number=1, packet_size=10):  # default packet size is 10 byte.
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
    if address == '127.0.0.1':
        response = Response(address, reply_packet, rtt, pid, sequence)
        return response
    if calculate_checksum(reply_header + reply_packet[:20]) == checksum:
        # second we check the header of reply packet:
        if type_of_message == 0 and code == 0 and pid == identifier and sequence == sequence_number:
            response = Response(address, reply_packet, rtt, pid, sequence)
            return response


def print_response(response):
    return f"Reply form IP<{TextColors.ORANGE}{response.address}{TextColors.RESET}> in {TextColors.CYAN}" \
           f"{response.rtt}ms{TextColors.RESET} seq={TextColors.CYAN}{response.sequence}{TextColors.RESET}."


def change_to_ip(host_name):
    try:
        server_ip = socket.gethostbyname(host_name)
        return server_ip
    except socket.error:
        return None


def calculate_statistics():
    hosts_dict_rtt = {}
    hosts_dict_loss = {}
    hosts_dict_req_packets = {}

    for host in ARRAY_OF_HOSTS:
        loss = 0
        sum_rtt = 0
        req_packets = 0
        for req in ARRAY_OF_REQUEST:
            if req.address == host:
                req_packets += 1
                find = False
                for res in ARRAY_OF_RESPONSE:
                    if req.id == res.id and req.sequence == res.sequence and req.address == res.address:
                        sum_rtt += float(res.rtt)
                        find = True
                        break
                if not find:
                    loss += 1
        hosts_dict_rtt[host] = sum_rtt
        hosts_dict_loss[host] = loss
        hosts_dict_req_packets[host] = req_packets
    return hosts_dict_req_packets, hosts_dict_rtt, hosts_dict_loss


def show_statistics(hosts_arr, hosts_dict_req_packets, hosts_dict_rtt, hosts_dict_loss):
    result = []
    for host in hosts_arr:
        send = hosts_dict_req_packets[host]
        rtt = hosts_dict_rtt[host]
        loss = hosts_dict_loss[host]
        receive = send - loss
        if send != 0:
            average_rtt = rtt / send
            per_loss = (loss / send) * 100
            per_loss = "{:.2f}".format(per_loss)
        else:
            average_rtt = 0.0
            per_loss = 0.0
        inf = f"For IP<{TextColors.ORANGE}{host}{TextColors.RESET}> <{TextColors.YELLOW}{send}{TextColors.RESET}> " \
              f"packet(s) sent and <{TextColors.GREEN}{receive}{TextColors.RESET}> packet(s) " \
              f"received, loss = {TextColors.RED}{per_loss}{TextColors.RESET}% "
        result.append(inf)
    return result


# handle sigint
def signal_handler(sig, frame):
    print(f'\n{TextColors.CYAN}--------------------statistics--------------------{TextColors.RESET}')
    req_packet, host_rtt, host_loss = calculate_statistics()
    result = show_statistics(ARRAY_OF_HOSTS, req_packet, host_rtt, host_loss)
    for text in result:
        print(text)
    max_rtt_obj = max(ARRAY_OF_RESPONSE, key=attrgetter('rtt'))
    min_rtt_obj = min(ARRAY_OF_RESPONSE, key=attrgetter('rtt'))
    print(
        f"MINIMUM RTT=<{TextColors.PURPLE}{min_rtt_obj.rtt}{TextColors.RESET}>ms, "
        f"MAXIMUM RTT=<{TextColors.PURPLE}{max_rtt_obj.rtt}{TextColors.RESET}>ms")
    sys.exit(0)


async def ping_one_host(host_name, timeout=1, icmp_packet_size=0):
    ip_of_host = change_to_ip(host_name)
    pid = os.getpid()
    seq_number = 1
    while True:
        request_icmp_packet = crate_packet(pid, seq_number, icmp_packet_size)
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            send_time = send_one_icmp_packet(ip_of_host, request_icmp_packet, my_socket)
            req = Request(ip_of_host, request_icmp_packet, send_time, pid, seq_number)
            ARRAY_OF_REQUEST.append(req)
            reply_icmp_packet, address, rtt = receive_one_icmp_packet(my_socket, req.sendTime, timeout)
            if reply_icmp_packet is not None and address[0] == ip_of_host:
                result = open_packet(reply_icmp_packet, pid, seq_number, rtt, ip_of_host)
                ARRAY_OF_RESPONSE.append(result)
                print(print_response(result))
            my_socket.close()
        except socket.error as e:
            print(e)
        except TypeError:
            print(f"Reply Timeout.")
        seq_number += 1
        await asyncio.sleep(1)
        # time.sleep(0.5)


# async def main(timeout=1, packet_size=0):
#     arr_of_task = []
#     for host in ARRAY_OF_HOSTS:
#         task = asyncio.create_task(ping_one_host(host, timeout, packet_size))
#         arr_of_task.append(task)
#     for task in arr_of_task:
#         await task


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description=" *ping hosts* ")
    parser.add_argument("host", help="The host or hosts that you want ping.", type=str)
    parser.add_argument("-t", "--timeout", help="timeout for each ping reply (default is 1 second).", type=float)
    parser.add_argument("-s", "--size", help="size of payload part of each ICMP request packet (default payload is 0).",
                        type=int)
    args = parser.parse_args()
    hosts = args.host
    timeout_for_response = args.timeout
    payload_size = args.size
    if timeout_for_response is None:
        timeout_for_response = 1
    if payload_size is None:
        payload_size = 0
    hosts = hosts.split(" ")

    for text in hosts:
        ip_of_text = change_to_ip(text)
        if ip_of_text == '0.0.0.0':
            continue
        if ip_of_text is not None:
            if ip_of_text not in ARRAY_OF_HOSTS:
                ARRAY_OF_HOSTS.append(ip_of_text)
                if str(ip_of_text) == text:
                    print(
                        f"IP<{TextColors.ORANGE}{text}{TextColors.RESET}> added for being ping...")
                else:
                    print(
                        f"Host <{TextColors.ORANGE}{text}{TextColors.RESET}><{TextColors.CYAN}{ip_of_text}"
                        f"{TextColors.RESET}> added for being ping...")
    if len(ARRAY_OF_HOSTS) == 0:
        print(f'{TextColors.RED}NO HOST FOUND!!!!{TextColors.RESET}')
    # asyncio.run(main(timeout_for_response, payload_size))
    loop = asyncio.get_event_loop()
    for host in ARRAY_OF_HOSTS:
        task = asyncio.ensure_future(ping_one_host(host, timeout_for_response, payload_size))
    loop.run_forever()
