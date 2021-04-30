import socket
import struct
import random


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
    # id = int((id(1) * random.random()) % 65535)
    # print(id)
    # header = struct.pack('bbHHh', 8, 0, 0, id, 1)
    # print(header)
    # data = bytes( 192 * 'Q', 'utf-8')
    # print(header+data)
    # print( )
