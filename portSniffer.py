import socket


#
server=str(input("Enter host name: "))
portRange=int(input("Enter port number: "))
timeout=int(input("Enter timeout for scanning: "))


def checkPort(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if (s.connect_ex((server, port))==0):
            s.close()
            return True
        else:
            s.close()
            return False
    except Exception as e:
        print(e)
        return False


for port in range(1,portRange):
    if checkPort(int(port)):
        print(f"port {port} is open!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    else:
        print(f"port {port} is closed!")



