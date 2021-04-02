import socket


#
server=str(input("Enter host name: "))
portRange=int(input("Enter port number: "))
timeout=int(input("Enter timeout for scanning: "))

#check port is open or not
def checkPort(ip,port,timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result=s.connect_ex((ip,port))
        if result==0:
            return True
        else:
            return False

    except socket.error as e:
       # print(e)
        return False









#
# for port in range(1,portRange):
#     if checkPort(server,port,timeout):
#         print(f"port {port} is open!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
#
#     else:
#         print(f"port {port} is closed!")



