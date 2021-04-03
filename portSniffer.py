import socket
import threading
import time

#
# server=str(input("Enter host name: "))
# portRangeDown=int(input("Enter port number start from: "))
# portRangeUp=int(input("Enter port number to end in: "))
# timeout=int(input("Enter timeout for scanning: "))
# threadsNumber=int(input("Enter threads number: "))

server = "www.google.com"
portRangeDown = 1
portRangeUp = 100
timeout = 1
threadsNumber = 2
# for save result to show
output = {}
# for choose ports that we want to check
targetPorts = []

printLock=threading.Lock()

# check port is open or not
def checkPort(ip, port, timeout, output):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            s.close()
            output[port] = "open"
            with printLock:
                print(f"port {port} is open!")
            return True
        else:
            s.close()
            output[port] = "close"
            with printLock:
                print(f"port {port} is close!")
            return False



    except socket.error as e:
        print(e)
        s.close()
        output[port] = "close"
        with printLock:
            print(f"port {port} is close!")
        return False


def threader(ip, targetports, timeout, threadsN, output):
    i = 0
    tCount=0
    while i<len(targetports):
        x=threading.activeCount()
        while tCount < threadsN and i < len(targetports):
            t = threading.Thread(target=checkPort, args=(ip, targetports[i], timeout, output))
            t.daemon=True
            t.start()
            tCount+=1
            i += 1
        time.sleep(0.01)


def startThread(ip, targetports, timeout, threadsN, output):
    thread = threading.Thread(target=threader, args=(ip, targetports, timeout, threadsN, output))
    thread.start()


def fillTargetsPort(arry):
    for p in range(portRangeDown, portRangeUp):
        arry.append(p)


def start():
    x=time.time()
    fillTargetsPort(targetPorts)
    time.sleep(0.01)

    startThread(server, targetPorts, timeout, threadsNumber, output)
    print(targetPorts)

    while len(output)<len(targetPorts):
        x=len(output)
        time.sleep(0.01)
        continue
    y=time.time()
    print(f"x is {x} and y is {y} and x-y is {y-x}")
    print(output)

start()
