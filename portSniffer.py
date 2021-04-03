import socket
import threading
import time
from queue import Queue
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
threadsNumber = 10
# for save result to show
output = {}
# for choose ports that we want to check
targetPorts = []
queue=Queue()

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


def threader(ip, queue, timeout,  output):
    while True:
        CPort=queue.get()
        checkPort(ip,CPort,timeout,output)
        queue.task_done()



def startThread(ip, queue, timeout, threadsN, output):
    for x in range(threadsN):
        t = threading.Thread(target=threader,args=(ip,queue,timeout,output))
        t.daemon = True
        t.start()


def fillTargetsPort(arry):
    for p in range(portRangeDown, portRangeUp):
        arry.append(p)
        queue.put(p)


def start():
    x=time.time()
    fillTargetsPort(targetPorts)
    time.sleep(0.01)

    startThread(server, queue, timeout, threadsNumber, output)
    print(targetPorts)

    while len(output)<len(targetPorts):
        x=len(output)
        time.sleep(0.01)
        continue
    y=time.time()
    print(f"x is {x} and y is {y} and x-y is {y-x}")
    print(output)

start()
