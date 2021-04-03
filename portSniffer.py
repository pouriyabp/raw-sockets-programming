import socket
import threading
import time
from queue import Queue


# check port is open or not
def checkPort(ip, port, timeout, output,printLock):
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


def threader(ip, queue, timeout,  output,printLock):
    while True:
        CPort=queue.get()
        checkPort(ip,CPort,timeout,output,printLock)
        queue.task_done()



def startThread(ip, queue, timeout, threadsN, output,printLock):
    for x in range(threadsN):
        t = threading.Thread(target=threader,args=(ip,queue,timeout,output,printLock))
        t.daemon = True
        t.start()


def fillTargetsPort(queue,arry,rangeDown,rangeUp):
    for p in range(rangeDown, rangeUp):
        arry.append(p)
        queue.put(p)


def start():
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
    queue = Queue()

    printLock = threading.Lock()


#--------------------------------------------------------------------------------------------------------
    if 'http://' in server or 'https://' in server:
        server = server[server.find('://') + 3:]

    x=time.time()
    fillTargetsPort(queue,targetPorts,portRangeDown,portRangeUp)
    time.sleep(0.01)

    startThread(server, queue, timeout, threadsNumber, output,printLock)
    print(targetPorts)

    while len(output)<len(targetPorts):
        x=len(output)
        time.sleep(0.01)
        continue
    y=time.time()
    print(f"x is {x} and y is {y} and x-y is {y-x}")
    print(output)

start()
