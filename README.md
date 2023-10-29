# Computer Network Project

**computer network course**

## phase1: port sniffer

##### simple port scanner that use thread to scan and find open ports of one host.

###### how to use it:

`$ python3 portSniffer.py HostName -r RangeofPorts`

###### use -h or --help for more information:

`python3 portSniffer.py -h`

###### you can choose threads number and timeout for each port with -n and -t.

###### simple example:

`$ python3 portSniffer.py www.google.com -t 2 -n 50 -p50`

###### result:

    server ip is 142.250.181.68
    port 80 is open!
    port 443 is open!
    port 21 is close!
    port 25 is close!
    port 22 is close!
    port 53 is close!
    port 110 is close!
    port 113 is close!
    port 135 is close!
    port 139 is close!
    port 143 is close!
    port 179 is close!
    port 199 is close!
    port 465 is close!
    port 514 is close!
    port 445 is close!
    port 548 is close!
    port 554 is close!
    port 646 is close!
    port 587 is close!
    port 993 is close!
    port 995 is close!
    port 1025 is close!
    port 1026 is close!
    port 1433 is close!
    port 1720 is close!
    port 1723 is close!
    port 3389 is close!
    port 5060 is close!
    port 2000 is close!
    port 3306 is close!
    port 5900 is close!
    port 6001 is close!
    port 8008 is close!
    port 5666 is close!
    port 8000 is close!
    port 8080 is close!
    port 49152 is close!
    port 8443 is close!
    port 32768 is close!
    port 8888 is close!
    port 10000 is close!
    port 49154 is close!
    time = 2.0583906173706055
    ************************************************************
    port 80 : OPEN
    port 443 : OPEN
    ************************************************************

## phase2:  ping

##### ping one host or more parallel.

- need root permission for run this code.
- only work on Linux.

###### how to use it:

`# python3 ping.py "name of hosts(in quotes)"`

###### use -h or --help for more information:

`# python3 ping.py -h`

###### you can choose  timeout for each packet and size of each packet with -t and -s.

###### simple example:

`#python3 ping.py "www.google.com 8.8.8.8 4.2.2.4" -t 1 -s 50`

###### result:

    Host <www.google.com><142.250.181.132> added for being ping...
    IP<8.8.8.8> added for being ping...
    IP<4.2.2.4> added for being ping...
    Reply form IP<142.250.181.132> in 76.96891ms seq=1.
    Reply form IP<8.8.8.8> in 80.33347ms seq=1.
    Reply form IP<4.2.2.4> in 115.08918ms seq=1.
    Reply form IP<142.250.181.132> in 65.82022ms seq=2.
    Reply form IP<8.8.8.8> in 62.90579ms seq=2.
    Reply form IP<4.2.2.4> in 115.83161ms seq=2.
    Reply form IP<142.250.181.132> in 73.05884ms seq=3.
    Reply form IP<8.8.8.8> in 78.19939ms seq=3.
    Reply form IP<4.2.2.4> in 119.86613ms seq=3.
    Reply form IP<142.250.181.132> in 63.27558ms seq=4.
    Reply form IP<8.8.8.8> in 68.88342ms seq=4.
    Reply form IP<4.2.2.4> in 117.94543ms seq=4.
    Reply form IP<142.250.181.132> in 73.10867ms seq=5.
    Reply form IP<8.8.8.8> in 62.58607ms seq=5.
    Reply form IP<4.2.2.4> in 117.50531ms seq=5.
    ^C
    --------------------statistics--------------------
    For IP<142.250.181.132> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    For IP<8.8.8.8> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    For IP<4.2.2.4> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    MINIMUM RTT=<62.58607>ms, MAXIMUM RTT=<119.86613>ms

:black_square_button: TODO: optimize functions that use asyncio.
:black_square_button: TODO: fix bug in diffrence between pid and identifier.

## phase3:  traceroute

##### find hops between source and destination.

- need root permission for run this code.
- only work on Linux.
- for now only work with ICMP packet.

###### how to use it:

`# python3 traceroute.py host mode`

###### use -h or --help for more information:

`# python3 traceroute.py -h`

###### you can choose  timeout for each packet, size of each packet, start TTL, Maximum hop or Maximum TTL, number of tries and send port with -t, -s, -f, -l, -e and -p.

###### simple example:

`# python3 traceroute.py 8.8.8.8 ICMP -t 1 -s 25 -l 40 -f 5 -e 4 -p 0`

###### result:

    traceroute <8.8.8.8> use ICMP:
    HOP<5> <==> <10.188.89.133> in 19.31143 after 1 tries.
    HOP<6> <==> NO REPLY after 4 tries.
    HOP<7> <==> <10.188.89.65> in 29.99926 after 1 tries.
    HOP<8> <==> NO REPLY after 4 tries.
    HOP<9> <==> <10.138.99.30> in 36.32927 after 1 tries.
    HOP<10> <==> <10.138.98.6> in 41.35251 after 1 tries.
    HOP<11> <==> <10.21.249.6> in 23.06533 after 1 tries.
    HOP<12> <==> <10.21.0.11> in 46.63014 after 1 tries.
    HOP<13> <==> <10.41.51.20> in 47.44816 after 1 tries.
    HOP<14> <==> <10.21.41.12> in 57.31082 after 1 tries.
    HOP<15> <==> <10.202.4.206> in 61.75208 after 1 tries.
    HOP<16> <==> <213.202.4.172> in 66.32495 after 1 tries.
    HOP<17> <==> <213.202.5.239> in 75.47593 after 1 tries.
    HOP<18> <==> <216.239.48.87> in 69.51118 after 1 tries.
    HOP<19> <==> <142.251.48.1> in 89.30731 after 1 tries.
    HOP<20> <==> DESTINATION<8.8.8.8> in 71.86580 after 1 tries.

:black_square_button: TODO: implement traceroute with tcp packet.

:black_square_button: TODO: implement traceroute with udp packet.

:black_square_button: TODO: send three packet parallel.

## phase4:  discover hosts

##### use arp frame to find up devise(s) in local network.

- need root permission for run this code.
- only work on Linux.
- this code might not work on some linux (you can change two function that export ip and mac address of interface if it
  doesn't work).

**you can find network interface in your host with `ip addr show` command.**

###### how to use it:

`# python3 hostDiscover.py ip/CIDR network-interface`

###### use -h or --help for more information:

`# python3 hostDiscover.py -h`

###### you can choose  timeout for each frame  with -t.

###### simple example:

`# python3 hostDiscover.py 10.10.24.1/24 wlo1`

###### resutl:

    Try for 10.10.24.1
    Interface with 4c:5e:0c:05:00:06 MAC address have 10.10.24.1 IP address.
    Try for 10.10.24.2
    Try for 10.10.24.3
    Try for 10.10.24.4
    Try for 10.10.24.5
    Try for 10.10.24.6
    Try for 10.10.24.7
    Try for 10.10.24.8
    Try for 10.10.24.9
    Try for 10.10.24.10
    Try for 10.10.24.11
    ^C
    10 IP tries and 1 host(s) found.

:black_square_button: TODO: send frames parallel.
