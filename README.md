# Computer Network Project

##phase1: port sniffer
#####simple port scanner that use thread to scan and find open ports of one host.
###### how to use it:
`$ python3 portSniffer.py HostName -r RangeofPorts`
###### use -h or --help for more information:
`python3 portSniffer.py -h`
###### you can choose threads number and timeout for each port with -n and -t.
###### simple example:
`$ python3 portSniffer.py www.google.com -t 2 -n 50 -p100`

##phase2:  ping
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
    Reply form IP<142.250.181.132> in 68.26282ms seq=1.
    Reply form IP<8.8.8.8> in 70.37783ms seq=1.
    Reply form IP<4.2.2.4> in 109.59363ms seq=1.
    Reply form IP<142.250.181.132> in 74.50199ms seq=2.
    Reply form IP<8.8.8.8> in 75.56725ms seq=2.
    Reply form IP<4.2.2.4> in 112.03265ms seq=2.
    Reply form IP<142.250.181.132> in 78.17078ms seq=3.
    Reply form IP<8.8.8.8> in 76.48325ms seq=3.
    Reply form IP<4.2.2.4> in 117.85197ms seq=3.
    Reply form IP<142.250.181.132> in 81.03633ms seq=4.
    Reply form IP<8.8.8.8> in 63.33733ms seq=4.
    Reply form IP<4.2.2.4> in 103.90949ms seq=4.
    Reply form IP<142.250.181.132> in 73.59552ms seq=5.
    Reply form IP<8.8.8.8> in 76.83110ms seq=5.
    Reply form IP<4.2.2.4> in 114.06994ms seq=5.
    ^C
    --------------------statistics--------------------
    For IP<142.250.181.132> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    For IP<8.8.8.8> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    For IP<4.2.2.4> <5> packet(s) sent and <5> packet(s) received, loss = 0.00% 
    MINIMUM RTT=<103.90949>ms, MAXIMUM RTT=<81.03633>ms
    
##phase3:  traceroute
##### find hops between source and destination.
- need root permission for run this code.
- only work on Linux.
- for now only work with ICMP packet.
###### how to use it:
`#  python3 traceroute.py host mode`
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

##phase4:  discover hosts
##### use arp frame to find up devise(s) in local network.
- need root permission for run this code.
- only work on Linux.
- this code might not work on some linux (you can change two function that export ip and mac address of interface if it doesn't work).
**you can find network interface in your host with `ip addr show` command.**
###### how to use it:
`# python3 hostDiscover.py ip/CIDR network-interface`
###### use -h or --help for more information:
`# python3 hostDiscover.py -h`
###### you can choose  timeout for each frame  with -t.
###### simple example:
`# python3 hostDiscover.py 10.10.24.1/24 wlo1`

:black_square_button: TODO: make send frames parallel.
