from scapy.all import IP,ICMP,send,sr1,TCP #Use in Level1 Functions
from scapy.all import sr,conf,getmacbyip #Use in Level2 Functions
from scapy.all import UDP,ISAKMP,ISAKMP_payload_SA,rdpcap,sendp #Use in Advanced Functions
import PySimpleGUI as sg #use for GUI creating
import random #Use in Generating Source Port Number

#====Initialize====
ipv4_level1_submits = [
    sg.Text('Level1 Functions'),
    sg.Submit("Ping 1-way(IPv4)",key="ping_1way_ipv4"),
    sg.Submit("Ping 2-way(IPv4)",key="ping_2way_ipv4"),
    sg.Submit("SYN 1-way(IPv4)",key="syn_1way_ipv4"),
    sg.Submit("SYN 3-way-handshake(IPv4)",key="syn_3way_ipv4"),
    ]
ipv4_level2_submits = [
    sg.Text('Level2 Functions'),
    sg.Submit("TCP Well-Known Port Scan(IPv4)",key="tcp_port_scan"),
    sg.Submit("Confirm Routes(IPv4)",key="confirm_ipv4_routes"),
    sg.Submit("Get_MAC address(IPv4)",key="confirm_mac_address"),
]
ipv4_advanced_submits = [
    sg.Text('Advanced Functions'),
    sg.Submit("Xmas Scan(IPv4)",key="xmas_scan"),
    sg.Submit("IKE Packet(IPv4)",key="ike_scan"),
    sg.Submit("Send Packet(IPv4,.pcap)",key="send_pcap_file")
]

sg.theme('Reddit')
layout = [
            [sg.Text("[Required]Source(IPv4): "), sg.InputText(key="ip_src")],
            [sg.Text("[Required]Destination(IPv4): "),sg.InputText("127.0.0.1",key="ip_dst")],
            [sg.Text("[Recommended]First: connectivity test by ping 2-way")],
            [sg.Text("[Advanced]Select PCAP file(.pcap)"),sg.InputText(),sg.FileBrowse(key="pcap_file")],
            ipv4_level1_submits,
            ipv4_level2_submits,
            ipv4_advanced_submits,
            [sg.Text('Statement'),sg.Output(key='statement',size=(50,1)),sg.Cancel("Wanna Cancel",key="cancel")],
            [sg.Text('Results'),sg.Output(key='results',size=(100,15))],
        ]
window = sg.Window(title='Scapy GUI for Beginners', layout=layout)

#====Level1 functions====
def ping_1way(src,dst): #ping_request
    window['statement'].update("Ready!")
    ping_request = IP(src = src, dst=dst)/ICMP()
    send(ping_request) #Send ICMP packet on Layer3
    window['statement'].update("Completed!")
    window['results'].update("[info] Ping(1-way): only Send and no Response")

def ping_2way(src,dst): #ping_request & ping reply
    window['statement'].update("Ready!")
    ping_request = IP(src = src, dst=dst,ttl=(5,5))/ICMP()
    ping_reply  = sr1(ping_request,timeout=10) #Send ICMP request and Receive ICMP response on Layer3
    results = ping_reply.show() if ping_reply else "dst→src: No Response(src or dst is not correct..??)"
    window['statement'].update("ping reply Result")
    window['results'].update(results)

def syn_1way(src,dst): #Send SYN packet
    window['statement'].update("Ready!")
    ip = IP(src = src, dst = dst)
    sport  = random.randint(1024,65535)
    seq_num    = random.randint(0,1000)
    SYN = ip/TCP(sport=sport,dport=443,flags='S',seq=seq_num)
    send(SYN) #Send SYN packet on Layer3
    window['statement'].update("Completed!")
    window['results'].update("[info] SYN(1-way): only Send and no Response")

def syn_3way(src,dst): #SYN→SYN\ACK→ACK(SYNchronize & ACKnowledge) #Destination_port:80
    window['statement'].update("Ready!")
    ip = IP(src = src, dst = dst,ttl=(5,5))
    sport  = random.randint(1024,65535)
    seq_num  = random.randint(0,1000)
    SYN = ip/TCP(sport=sport,dport=80,flags='S',seq=seq_num) #SYN packet
    SYN_ACK = sr1(SYN,timeout=10) #Send SYN and Receive SYN/ACK on Layer3
    if SYN_ACK:
        ACK = ip/TCP(sport=sport, dport=80, flags='A', seq=SYN_ACK.ack , ack=SYN_ACK.seq + 1) #ACK packet
        send(ip/ACK) #Send packet on Layer3
    syn_ack_info = SYN_ACK.show() if SYN_ACK else "Please Retry! dst→src: No Response Found(IPv4 is wrong or dst_port:80 is not open..??)"
    window['statement'].update("SYN/ACK packet")
    window['results'].update(syn_ack_info)

#====Level2 functions====
def tcp_port_scan(src,dst):#TCP Port Scan(Well-known)
    window['statement'].update("Ready!")
    sport  = random.randint(1024,65535)
    port_scan_scope = IP(src= src, dst=dst,ttl=(5,5))/TCP(flags="S",sport=sport, dport=(1,1024))#dst: well-known port
    answers = sr(port_scan_scope,timeout=3) #Scan(Send SYN and Receive SYN/ACK) on Layer3
    if answers:
        ans,_ = answers[0],answers[1:]
    results = ans.summary( lambda s,r: r.sprintf("%TCP.sport% \t %TCP.flags%")) if answers else "dst→src: No Response Found(IPv4 is wrong or ..??)"
    window['statement'].update("TCP Port Scan Results(SA: open,RA: filtered)")
    window['results'].update(results)

def confirm_ipv4_routes():#Get iptables routes about IPv4
    window['statement'].update("Ready!")
    window['statement'].update("ipv4_route results")
    window['results'].update(conf.route)

def confirm_mac_address(src,dst):#Get MAC by IP
    window['statement'].update("Ready!")
    mac_src,mac_dst = getmacbyip(src),getmacbyip(dst)
    window['statement'].update("Get MAC Address by IPv4")
    results ={"MAC_address(Source)":mac_src,"Mac_address(Destination)":mac_dst}
    window['results'].update(results)
    pass

#====Advanced Functions=====
def xmas_scan(src, dst):#TCP packet with the FIN,PSH,URG flags set. #Destination_port:666
    window['statement'].update("Ready!")
    sport  = random.randint(1024,65535)
    FPU = IP(src=src, dst=dst,ttl=(5,5))/TCP(sport=sport, dport=666,flags="FPU") #FPU packet #Destination_port:666
    answers = sr1(FPU,timeout=10) #TCP EXISTS: on Layer3.
    if answers:
        ans,_ = answers[0],answers[1:]
    results = ans.summary() if answers else "No Response Found(IPv4 is wrong or dst_port:666..??)"
    window['statement'].update("Xmas(FIN,PSH,URG) Scan Results")
    window['results'].update(results)

def ike_scan(src,dst): #identify VPN concentrators by sending ISAKMP Security Association proposals
    window['statement'].update("Ready!")
    sport  = random.randint(1024,65535)
    simple_packet = IP(src= src, dst=dst,ttl=(5,5))/UDP()
    proposals = simple_packet/ISAKMP()/ISAKMP_payload_SA()
    answers = sr(proposals,timeout=10) #Send and Receive
    if answers:
        ans,_ = answers[0],answers[1:]
    results = ans.nsummary(prn=lambda s,r: r.src,lfilter=lambda s,r: r.haslayer(ISAKMP)) if answers else "No Response Found"
    window['statement'].update("IKE Scan Results")
    window['results'].update(results)

def send_pcap_file(ip_src,ip_dst,pcap_file):#Send packet on Layer3 and Layer2 because protocol is not clear
    window['statement'].update("Ready!")
    packet=rdpcap(pcap_file)
    packet[IP].src,packet[IP].dst = ip_src, ip_dst
    send(packet) #Send packet on Layer3
    sendp(packet) #Send packet on Layer2
    window['statement'].update("Send Packet")
    window['results'].update(packet.show())

#====Operate GUI ====
while True:
    event, values = window.read()
    ip_src = values["ip_src"]
    ip_dst = values["ip_dst"]
    pcap_file = values["pcap_file"]

    #[Execute]: Click "x Button" on upper right, GUI is Closed
    if event == sg.WIN_CLOSED:
        break
    #[Execute]: Click "Wanna Cancel Button", GUI is not Closed but STOP Execute something
    if event == "cancel":
        continue

    #[Execute]: Click "IPv4 event"(Level1)
    if event == "ping_1way_ipv4":
        ping_1way(ip_src,ip_dst)
    if event == "ping_2way_ipv4":
        ping_2way(ip_src,ip_dst)
    if event == "syn_1way_ipv4":
        syn_1way(ip_src,ip_dst)
    if event == "syn_3way_ipv4":
        syn_3way(ip_src,ip_dst)

    #[Execute]: Click "IPv4 event"(Level1)
    if event =="tcp_port_scan":
        tcp_port_scan(ip_src,ip_dst)
    if event == "confirm_ipv4_routes":
        confirm_ipv4_routes()
    if event == "confirm_mac_address":
        confirm_mac_address(ip_src,ip_dst)

    ##[Execute]: Click "IPv4 event"(Advanced)
    if event =="xmas_scan":
        xmas_scan(ip_src,ip_dst)
    if event == "ike_scan":
        ike_scan(ip_src,ip_dst)
    if event == "send_pcap_file":
        send_pcap_file(ip_src,ip_dst, pcap_file)
window.close()

#PySimpleGUI Reference: https://github.com/PySimpleGUI/PySimpleGUI
#scapy Reference: https://scapy.readthedocs.io/en/latest/usage.html
#You should confirm Packets with Wireshark:https://www.wireshark.org/