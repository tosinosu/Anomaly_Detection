import sys
import scapy
from datetime import datetime
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, Ether, ICMP
from scapy.data import *
import numpy as np
from scapy.packet import Raw
from tensorflow import keras
from tensorflow.keras.preprocessing.text import Tokenizer

payload = ''
src_ip = ''
dest_ip = ''
src_mac = ''
dest_mac = ''
protocol = ''
version = ''
window = ''

def anonymize_data(df, cols):
    for col_name in cols:
        keys = {j: i for i, j in enumerate(df[col_name].unique())}
        df[col_name] = df[col_name].apply(lambda x: keys[x])
    return df

def tokenizer(payload):
    tokenizer = Tokenizer(num_words = 200, lower=True, oov_token="<OOV>")
    tokenizer.fit_on_texts(payload)
    sequences = tokenizer.texts_to_sequences(payload)
    print (type(sequences))
    return sequences

if len(sys.argv) == 3:
    attributes = []  

    packets = sniff(offline=sys.argv[1])

    # Write CSV header
    csv_header = ('Time', 'Identifier', 'Src_IP', 'Src_MAC','Dest_IP', 'Dest_MAC', 'Src_Port', 'Dest_Port', 
                         'Proto', 'Seq_Num', 'Ack_Num', 'TCP_Flag','Window_Size', 'TCP_Checksum',
                           "Packet_Length", 'Payload')
        
    # Extract packet information and write to CSV
    for i, packet in enumerate(packets):
        time = packet.time
        #time = datetime.utcfromtimestamp(math.floor(time_utc))

        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            len = packet[IP].len
            id = packet[IP].id
            protocol = packet[IP].proto
            version = packet[IP].version
        else:
            src_ip='Unknown'
            dest_ip = 'Unknown'
            len = 'Unknown'
            protocol = 'Unknown'

        if Ether in packet:
            src_mac = packet[Ether].src
            dest_mac = packet[Ether].src
            payload = str(packet[Ether].payload)
        #if Raw in packet:
            #payload = packet[Raw].load
        #else:
        #    payload = "Unknown" bytes(packet[TCP].payload).decode('UTF8','replace')

       # if ICMP in packet:
         #   icmp_code = packet[ICMP].code
      #  else:
       #     icmp_code ="Unknown"

        if TCP in packet:
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            tcp_flag = packet[TCP].flags
            tcp_checksum = packet[TCP].chksum
            window = packet[TCP].window
        elif UDP in packet:
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            payload = str(packet[UDP].payload)
        else:
            src_port = 'Unknown'
            src_mac = 'Unknown'
            dest_port = 'Unknown'
            dest_mac = 'Unknown'
            tcp_checksum = 'Unknown'
            tcp_flag = "Unknown"
            len = 'Unknown'
            seq_num = "Unknown"
            ack_num = "Unknown"
            window = "Unknown"
                
        # Write packet information to CSV
        attributes.append([time, id, src_ip, src_mac, dest_ip, dest_mac, src_port, dest_port, protocol,
                                  seq_num, ack_num, tcp_flag, window, tcp_checksum, len, payload])

    df = pd.DataFrame(attributes, columns=csv_header)

    tokenize = tokenizer(df.Payload.to_list())
   # print((tokenize.shape))
   # df.Payload = df.sum(tokenize)#, axis = 1, keepdims = True)
    #print((df.Payload))
    #Anonymizing columns
    columns_anon = ['Src_IP', 'Src_MAC','Dest_IP', 'Dest_MAC']
    raw_data = anonymize_data(df, columns_anon)

    #raw_data.to_csv(sys.argv[2], index_label="Index")
else:
    print("Incorrect usage")
    print("Syntax: python readpcap.py <pcap_file> <csv_filename_to_create>")
