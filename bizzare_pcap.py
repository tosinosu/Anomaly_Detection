import sys
from collections import Counter
from datetime import datetime
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, Ether, ICMP
from scapy.data import *
import numpy as np
from scapy.packet import Raw
import tensorflow as tf
from tensorflow.keras.layers import  Embedding
from sklearn.feature_extraction.text import CountVectorizer
from tensorflow.keras.preprocessing.text import Tokenizer

payload_var = ''
payload_std = ''
src_ip = ''
dest_ip = ''
src_mac = ''
dest_mac = ''
protocol = ''
version = ''
window = ''

def anonymize_data(df, cols):
    map = list()
    for col_name in cols:
        keys = {j: i for i, j in enumerate(df[col_name].unique())}
        values = {i: j for i, j in enumerate(df[col_name].unique())}
        df[col_name] = df[col_name].apply(lambda x: keys[x])
        #mapping[col_name] = df[col_name].apply(lambda x: values[x])
        map.append(pd.DataFrame([keys, values]))
    return df, map

def tokenizer(payload):
    tokenizer = Tokenizer(num_words = 200, lower=True, oov_token="<OOV>")
    tokenizer.fit_on_texts(payload)
    sequences = tokenizer.texts_to_sequences(payload)
    #print (sum(sequences))
    return sequences

def compute_character_std_var(payload):
    # Convert text to lowercase
    #text = text.lower()
    # Count the frequency of each character
    if payload == '':
        payload_var= 0
        payload_std= 0
    else:
        char_frequency = Counter(payload)
        list_freq = list(char_frequency.values())
        payload_var = np.var(list_freq)
        payload_std = np.std(list_freq)

    return payload_var, payload_std


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
            src_ip=None
            dest_ip =None
            len = None
            protocol = None

        if Ether in packet:
            src_mac = packet[Ether].src
            dest_mac = packet[Ether].src
            payload = str(packet[Ether].payload)
            payload_var, payload_std = compute_character_std_var(payload)
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
            payload_var, payload_std = compute_character_std_var(payload)

        else:
            src_port = ''
            src_mac = ''
            dest_port = ''
            dest_mac = ''
            tcp_checksum = ''
            tcp_flag = ''
            len = ''
            seq_num = ''
            ack_num = ''
            window = ''
                
        # Write packet information to CSV
        attributes.append([time, id, src_ip, src_mac, dest_ip, dest_mac, src_port, dest_port, protocol,
                                  seq_num, ack_num, tcp_flag, window, tcp_checksum, len, payload_std])
        #print(payload_std)

    df = pd.DataFrame(attributes, columns=csv_header)



    #Anonymizing columns
    columns_anon = ['Src_IP', 'Src_MAC','Dest_IP', 'Dest_MAC']
    raw_data, mapping = anonymize_data(df, columns_anon)
    
    raw_data.to_csv(sys.argv[2], index_label="Index")
    pd.DataFrame(mapping).to_csv('Data mapping.csv')
else:
    print("Incorrect usage")
    print("Syntax: python python_filename <pcap_file> <csv_filename_to_create>")
