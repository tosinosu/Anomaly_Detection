from os import makedirs, path, listdir
from math import floor
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter
from scapy.all import IP, TCP, UDP, Ether, rdpcap

def compute_character_std_var(payload):
    if payload == '':
        payload_std= 0
    else:
        char_frequency = Counter(payload)
        list_freq = list(char_frequency.values())
        payload_std = np.std(list_freq)
    return payload_std

def extract_features(packet):
    payload_std = src_ip = dest_ip = src_mac=dest_mac=protocol=ttl=window=seq_num= ack_num=tcp_flag=tcp_checksum=time=packet_id=packet_len=''
    #ack_num=tcp_flag=tcp_checksum=time=packet_id=packet_len = ''

    time_utc = packet.time
    time = datetime.utcfromtimestamp(floor(time_utc))

    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        packet_len = packet[IP].len
        packet_id = packet[IP].id
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
    else:
        src_ip = dest_ip = packet_len = packet_id = protocol = ttl = ''

    if Ether in packet:
        src_mac = packet[Ether].src
        dest_mac = packet[Ether].src
        if packet[Ether].payload is not None:
                payload = str(packet[Ether].payload)
                payload_std = compute_character_std_var(payload)
        else:
            payload_std = 0
    else:
        src_mac = dest_mac = payload_std = ''

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
        payload_std = compute_character_std_var(payload)
    else:
        src_port = dest_port = seq_num = ack_num = tcp_flag = tcp_checksum = window = ''

    return [time, packet_id, src_ip, src_mac, dest_ip, dest_mac, src_port, dest_port, protocol, seq_num, ack_num,
            tcp_flag, ttl, window, tcp_checksum, packet_len, payload_std]

attributes = []
directory = 'pcap/pcap'
pcap_files = [file for file in listdir(directory)]# if file.endswith('.pcap')]
count = 0
pcap_len = len(pcap_files)

try:
    makedirs('pcapcsv/datasets', exist_ok=True)
except OSError as error:
    print(error)

csv_header = ('Time', 'Identifier', 'Src_IP', 'Src_MAC', 'Dest_IP', 'Dest_MAC', 'Src_Port', 'Dest_Port',
              'Proto', 'Seq_Num', 'Ack_Num', 'TCP_Flag', 'TTL', 'Window_Size', 'TCP_Checksum', "Packet_Length", 'Payload')



#b4 = datetime.now()
for each_dir in pcap_files:
    joined = path.join(directory, each_dir)
    packets = rdpcap(joined)
    #attributes.extend(extract_features(packet) for packet in packets)
    attributes = map(extract_features, packets)
    ds_name = "".join(["pcapcsv/datasets/", each_dir, ".csv"])
    df = pd.DataFrame(attributes, columns=csv_header)
    df.to_csv(ds_name, index=None)
    #attributes.extend(extract_features.remote(packet) for packet in packets)
    print(f'{count} of {pcap_len} successfully processes at {datetime.now()}')
    count += 1
    #break

#after = datetime.now()
#print('Time taken:', after-b4)


