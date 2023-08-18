from os.path import join
from pandas import concat, read_csv, DataFrame
from os import makedirs, path, listdir
from math import floor
from numpy import std
from datetime import datetime
from collections import Counter
from scapy.all import IP, TCP, UDP, Ether, sniff


def compute_character_std_var(payload):
    if payload == '':
        payload_std= 0
    else:
        char_frequency = Counter(payload)
        list_freq = list(char_frequency.values())
        payload_std = std(list_freq)
    return payload_std

#all_pcaps = []
def extract_features(packet):
    all_pcaps = []

    payload_std = used_time = dest_port = protocol = ttl = window = seq_num = ack_num = tcp_flag = tcp_checksum = time = packet_len=''

    time_utc = packet.time
    time = datetime.utcfromtimestamp(floor(time_utc))
    #9/1/2016  12:45:51 PM
    #start_time1=datetime(year=2016, month=9, day=1, hour=12, minute=40, second=0)
    #end_time1=datetime(year=2016, month=9, day=1, hour=12, minute=44, second=0)
    #start_time2=datetime(year=2016, month=9, day=1, hour=12, minute=45, second=0)
    #end_time2=datetime(year=2016, month=9, day=1, hour=12, minute=45, second=54)
    #print(time)
    start_time1=datetime(year=2018, month=2, day=23, hour=8, minute=0)
    end_time1=datetime(year=2018, month=2, day=23, hour=14, minute=15)
    start_time2=datetime(year=2018, month=2, day=23, hour=15, minute=0)
    end_time2=datetime(year=2018, month=2, day=23, hour=15, minute=20)
#start_time1 <= time <= end_time1 | start_time2 <= time <= end_time2): # 
    if (time >= start_time1 and time <= end_time1) or (time >= start_time2 and time <= end_time2):
        #print('Match')
        used_time = time
        if IP in packet:
            packet_len = packet[IP].len
            protocol = packet[IP].proto
            ttl = packet[IP].ttl
        else:
            packet_len = protocol = ttl = ''

        if Ether in packet:
            if packet[Ether].payload is not None:
                    payload = str(packet[Ether].payload)
                    payload_std = compute_character_std_var(payload)
            else:
                payload_std = 0
        else:
            payload_std = ''

        if TCP in packet:
            dest_port = packet[TCP].dport
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            tcp_flag = packet[TCP].flags
            tcp_checksum = packet[TCP].chksum
            window = packet[TCP].window

        elif UDP in packet:
            dest_port = packet[UDP].dport
            payload = str(packet[UDP].payload)
            payload_std = compute_character_std_var(payload)
        else:
            dest_port = seq_num = ack_num = tcp_flag = tcp_checksum = window = ''

        return [used_time, dest_port, protocol, seq_num, ack_num, tcp_flag, ttl, window, tcp_checksum, packet_len, payload_std]
    else:
        return None

    



#if file.endswith('.pcap')]
attributes = []
pcap_directory = 'D:/pcap/Fri_23/pcap'
new_pcap_dir = 'pcapcsv/datasets_Fri_23/'
pcap_files = [file for file in listdir(pcap_directory)]# if file.endswith('.pcap')]
count = 0
pcap_len = len(pcap_files)

try:
    makedirs(new_pcap_dir, exist_ok=True)
except OSError as error:
    print(error)


csv_header = ('Time', 'Dest_Port', 'Proto', 'Seq_Num', 'Ack_Num', 'TCP_Flag', 'TTL', 'Window_Size', 'TCP_Checksum', "Packet_Length", 'Payload')

#b4 = datetime.now()
for each_dir in pcap_files:
    #all_pcaps.clear()
    joined = path.join(pcap_directory, each_dir)
    #attributes.extend(extract_features(packet) for packet in packets)
    ds_name = "".join(["pcapcsv/datasets_Fri_23/", each_dir, ".csv"])
    count += 1
    if path.exists(ds_name):
        print(ds_name + ' already exist, moving to next one')
        continue
    
    #for pkt_data in sniff(offline=joined):
     #   print(extract_features(pkt_data))

    #packets = rdpcap(joined)
    #packets = sniff(offline=joined)
    #attribute = map(extract_features, packets)
    #attributes.extend(attribute)
    #attributes.extend(extract_features(packet) for packet in packets)
    #attributes.extend(extract_features(pkt_data) for pkt_data in sniff(offline=joined))
   # for pkt_data in sniff(offline=joined):
    #    features = extract_features(pkt_data)
        #print(f"Feature returned: {(features)}")
     #   if features==None:
      #      continue         
       # else:
        #    attributes.append(features)
    
    #attributes_to_add = [extract_features(pkt_data) for pkt_data in sniff(offline=joined)]
    #attributes.extend([attr for attr in attributes_to_add if attr is not None])
   
    attributes_to_add = list(filter(lambda x: x is not None, map(extract_features, sniff(offline=joined))))
    attributes.extend(attributes_to_add)

    df = DataFrame(attributes, columns=csv_header)
    df.to_csv(ds_name, index=None) 

    print(f'{count} of {pcap_len} successfully processes at {datetime.now()}')

    attributes.clear()

    # Convert PacketList to list of dictionaries
    #pkt_list = [pkt.__dict__['time', 'dest_port'] for pkt in packets]
    
print(f'All data successfully processes at {datetime.now()}')
