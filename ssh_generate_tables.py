#!/usr/bin/env python
# coding: utf-8

# In[1]:


from multiprocessing import Process,Pool
from collections import defaultdict
from datetime import datetime
from tkinter import _flatten
from pathlib import Path
import geoip2.database
from tqdm import tqdm
from decimal import *
import pandas as pd
import numpy as np
import argparse
import ssdeep
import pickle
import copy
import pytz
import time
import json
import os


# In[2]:

parser = argparse.ArgumentParser(prog='ssh_generate_tables.py', description='This script is for generate packet/session table.')
parser.add_argument("geoip_country", type=str, help='Geoip country db path')
parser.add_argument("geoip_domain", type=str, help='Geoip country db path')
parser.add_argument("geoip_ISP", type=str, help='Geoip country db path')
parser.add_argument("isp", type=str, help='ISP for input file')
parser.add_argument("input_file", type=str, help='Input cowire json log')
parser.add_argument("core", type=int, help='Core number for multi-processing (be aware of device limitations)')
parser.add_argument("output_directory", type=str, help='Directory to save output files packet/session table (00, 06, 12, 18)')

args = parser.parse_args()
start = time.time() # 執行時間
# geoip_country_path = '/home/steven/code/share/steven/SSH/GeoIP2-Country_20200526/GeoIP2-Country.mmdb'
# geoip_domain_path = '/home/steven/code/share/steven/SSH/GeoIP2-Domain_20200526/GeoIP2-Domain.mmdb'
# gepip_ISP_path = '/home/steven/code/share/steven/SSH/GeoIP2-ISP_20200526/GeoIP2-ISP.mmdb'
geoip_country_path = args.geoip_country
geoip_domain_path = args.geoip_domain
gepip_ISP_path = args.geoip_ISP


# In[3]:


# isps = os.listdir('/home/steven/code/share/steven/Honeypot/ISP')
# isps.remove('report')
# isps


# In[4]:


# isp = '台灣碩網'
isp = args.isp
# file_path = f'/home/steven/code/share/Dian/0318/ssh_log/2022-01-01/台灣碩網/cowrie.json.2022-01-01'
file_path = args.input_file
date = os.path.basename(file_path).split('.')[-1]


# In[5]:

# core = 100
core = args.core


# In[6]:


output_form_template = {
            'session_id':None,#不在table內
            'session_protocol':None, #不在table內
            'session_time':None,
            'session_time_list':[],
            'session_duration':None,
            'session_i_tt_packet':0,
            'session_o_tt_packet':0,
            'session_i_tt_frame_length':0,
            'session_o_tt_frame_length':0, 
            'udp_i_tt_length':0,
            'udp_o_tt_length':0,
            'udp_i_avg_length':0,
            'udp_o_avg_length':0,
            'icmp_i_avg_length':0,
            'icmp_o_avg_length':0,
            'icmp_i_tt_datagram_length':0,
            'icmp_o_tt_datagram_length':0,
            'tcp_i_tt_payload_length':0,
            'tcp_o_tt_payload_length':0,
            'tcp_i_avg_payload_length':0,
            'tcp_o_avg_payload_length':0,
            'ip_src':None,
            'ip_dst':None,
            'tcp_srcport':None,
            'tcp_dstport':None,
            'country':None,
            'isp':None,
            'domain':None,
            'frame_i_max_protocols':None,
            'frame_o_max_protocols':None,
            'tcp_i_payload_list':[],
            'tcp_o_payload_list':[]
        }
assist_form_template = {
            'udp_i_packet':0,
            'udp_o_packet':0,
            'icmp_i_packet':0,
            'icmp_o_packet':0,
            'tcp_i_packet':0,
            'tcp_o_packet':0
        }




def run(data):
    output_form = copy.deepcopy(output_form_template)
    assist_form = copy.deepcopy(assist_form_template)
    
    def packet_classification(data_i, event_id, target, case):
    #session inbound and outbound packets
        if case==0:
            if data_i['eventid'] == event_id:
                output_form[target] = 1
        #tcp inbound length            
        elif case==1:
            if data_i['eventid'] == event_id:
                output_form[target] += len(data_i["message"][5:])
#                 assist_form["tcp_i_packet"] += 1
        #tcp outbound length             
        elif case==2:
            if data_i['eventid'] == event_id:
                output_form[target] += len(data_i["message"])
#                 assist_form["tcp_o_packet"] += 1
        #udp, icmp inbound length 
        elif case==3:
            if event_id in data_i['eventid']:
                output_form[target] += len(data_i["message"][5:])
#                 assist_form[target+"_i_packett"] += 1
        #udp, icmp outbound length 
        elif case==4:
            if event_id in data_i['eventid']:
                output_form[target] += len(data_i["message"])
#                 assist_form[target+"_o_packett"] += 1
        #login inbound length            
        elif case==5:
            if data_i['eventid'] == event_id:
                output_form[target] += len(data_i["username"])
                output_form[target] += len(data_i["password"])
#                 assist_form["tcp_i_packet"] += 1
    #empty
    if data == None:
        return output_form
        del output_form
        
    elif data.get("session",None) == None: 
        return output_form
        del output_form
    
    output_form["session_id"] = data["session"]
    output_form["session_time"] = data["timestamp"]
    try:
        output_form["session_protocol"] = data["protocol"]
    except:
        output_form["session_protocol"] = None
    output_form["session_time_list"] = [data["timestamp"]]
    output_form["ip_src"] = data["src_ip"]
    try:
        output_form["ip_dst"] = data["dst_ip"]
    except:
        output_form["ip_dst"] = None
    try:
        output_form["tcp_srcport"] = data["src_port"]
    except:
        output_form["tcp_srcport"] = None
    try:
        output_form["tcp_dstport"] = data["dst_port"]
    except:
        output_form["tcp_dstport"] = None

    output_form["frame_i_max_protocols"] = None
    output_form["frame_o_max_protocols"] = None
    output_form["tcp_i_payload_list"] = []
    output_form["tcp_o_payload_list"] = []

    if data['eventid'] == "cowrie.session.closed":
        output_form["session_duration"] = str(data["duration"])
    
    # Login success or fail
    elif "cowrie.login" in data['eventid']:
        #tcp_i_payload_list
        output_form["tcp_i_payload_list"].append([data["username"], data["timestamp"], len(data["username"])]) 
        output_form["tcp_i_payload_list"].append([data["password"], data["timestamp"], len(data["password"])])
        #tcp_o_payload_list
        output_form["tcp_o_payload_list"].append([data["message"], data["timestamp"], len(data["message"])])                
        #session_o_tt_packet
        packet_classification(data, "cowrie.login.failed", "session_o_tt_packet",  0)
        #session_o_tt_frame_length 
        packet_classification(data, "cowrie.login.failed", "session_o_tt_frame_length",  2)
        #tcp_i_tt_payload_length
        packet_classification(data, "cowrie.login.success", "tcp_i_tt_payload_length",  5)
        #tcp_o_tt_payload_length
        packet_classification(data, "cowrie.login.failed", "tcp_o_tt_payload_length",  2)

    elif data['eventid'] == "cowrie.command.input":
        #tcp_i_payload_list
        output_form["tcp_i_payload_list"].append([data["message"][5:], data["timestamp"], len(data["message"][5:])])
        #session_i_tt_packet
        packet_classification(data, "cowrie.command.input", "session_i_tt_packet",  0)
        #session_i_tt_frame_length 
        packet_classification(data, "cowrie.command.input", "session_i_tt_frame_length",  1)
        #tcp_i_tt_payload_length
        packet_classification(data, "cowrie.command.input", "tcp_i_tt_payload_length",  1)

    elif data['eventid'] == "cowrie.command.failed":
        #tcp_o_payload_list
        output_form["tcp_o_payload_list"].append([data["message"], data["timestamp"], len(data["message"])])
        #tcp_o_tt_payload_length
        packet_classification(data, "cowrie.command.failed", "tcp_o_tt_payload_length",  2)

    elif data['eventid'] == "udp":
        #udp_i_tt_length 
        packet_classification(data, "udp", "udp_i_tt_length",  3,output_form, assist_form)
        #udp_o_tt_length 
        packet_classification(data, "udp", "udp_o_tt_length",  4,output_form, assist_form)
    elif data['eventid'] == "icmp":
        #icmp_i_tt_length 
        packet_classification(data, "icmp", "icmp_i_tt_datagram_length", 3)
        #icmp_o_tt_length 
        packet_classification(data, "icmp", "icmp_o_tt_datagram_length", 4)


    return output_form


# In[7]:


def jsonlize(i):
    try:
        tmp = json.loads(i)
    except:
        tmp = None
    return tmp

def get_ip_info(ip, client_country, client_isp, client_domain):
    ip_info = {'country':None, 'isp':None, 'domain':None}
    try:
        response_country = client_country.country(str(ip))
        ip_info['country'] = response_country.country.name
    except:
        pass
    try:
        response_isp = client_isp.isp(str(ip))
        ip_info['isp'] = response_isp.isp
    except:
        pass
    try:
        response_domain = client_domain.domain(str(ip))
        ip_info['domain'] = response_domain.domain
    except:
        pass
    return ip_info

        
def frame_with_constant(result_dic1):
    for key,value in result_dic.items():
        if result_dic1[key]["tcp_i_tt_payload_length"] != 0:
            result_dic1[key]["session_i_tt_frame_length"] = result_dic1[key]["tcp_i_tt_payload_length"] * 2.56
        if result_dic1[key]["tcp_o_tt_payload_length"] != 0:
            result_dic1[key]["session_o_tt_frame_length"] = result_dic1[key]["tcp_o_tt_payload_length"] * 2.56


# In[8]:


with open(file_path) as f:
    file_content = f.read().split('\n')[:-1]


# In[9]:


p = Pool(core)
print("Jsonlize ...")
data = p.map(jsonlize, file_content)


# In[10]:


try:
    print("Finding command event ...")
    result = p.map(run, data)
except:
    print("Error!")


# In[11]:


result_dic = defaultdict(list)


# In[12]:


print("Covert to dict ...")
for r in tqdm(result):
    result_dic[r['session_id']].append(r)
# del result


# In[13]:

print("Duplicate tmp dict ...")
result_dic1 = {}
for k in result_dic.keys():
    result_dic1[k] = copy.deepcopy(output_form_template)


# In[14]:


print("Generate needed columns ...")
client_country = geoip2.database.Reader(geoip_country_path)
client_isp = geoip2.database.Reader(gepip_ISP_path)
client_domain = geoip2.database.Reader(geoip_domain_path)

for key,value in tqdm(result_dic.items()):
    avg_template = assist_form_template.copy()
    for v in value:
        if result_dic1[key]['session_id'] == None:
            result_dic1[key]['session_id'] = v.get('session_id',None)
            
        if result_dic1[key]['session_protocol'] == None:
            result_dic1[key]['session_protocol'] = v.get('session_protocol',None)
        
        if result_dic1[key]['session_time'] == None:
            result_dic1[key]['session_time'] = v.get('session_time',None)
        
        result_dic1[key]['session_time_list'].append(v.get('session_time',None))
        
        if result_dic1[key]['session_duration'] == None:
            result_dic1[key]['session_duration'] = v.get('session_duration',None)
            
        result_dic1[key]['session_i_tt_packet'] += v.get('session_i_tt_packet',0)
        result_dic1[key]['session_o_tt_packet'] += v.get('session_o_tt_packet',0)
        result_dic1[key]['session_i_tt_frame_length'] += v.get('session_i_tt_frame_length',0)
        result_dic1[key]['session_o_tt_frame_length'] += v.get('session_o_tt_frame_length',0)
        result_dic1[key]['udp_i_tt_length'] += v.get('udp_i_tt_length',0)
        result_dic1[key]['udp_o_tt_length'] += v.get('udp_o_tt_length',0)
        result_dic1[key]['icmp_i_tt_datagram_length'] += v.get('icmp_i_tt_datagram_length',0)
        result_dic1[key]['icmp_o_tt_datagram_length'] += v.get('icmp_o_tt_datagram_length',0)
        result_dic1[key]['tcp_i_tt_payload_length'] += v.get('tcp_i_tt_payload_length',0)
        result_dic1[key]['tcp_o_tt_payload_length'] += v.get('tcp_o_tt_payload_length',0)

        for item in v['tcp_i_payload_list']:
            result_dic1[key]['tcp_i_payload_list'].append(item)
        for item in v['tcp_o_payload_list']:
            result_dic1[key]['tcp_o_payload_list'].append(item)

        #udp_i_avg_length
        if result_dic1[key]['udp_i_tt_length'] > 0:
            avg_template['udp_i_packet'] += 1
        #udp_o_avg_length
        elif result_dic1[key]['udp_o_tt_length'] > 0:
            avg_template['udp_o_packet'] += 1
        #icmp_i_avg_length
        elif result_dic1[key]['icmp_i_tt_datagram_length'] > 0:
            avg_template["icmp_i_packet"] += 1
        #icmp_o_avg_length
        elif result_dic1[key]['icmp_o_tt_datagram_length'] > 0:
            avg_template["icmp_o_packet"] += 1
        #tcp_i_avg_payload_length
        elif result_dic1[key]['tcp_i_tt_payload_length'] > 0:
            avg_template["tcp_i_packet"] += 1
        #tcp_o_avg_payload_length
        elif result_dic1[key]['tcp_o_tt_payload_length'] > 0:
            avg_template["tcp_o_packet"] += 1
        
        if result_dic1[key]['ip_src'] == None:
            result_dic1[key]['ip_src'] = v.get('ip_src',None)
        if result_dic1[key]['ip_dst'] == None:
            result_dic1[key]['ip_dst'] = v.get('ip_dst',None)
        if result_dic1[key]['tcp_srcport'] == None:
            result_dic1[key]['tcp_srcport'] = v.get('tcp_srcport',None)
        if result_dic1[key]['tcp_dstport'] == None:
            result_dic1[key]['tcp_dstport'] = v.get('tcp_dstport',None)
        if result_dic1[key]['country'] == None:
            ip_info = get_ip_info(v.get('ip_src',None), client_country, client_isp, client_domain)
            result_dic1[key]['country'] = ip_info.get('country')
            result_dic1[key]['isp'] = ip_info.get('isp')
            result_dic1[key]['domain'] = ip_info.get('domain')
        
    if avg_template['udp_i_packet'] != 0:
        result_dic1[key]["udp_i_avg_length"] = result_dic1[key]['udp_i_tt_datagram_length']/avg_template['udp_i_avg_length']
    elif avg_template['udp_o_packet'] != 0:
        result_dic1[key]["udp_o_avg_length"] = result_dic1[key]['udp_i_tt_datagram_length']/avg_template['udp_o_avg_length']
        
    elif avg_template['icmp_i_packet'] != 0:
        result_dic1[key]["icmp_i_avg_length"] = result_dic1[key]['icmp_i_tt_length']/avg_template['icmp_i_packet']
    elif avg_template['icmp_o_packet'] != 0:
        result_dic1[key]["icmp_i_avg_length"] = result_dic1[key]['icmp_o_tt_length']/avg_template['icmp_o_packet']
    
    elif avg_template['tcp_i_packet'] != 0:
        result_dic1[key]["tcp_i_avg_payload_length"] = result_dic1[key]['tcp_i_tt_payload_length']/avg_template['tcp_i_packet']
    elif avg_template['tcp_o_packet'] != 0:
        result_dic1[key]["tcp_o_avg_payload_length"] = result_dic1[key]['tcp_o_tt_payload_length']/avg_template['tcp_o_packet']
frame_with_constant(result_dic1)


# In[15]:


print("Join all sessions to df ...")
joined = []
for value in tqdm(result_dic1.values()):
    joined.append(value.values())
joined
df = pd.DataFrame(joined, columns = ['session_id', 'session_protocol', 'session_time', 'session_time_list', 
                                                 'session_duration', 'session_i_tt_packet', 'session_o_tt_packet', 'session_i_tt_frame_length', 
                                                 'session_o_tt_frame_length', 'udp_i_tt_length', 'udp_o_tt_length', 'udp_i_avg_length', 'udp_o_avg_length', 
                                                 'icmp_i_avg_length', 'icmp_o_avg_length', 'icmp_i_tt_datagram_length', 'icmp_o_tt_datagram_length', 'tcp_i_tt_payload_length', 
                                                 'tcp_o_tt_payload_length', 'tcp_i_avg_payload_length', 'tcp_o_avg_payload_length', 'ip_src', 'ip_dst', 'tcp_srcport', 'tcp_dstport', 
                                                 'country', 'isp', 'domain', 'frame_i_max_protocols', 'frame_o_max_protocols', 'tcp_i_payload_list', 'tcp_o_payload_list'])


# In[16]:


def str2timestamp(s):
    try:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
    except:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return pytz.utc.localize(dt).timestamp()

def session_time_list2timestamp(s):
    s = [str2timestamp(i) for i in s]
    return s

def convert_i_payload(s):
    if  len(s) == 0:
        return []
    else:
        for i in range(len(s)):
            ssdeep_i_table[ssdeep.hash(s[i][0])] = s[i][0] 
            s[i][0] = ssdeep.hash(s[i][0])
            if type(s[i][1]) != type(0.0):
                s[i][1] = str2timestamp(s[i][1])
        return s
    
def convert_o_payload(s):
    if  len(s) == 0:
        return []
    else:
        for i in range(len(s)):
            ssdeep_o_table[ssdeep.hash(s[i][0])] = s[i][0] 
            s[i][0] = ssdeep.hash(s[i][0])
            if type(s[i][1]) != type(0.0):
                s[i][1] = str2timestamp(s[i][1])
        return s


# In[17]:


# ssdeep_i_table = {}
# ssdeep_o_table = {}
# df['tcp_i_payload_list'] = df['tcp_i_payload_list'].apply(convert_i_payload)
# df['tcp_o_payload_list'] = df['tcp_o_payload_list'].apply(convert_i_payload)


# In[18]:


# with open(pickle_name,'wb') as f:
#     pickle.dump(df, output_name)


# In[19]:


df


# # Making tables

# In[20]:


month, day = date.split('-')[1:]


# In[21]:


def timecheck(x):
    if '.' not in x:
        x = x[:-1] + '.00' + x[-1]
    return x


# In[22]:


def IDname(session):
    ID = session[0] 
    Protocol = session[1] 
    time = session[2]
    # for i in tqdm(range(len(ID))):
    ID = f'2022{month}{day}_{isp}_'+ str(Protocol) + '_' + str(time)
        # session['Packet_ID_i'][i] = session['Session_ID'][i]
    return ID

def Sessionpaylaod(session):
    tmp = []
    for i in range(len(session)):
        tmp.append(session[i][0])
    session = tmp
    return session
                   
def Sessionpktime(session):
    tmp=[]
    for i in range(len(session)):
        session[i][1] = timecheck(session[i][1])
        session[i][1] =  pytz.utc.localize(datetime.strptime(str(session[i][1]),"%Y-%m-%dT%H:%M:%S.%fZ")).timestamp()
        tmp.append(session[i][1])
    session = tmp
    return session 
                   
def Packet2Str(packet):
    # for i in tqdm(range(len(ID))):
    a = float(packet[0])
    for i in range(len(packet)):        
        if( i  != 0 and packet[i] == a):
            # print("Hello")
            packet[i] = Decimal(packet[i])+ Decimal(0.000001)
            
        packet[i] = str(packet[i])
        # print(packet[i])
        # print('\n')
    return packet
                   

def PacketprocessID(packet):
    packet_time = packet[0]
    Protocol = packet[1]
    for i in range(len(packet_time)):
        packet_time[i] = f'2021{month}{day}_中華電信_'+ str(Protocol) + '_' + packet_time[i]
    return packet_time
                   
def PacketID(packetlist):
    sessionid = packetlist[0]
    packetid = packetlist[1]
    ipsrc = packetlist[2]
    protocol = packetlist[3]
    time = packetlist[4]
    ipsrc = packetlist[5]
    ipdst = packetlist[6]
    tcpsrc = packetlist[7]
    tcpdst = packetlist[8]
    payload = packetlist[9]
    pkdf_list = packetlist[10]
    tmp = []
    for i in range(len(time)):
        tmp.append(str(sessionid))
        tmp.append(str(packetid[i]))
        tmp.append(str(ipsrc))
        tmp.append(str(protocol))
        tmp.append(time[i])
        tmp.append(str(ipsrc))
        tmp.append(str(ipdst))
        tmp.append(str(tcpsrc))
        tmp.append(str(tcpdst))
        tmp.append(str(payload[i]))
    pkdf_list= tmp
    return pkdf_list


# In[23]:


df = df[df["tcp_i_payload_list"].apply(lambda x: len(x) != 0)]
df["session_time"] = df["session_time"].apply(timecheck)
df = df.reset_index(drop=True)


# In[24]:


session_df = pd.DataFrame(columns=['Session_ID','Src_ISP','Protocol','session_time','Packet_ID_i','ip_src','ip_dst','tcp_srcport','tcp_dstport','tcp_i_payload_list'])


# In[25]:


session_df['tcp_i_payload_list'] = df['tcp_i_payload_list']
session_df['tcp_dstport'] = df['tcp_dstport']
session_df['tcp_srcport'] = df['tcp_srcport']
session_df['ip_dst'] = df['ip_dst']
session_df['ip_src'] = df['ip_src']
session_df['session_time'] = df['session_time']
session_df['Protocol'] = df['session_protocol']
session_df['Src_ISP'] = '中華電信'


# In[26]:


session_df


# In[27]:


print("Generate session and packet table ...")
session_df["session_time"] = session_df["session_time"].apply(lambda x: pytz.utc.localize(datetime.strptime(str(x),"%Y-%m-%dT%H:%M:%S.%fZ")).timestamp())
# session_df["session_time"] = session_df["session_time"].apply(lambda x: pytz.utc.localize(datetime.strptime(str(x),"%Y-%m-%dT%H:%M:%SZ")).timestamp())


# In[28]:


session_id = list(session_df.Session_ID)
session_Protocol = list(session_df.Protocol)
session_time = list(session_df.session_time)
session = list(zip(session_id, session_Protocol, session_time))


# In[29]:


p = Pool(core)


# In[30]:


print("Making session id ...")
session_idd = p.map(IDname, session)

session_df.Session_ID = session_idd
session_df.Packet_ID_i = session_df.Session_ID

Session_rawpayload = list(session_df.tcp_i_payload_list)

sessionpayload = p.map(Sessionpaylaod,Session_rawpayload)

sessionpktime = p.map(Sessionpktime,Session_rawpayload)

sessionpktime_1 = sessionpktime

sessionpktime_1 = p.map(Packet2Str,sessionpktime_1)


# In[31]:


print("Making packet id ...")
packet_ID = list(zip(sessionpktime_1,session_Protocol))

packet_process_ID = p.map(PacketprocessID,packet_ID)

session_df.Packet_ID_i = packet_process_ID
session_df.tcp_i_payload_list = sessionpayload


# In[32]:


packet_df = pd.DataFrame(columns=['Session_ID','Packet_ID','Src_ISP','Protocol','packet_time','ip_src','ip_dst','tcp_srcport','tcp_dstport','tcp_i_payload_list'])


# In[33]:


session_id = list(session_df.Session_ID)
session_Protocol = list(session_df.Protocol)
ipsrc = list(session_df.Src_ISP)
ipdst = list(session_df.ip_dst)
tcpsrcport = list(session_df.tcp_srcport)
tcpdstport = list(session_df.tcp_dstport)
pkdf_list = list(session_df.session_time)
packet_list = list(zip(session_id,packet_process_ID,ipsrc,session_Protocol,sessionpktime_1,ipsrc,ipdst,tcpsrcport,tcpdstport,sessionpayload,pkdf_list))


# In[34]:


pkdf_list = p.map(PacketID,packet_list)
pkdf_list = list(_flatten(pkdf_list))


# In[35]:


long = len(pkdf_list)

pkdf_processlist=[]
tmp =[]
count = 1 
for i in tqdm(range(long)):
    tmp.append(pkdf_list[i])
    if(count%10 == 0):
        pkdf_processlist.append(tmp)
        tmp =[]
        # print("No.")
        # print(count)
        # print("\n")
    count = count + 1


# In[36]:


packet_df  = pd.DataFrame(pkdf_processlist, columns=['Session_ID','Packet_ID','Src_ISP','Protocol','packet_time','ip_src','ip_dst','tcp_srcport','tcp_dstport','tcp_i_payload_list'])


# In[37]:


session_df = session_df[session_df['Protocol'] == 'ssh']
packet_df = packet_df[packet_df['Protocol'] == 'ssh']


# In[38]:


session_df_4 = np.array_split(session_df, 4)
packet_df_4 = np.array_split(packet_df, 4)


# In[42]:


print("Saving file ...")
time_list = ['00', '06', '12', '18']
output_directory = args.output_directory
if not os.path.exists(output_directory):
    os.makedirs(output_directory)
for i in range(4):
    session_df_4[i].to_pickle(f'{output_directory}/session_table_{"".join(date.split("-"))}_{time_list[i]}_{isp}_ssh_pcap.pickle')
    packet_df_4[i].to_pickle(f'{output_directory}/packet_table_{"".join(date.split("-"))}_{time_list[i]}_{isp}_ssh_pcap.pickle')
print("Finish!")
end = time.time() # 執行時間
print("Execution time:", end - start)


# In[ ]:




