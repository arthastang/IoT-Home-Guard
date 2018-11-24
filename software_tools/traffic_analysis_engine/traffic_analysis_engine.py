#!/usr/bin/python3

"""
Traffic analysis engine class defination
"""
import yaml
import sys
import pyshark
import re
import sqlite3
import time
import hashlib


class TrafficAnalysisEngine(object):
 	
	def __init__(self, pcap_file, device_name):
		self.filename = 'pcaps/' + pcap_file + ".pcap"
		self.devicename = 'device_fingerprint_database/' + device_name + ".yaml"
		self.device_name = device_name
		f = open(self.devicename)
		self.rules = yaml.load(f)
		self.device_ip = '172.27.35.73'
		self.DNS_server_ip = ['4.2.2.2','8.8.8.8']
		self.domain_ip = []
		self.domain_ip.append(self.rules['domain'])
		#print('domain ip: ',self.domain_ip)
		self.new_ip = {}

		cap = pyshark.FileCapture(self.filename,only_summaries=True)
		for p in cap:
			if p.protocol == "DNS":
				if "response" in p.info:
					result = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", p.info)
					if result:
						for r in result:
							if r not in self.domain_ip:
								self.domain_ip.append(r)

			# if p.protocol == "ARP":
			# 	if str(self.rules['packet'][0]['MAC']) in p.info:  #xiaoaitongxue MAC address
			# 		self.device_ip = p.info.split(" ")[0]


	def ARP_analyze(self,packet):   
		if (packet.source == self.rules['packet'][0]['MAC']) or (packet.destination == self.rules['packet'][0]['MAC']):
			return True
		else:
			return False

	def UDP_analyze(self,packet):
		if (packet.source == self.rules['device'][0]) and (packet.destination == self.rules['packet'][1]['dst_IP']): #and (packet.info.split(' ')[0] == self.rules['packet'][1]['src_port']) and (packet.info.split(' ')[2] == self.rules['packet'][1]['dst_port']):
			return True
		elif (packet.source == self.rules['packet'][2]['IP']): #and packet.info.split(' ')[0] == self.rules['packet'][2]['port']):#or (packet.destination == self.rules['packet'][2]['IP'] and packet.info.split(' ')[2] == self.rules['packet'][2]['port']):
			return True
		else:
			return False

	def TCP_analyze(self,packet):
		if(packet.destination == '172.27.35.7'):
			return True
		else:
			return False
		#for domain_IP in self.domain_ip:
		#	if(packet.source == self.device_ip) and (packet.destination == domain_IP) :
		#		return True
		#	if(packet.source == domain_IP) and (packet.destination == self.device_ip) :
		#		return True

		#if (packet.source == self.device_ip) and (packet.destination not in self.new_ip.keys()):
		#	self.new_ip[packet.destination] = 1
		#elif (packet.source == self.device_ip) and (packet.destination in self.new_ip.keys()):
		#	self.new_ip[packet.destination] = self.new_ip[packet.destination] + 1
		#elif (packet.destination == self.device_ip) and (packet.source not in self.new_ip.keys()):
		#	self.new_ip[packet.source] = 1
		#elif (packet.destination == self.device_ip) and (packet.source in self.new_ip.keys()):
		#	self.new_ip[packet.source] = self.new_ip[packet.source] + 1
		
		#return False

	def TLSv1_analyze(self,packet): 
		for domain_IP in self.domain_ip:
			if(packet.source == self.device_ip) and (packet.destination == domain_IP) :
				return True
			elif(packet.source == domain_IP) and (packet.destination == self.device_ip) :
				return True
		return False

	def HTTP_analyze(self,packet):
		for domain_IP in self.domain_ip:
			if(packet.source == self.device_ip) and (packet.destination == domain_IP) :
				return True
			elif(packet.source == domain_IP) and (packet.destination == self.device_ip) :
				return True
		return False


	def traffic_analyze(self,packet):
		prot = packet.protocol

		# if prot == "ARP":
		# 	return self.ARP_analyze(packet)

		# if prot == "UDP":
		# 	return self.UDP_analyze(packet)

		if prot == "TCP": 
			return self.TCP_analyze(packet)

		# elif prot == "DNS": 
		# 	return self.DNS_analyze(packet)

		# elif prot == "ICMP": 
		# 	return self.ICMP_analyze(packet)

		elif (prot == "TLSv1") or (prot == "TLSv1.1") or (prot == "TLSv1.2"): 
			return self.TLSv1_analyze(packet)

		elif prot == "HTTP": 
			return self.HTTP_analyze(packet)
		
		else:
			return True	


	def run(self):

		cap = pyshark.FileCapture(self.filename,only_summaries=True)
		i = j = 0
		resultdump=[]
		for p in cap:
			ret = self.traffic_analyze(p)
			i = i+1
			if not ret:
			# 	print("[Result] No security issues.")
			#else:
				j = j+1
				#print("[Result] WARINING: Trojan has been discovered.")
				#print(p.no, p.protocol, p.source, p.destination,'\n')
				ttime = time.asctime(time.localtime(time.time()))
				hash=hashlib.md5()
				hash1=p.protocol+p.destination
				hash.update(hash1.encode('utf-8'))
				conn=sqlite3.connect("homeguard.db")
				#print("Opened database successfully!")
				resultdict=dict()
				resultdict['dev']=self.device_name
				resultdict['time']=ttime
				resultdict['num']=p.no
				p.destination = '172.27.35.73'
				resultdict['des']=p.destination
				resultdict['protocol']=p.protocol
				resultdict['hash']=hash.hexdigest()
				resultdump.append(resultdict)

				sql="insert into Result(dev,time,num,des,protocol,hash)values('%s','%s','%s','%s','%s','%s')"%(self.device_name,ttime,p.no,p.destination,p.protocol,hash.hexdigest())
				conn.execute(sql)
				conn.commit()
				conn.close()
				#print("Close database successfully!")
				

		#print(j,"/",i,'\n')
		#print(self.domain_ip,'\n')
		#print(self.new_ip)
		#print(self.device_ip)
		print(resultdump)


