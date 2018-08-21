"""
Traffic analysis engine class defination
"""
import yaml
import sys
import pyshark

class TrafficAnalysisEngine(object):
 	
	def __init__(self, pcap_file, device_name):
		self.filename = 'pcaps/' + pcap_file + ".pcap"
		self.devicename = 'device_fingerprint_database/' + device_name + ".yaml"
		f = open(self.devicename)
		self.rules = yaml.load(f)

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
		for domain_IP in self.rules['domain']:
			if(packet.source == self.rules['device'][0]) and (packet.destination == domain_IP) :#and (packet.info.split(' ')[2] == self.rules['packet'][3]['port']):
				return True
			elif(packet.source == domain_IP) and (packet.destination == self.rules['device'][0]) :#and (packet.info.split(' ')[0] == self.rules['packet'][3]['port']):
				return True
		return False    

	def DNS_analyze(self,packet):  
		for DNS_IP in self.rules['DNS Server']:
			if(packet.source == self.rules['device'][0]) and (packet.destination == DNS_IP) :#and (packet.info.split(' ')[2] == self.rules['packet'][4]['port']):
				return True
			elif(packet.source == DNS_IP) and (packet.destination == self.rules['device'][0]) :#and (packet.info.split(' ')[0] == self.rules['packet'][4]['port']):
				return True
		return False
       
	def ICMP_analyze(self,packet):  
		for domain_IP in self.rules['domain']:
			for DNS_IP in self.rules['DNS Server']:
				for router_IP in self.rules['router']:
					if(packet.source == self.rules['device'][0]) and ((packet.destination == domain_IP) or (packet.destination == DNS_IP) or (packet.destination == router_IP)):
						return True
					elif(packet.destination == self.rules['device'][0]) and ((packet.source == domain_IP) or (packet.source == DNS_IP) or (packet.source == router_IP)):
						return True
		return False

	def TLSv1_analyze(self,packet): 
		for domain_IP in self.rules['domain']:
			if(packet.source == self.rules['device'][0]) and (packet.destination == domain_IP) :
				return True
			elif(packet.source == domain_IP) and (packet.destination == self.rules['device'][0]) :
				return True
		return False


	def traffic_analyze(self,packet):
		prot = packet.protocol

		if prot == "ARP":
			return self.ARP_analyze(packet)

		elif prot == "UDP":
			return self.UDP_analyze(packet)

		elif prot == "TCP": 
			return self.TCP_analyze(packet)

		elif prot == "DNS": 
			return self.DNS_analyze(packet)

		elif prot == "ICMP": 
			return self.ICMP_analyze(packet)

		elif (prot == "TLSv1") or (prot == "TLSv1.1") : 
			return self.TLSv1_analyze(packet)

		else:
			return False	


	def run(self):
        #main process of analysis engine
        # f = open(self.devicename)
        # rules = yaml.load(f) #load rules
		cap = pyshark.FileCapture(self.filename,only_summaries=True)

		for p in cap:
			print(p.no)
			ret = self.traffic_analyze(p)

			if not ret:
				print("[Result] No security issues.")
			else:
				print("[Result] WARINING: Trojan has been discovered.")


