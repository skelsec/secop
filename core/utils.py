import ipaddress
import subprocess
import enum
from itertools import groupby
import json
import datetime

def flatten(i, separator):
	return str(i).replace('\r','\\r').replace('\n','\\n').replace(separator,' ')

def h2bin(x):
	data = x.replace(' ', '').replace('\n', '').replace('\t', '').replace('\r', '')
	return bytearray.fromhex(data)

def hexdump(s):
	for b in range(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % c for c in lin)
		pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
		return '  %04x: %-48s %s' % (b, hxdat, pdat)

def execute(cmd, yield_output = True, supress_exitcode = True):
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, shell=False)
	for stdout_line in iter(popen.stdout.readline, ""):
		if yield_output:
			yield stdout_line.replace('\r','').replace('\n','').strip() 
	popen.stdout.close()
	return_code = popen.wait()
	if not supress_exitcode:
		if return_code:
			raise subprocess.CalledProcessError(return_code, cmd)

class TestResult(enum.Enum):
	NOTSTARTED    = 0
	STARTED       = 1
	ERROR         = 2
	NOTVULNERABLE = 3
	VULNERABLE    = 4

class Protocol(enum.Enum):
	TCP = 0
	UDP = 1

class PortStatus(enum.Enum):
	NOT_CHECKED = 0
	CLOSED = 1
	OPEN = 2
	FILTERED = 3
	
	
class IPStatus(enum.Enum):
	DOWN = 0
	UP = 1
	NOT_CHECKED = 2
	
class ScannerType(enum.Enum):
	NMAP = 0
	MASSCAN = 1
	FILE = 3
	
class DummyTarget():
	def __init__(self, ip, port, rdns = None):
		self.ip = ip
		self.port = port
		self.rdns  = rdns
		
	def getaddr(self):
		return (self.ip, int(self.port))
		
	def toJSON(self):
		return json.dumps(self.toDict())
			
	def toDict(self):
		t = {}
		t['ip']   = self.ip
		t['port'] = self.port
		t['rdns'] = self.rdns
		return t

### Small parsers for easing user input
class Ports():
	def __init__(self, portdef = None, port_type = Protocol.TCP):
		self.portdef = portdef #string what the user created
		self.ports = [] #list of int
		self.port_type = port_type
		
		if portdef is not None:
			self.parse()
		
	def parse(self):
		tf = []
		if self.portdef.find(',') != -1:
			for tp in self.portdef.split(','):
				tf.append(tp.strip())
		else:
			tf.append(self.portdef)
			
		for tp in tf:
			if tp.find('-') != -1:
				start, end = tp.split('-')
				start = int(start)
				end   = int(end)
				Ports.sanitycheck_2(start, end)
				self.ports += list(range(start, end))
			else:
				tp = int(tp)
				Ports.sanitycheck_1(tp)
				self.ports.append(tp)
				
		self.repartition()
				
	def sanitycheck_1(port):
		if port < 0 or port > 65535:
			raise Exception('aaaa')
		
	def sanitycheck_2(start, end):
		Ports.sanitycheck_1(start)
		Ports.sanitycheck_1(end)
		if start > end :
			raise Exception('aaaa')
			
	def repartition(self):
		self.portdef = ''
		self.ports = list(set(self.ports))
		self.ports.sort()
		for start, end in Ports.ranges(self.ports):
			if start == (end -1):
				self.portdef += '%d' % (start)
			else:
				self.portdef += '%d-%d' % (start, end - 1)
			self.portdef += ' '
		
	#https://stackoverflow.com/questions/2154249/identify-groups-of-continuous-numbers-in-a-list
	def ranges(lst):
		pos = (j - i for i, j in enumerate(lst))
		t = 0
		for i, els in groupby(pos):
			l = len(list(els))
			el = lst[t]
			t += l
			yield (el, el+l)
			
	def toJSON(self):
		return json.dumps(self.toDict())
		
	def toDict(self, verbose = False):
		temp = {}
		temp['portdef']            = self.portdef
		temp['port_type']          = self.port_type
		if verbose:
			temp['ports']        = self.ports
		
		return temp
	
class Targets():
	def __init__(self, targetdef = None):
		self.targetdef = targetdef
		self.targets = [] #should be list of ipaddr or ipnetwork
		
		if targetdef is not None:
			self.parse()
		
	def parse(self):
		tf = []
		if self.targetdef.find(',') != -1:
			for tp in self.targetdef.split(','):
				tf.append(tp.strip())
				
		else:
			tf.append(self.targetdef)
			
		for tp in tf:
			if tp.find('/') != -1:
				try:
					ipaddress.ip_network(tp)
				except Exception as e:
					raise e
				self.targets.append(ipaddress.ip_network(tp))
				
			else:
				try:
					ipaddress.ip_address(tp)
				except Exception as e:
					raise e
				self.targets.append(ipaddress.ip_address(tp))
		
		self.targetdef = ','.join([str(x) for x in self.targets])
		
	def toJSON(self):
		return json.dumps(self.toDict())
		
	def toDict(self, verbose = False):
		temp = {}
		temp['targetdef']            = self.targetdef
		if verbose:
			temp['targets']        = self.targets
		
		return temp
		

class UniversalEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, (enum.Enum,ipaddress.IPv4Network,ipaddress.IPv6Network,ipaddress.IPv4Address,ipaddress.IPv6Address)):
			return str(obj)
		elif isinstance(obj, (Targets,Ports,DummyTarget)):
			return obj.toJSON()
		else:
			return json.JSONEncoder.default(self, obj)
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		