import json
from datetime import datetime
import ftplib
import socket

from ....utils import TestResult, UniversalEncoder

class FTP001PluginDef():
	def __init__(self):
		self.classname        = 'FTP001'
		self.version          = '0.1'
		self.triggerPorts     = '21'
		self.shortname        = 'FTP anon'
		self.name             = 'FTP anonymous access'
		self.CVE_score        = 0
		self.shortdescription = ''
		self.longdescription  = ''
		self.resolution       = ''

class FTP001():
	def __init__(self, target = None, timeout = 1):
		self.plugindef       = FTP001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None
		#socket parameters
		self.soc_timeout     = timeout
		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		ip, port = self.target.getaddr()
		try:
			ftp = ftplib.FTP()
			ftp.connect(ip, port, timeout= self.soc_timeout)
			ftp.login()               # user anonymous, passwd anonymous@
			self.testresult = TestResult.VULNERABLE
			
		except ftplib.error_perm as e:
			self.testresult = TestResult.NOTVULNERABLE
				
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
	
	parser = argparse.ArgumentParser("This module is testing for FTP anonymous access")
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = FTP001(t, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())