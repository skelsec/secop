import json
from datetime import datetime
import socket

from ....utils import TestResult, UniversalEncoder
from ..smbutils import DomainGrab, SmbFinger

class SMB001PluginDef():
	def __init__(self):
		self.classname        = 'SMB001'
		self.version          = '0.1'
		self.triggerPorts     = '445'
		self.shortname        = 'SMBInfo'
		self.name             = 'SMB null session info gathering'
		self.CVE_score        = 0
		self.shortdescription = ''
		self.longdescription  = ''
		self.resolution       = ''

class SMB001():
	def __init__(self, target = None, timeout = 1):
		self.plugindef       = SMB001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None
		#socket parameters
		self.soc_timeout     = timeout
		#test parameters
		self.SMBDomain       = None
		self.SMBHostname     = None
		self.SMBSigning      = None
		self.SMBOsVersion    = None
		self.SMBLanManClient = None
		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
				soc.settimeout(self.soc_timeout)
				soc.connect(self.target.getaddr())
				self.SMBHostname, self.SMBDomain = DomainGrab(soc)
				
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
				soc.settimeout(self.soc_timeout)
				soc.connect(self.target.getaddr())
				self.SMBSigning, self.SMBOsVersion, self.SMBLanManClient = SmbFinger(soc)
			
			self.testresult = TestResult.VULNERABLE
				
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
		t['SMBDomain']       = self.SMBDomain
		t['SMBHostname']     = self.SMBHostname
		t['SMBSigning']      = self.SMBSigning
		t['SMBOsVersion']    = self.SMBOsVersion
		t['SMBLanManClient'] = self.SMBLanManClient
		return t
		
		
if __name__ == '__main__':
	from ....utils import DummyTarget
	import argparse
	
	parser = argparse.ArgumentParser("This module is grabbing public info from SMB port")
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = SMB001(t, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())