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
	"""Tests for Anonymous FTP access
	
	Args:
        target (target, optional): The target specification object. Type: either 'target' or 'DummyTarget'. Defaults to None.
        args   (:obj:`dict`, optional): The second parameter. Defaults to None.
			Uses the following arguemt parameters:
				self.args['socket']['timeout']   To specify the timeout
	"""
	
	def __init__(self, target = None, args = None):
		self.args            = args
		self.plugindef       = FTP001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None

		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		ip, port = self.target.getaddr()
		try:
			ftp = ftplib.FTP()
			ftp.connect(ip, port, timeout= self.args['socket']['timeout'])
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
		t['args']     = self.args
		return t
		
		
if __name__ == '__main__':
	from ....utils import DummyTarget
	import argparse
	
	parser = argparse.ArgumentParser("This module is testing for FTP anonymous access")
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	vuln_args = {}
	vuln_args['socket'] = {}
	vuln_args['socket']['timeout'] = args.timeout
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = FTP001(t, args =  vuln_args)
	vuln.test()
	print(vuln.toJSON())