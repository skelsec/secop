#https://gist.github.com/akshatmittal/10279360
import json
from datetime import datetime
import ldap

from ....utils import TestResult, UniversalEncoder



class LDAP001PluginDef():
	def __init__(self):
		self.classname        = 'LDAP001'
		self.version          = '0.1'
		self.triggerPorts     = '389,636,3268'
		self.shortname        = 'LDAP Anon'
		self.name             = 'LDAP anonymous bind test'
		self.CVE_score        = 0
		self.shortdescription = ''
		self.longdescription  = ''
		self.resolution       = ''

class LDAP001():
	"""Tests for Anonymous LDAP bind
	
	Args:
        target (target, optional): The target specification object. Type: either 'target' or 'DummyTarget'. Defaults to None.
        args   (:obj:`dict`, optional): The second parameter. Defaults to None.
			Uses the following arguemt parameters:
				self.args['socket']['timeout']   To specify the timeout
				self.args['LDAP']['forceSSL']   To override SSL settings
	"""
	def __init__(self, target = None, args = None):
		self.args            = args
		self.plugindef       = LDAP001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None

		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		try:
			ip, port = self.target.getaddr()
			isSSL = False
			url = ''
			if port == 389:
				url = 'ldap://%s:%d' % (ip, port)
			elif port == 636 or port == 3268:
				url = 'ldaps://%s:%d' % (ip, port)
				isSSL = True
			else:
				if self.args is not None:
					if 'LDAP' in self.args:
						if 'forceSSL' in self.args['LDAP'] and self.args['LDAP']['forceSSL']:
							url = 'ldaps://%s:%d' % (ip, port)
							isSSL = True
							
			if not isSSL:
				url = 'ldap://%s:%d' % (ip, port)	
			else:
				ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
			
			timeout = 1
			try:
				timeout = self.args['socket']['timeout']
			except Exception as e:
				pass
			
			ldap.set_option(ldap.OPT_TIMEOUT, timeout)
				
			try:
				con = ldap.initialize(url, bytes_mode=False)
				con.simple_bind_s("","")
				self.testresult = TestResult.VULNERABLE
			
			except ldap.INVALID_CREDENTIALS as e:
				self.testresult = TestResult.NOTVULNERABLE
			
			except ldap.TIMEOUT as e:
				self.testresult = TestResult.ERROR
				self.error_reason = 'LDAP timeout'
				
			except Exception as e:
				raise(e)
				
		except Exception as e:
			self.testresult = TestResult.ERROR
			self.error_reason = str(e)
	
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
			
	def toDict(self):
		t = {}
		t['target']       = self.target.toDict()
		t['testresult']   = self.testresult
		t['error_reason'] = self.error_reason
		t['tested_at']    = self.tested_at
		t['args']         = self.args
		return t
		

		
		
if __name__ == '__main__':
	from ....utils import DummyTarget
	import argparse
	
	parser = argparse.ArgumentParser('Test for anonymous LDAP bind')
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=float, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	vuln_args = {}
	vuln_args['socket'] = {}
	vuln_args['socket']['timeout'] = args.timeout
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = LDAP001(t, args = vuln_args)
	vuln.test()
	print(vuln.toJSON())
	