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
	def __init__(self, target = None, timeout = 1, args = None):
		self.args            = args
		self.plugindef       = LDAP001PluginDef()
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
				if self.args.ldapargs.forceSSL:
					url = 'ldaps://%s:%d' % (ip, port)
					isSSL = True
				else:
					url = 'ldap://%s:%d' % (ip, port)
			else:
				url = 'ldap://%s:%d' % (ip, port)
		if isSSL:
			ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
		try:
			con = ldap.initialize(url, bytes_mode=False)
			con.simple_bind_s("","")
			self.testresult = TestResult.VULNERABLE
		
		except ldap.INVALID_CREDENTIALS as e:
			self.testresult = TestResult.NOTVULNERABLE
			self.synopsis = str(e)
				
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
	
	parser = argparse.ArgumentParser('Test for anonymous LDAP bind')
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()	
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = LDAP001(t, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())
	