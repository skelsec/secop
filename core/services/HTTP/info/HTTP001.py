import json
from datetime import datetime
import base64
from ....utils import TestResult, UniversalEncoder, h2bin, hexdump
from ..httputils import getURL
from selenium import webdriver


class HTTP001PluginDef():
	def __init__(self):
		self.classname        = 'HTTP001'
		self.version          = '0.1'
		self.triggerPorts     = '80,443'
		self.shortname        = ''
		self.name             = 'HTTP screenshot'
		self.CVE_score        = 0
		self.shortdescription = 'Creates screenshot of the target HTTP(s) server'
		self.longdescription  = ''
		self.resolution       = ''

class HTTP001():
	"""Creates a screenshot of the target.
	
	Args:
        target (target, optional): The target specification object. Type: either 'target' or 'DummyTarget'. Defaults to None.
        args   (:obj:`dict`, optional): The second parameter. Defaults to None.
			Uses the following arguemt parameters:
				self.args['socket']['isSSL']     To specify is the target is using SSL
				self.args['socket']['timeout']   To specify the timeout
				self.args['PATH']['PhantomJS']   To specift PhantomJS binary path (it needs to be specified either here or in the OS PATH variable)
	"""
	def __init__(self, target = None, args = None):
		self.args            = args
		self.plugindef       = HTTP001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None
		self.screenshot      = None

		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		try:
			url = getURL(self.target, False)
			phantomJSbin = ''
			if self.args is not None:
				if 'socket' in self.args:
					if 'isSSL' in self.args['socket']:
						url = getURL(self.target, self.args['socket']['isSSL'])
				if 'PATH' in self.args:
					if 'PhantomJS' in self.args['PATH']:
						phantomJSbin = self.args['PATH']['PhantomJS']
			if 	phantomJSbin != '':
				driver = webdriver.PhantomJS(executable_path=phantomJSbin, service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any']) # or add to your PATH
			else:
				driver = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'])
			driver.get(url)
			self.screenshot = base64.b64decode(driver.get_screenshot_as_base64())
			driver.quit()
			self.testresult = TestResult.VULNERABLE
				
		except Exception as e:
			self.testresult = TestResult.ERROR
			self.error_reason = str(e)
	
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
			
	def toDict(self, verbose = False):
		t = {}
		t['target']          = self.target.toDict()
		t['testresult']      = self.testresult
		t['error_reason']    = self.error_reason
		t['tested_at']       = self.tested_at
		t['args']            = self.args
		if verbose:
			t['screenshot']      = base64.b64encode(self.screenshot)
		return t
		

		
		
if __name__ == '__main__':
	from ....utils import DummyTarget
	import argparse
	
	parser = argparse.ArgumentParser('Takes screenshot of the specified target HTTP(s) server')
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	parser.add_argument("--ssl", action='store_true', default = False, help="use HTTPS")
	
	args = parser.parse_args()
	
	t = DummyTarget(args.ip,args.port)
	vuln_args = {}
	vuln_args['socket'] = {}
	vuln_args['socket']['timeout'] = args.timeout
	vuln_args['socket']['isSSL']   = args.ssl
	
	
	vuln_args['PATH'] = {}
	vuln_args['PATH']['PhantomJS'] = '.\\bins\\phantomjs-2.1.1-windows\\bin\\phantomjs.exe'
	
	vuln = HTTP001(t, args = vuln_args) 
	vuln.test()
	print(vuln.toJSON())
	