#https://gist.github.com/akshatmittal/10279360
import json
from datetime import datetime

from ....utils import TestResult, UniversalEncoder, h2bin, hexdump
from selenium import webdriver


class HTTP001PluginDef():
	def __init__(self):
		self.classname        = 'HTTPS001'
		self.version          = '0.1'
		self.triggerPorts     = '80,443'
		self.shortname        = ''
		self.name             = ''
		self.CVE_score        = 0
		self.shortdescription = ''
		self.longdescription  = ''
		self.resolution       = ''

class HTTP001():
	def __init__(self, target = None, timeout = 1, args = None):
		self.args            = args
		self.plugindef       = HTTP001PluginDef()
		self.target          = target
		self.testresult      = TestResult.NOTSTARTED
		self.error_reason    = None
		self.tested_at       = None
		#socket parameters
		self.soc_timeout     = timeout
		self.screenshot      = None

		
	def test(self):
		self.testresult = TestResult.STARTED
		self.tested_at  = datetime.utcnow()
		try:
			if self.args is not None:
				driver = webdriver.PhantomJS(executable_path=self.args['PhantomJS_PATH'], service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any']) # or add to your PATH
			else:
				driver = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'])
			driver.get('https://google.com/')
			self.screenshot = driver.get_screenshot_as_base64()
			driver.quit()
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
	vuln_args = {}
	vuln_args['PhantomJS_PATH'] = '.\\bins\\phantomjs-2.1.1-windows\\bin\\phantomjs.exe'
	
	vuln = HTTP001(t, args = vuln_args, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())
	