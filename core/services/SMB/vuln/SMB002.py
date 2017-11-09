
#https://github.com/worawit/MS17-010/blob/master/checker.py
import json
from datetime import datetime
from impacket import smb, nt_errors
from impacket.uuid import uuidtup_to_bin
import struct
import sys

from ....utils import TestResult, UniversalEncoder
from ..smbutils import DomainGrab, SmbFinger
from ..mysmb import MYSMB

NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

MSRPC_UUID_BROWSER  = uuidtup_to_bin(('6BFFD098-A112-3610-9833-012892020162','0.0'))
MSRPC_UUID_SPOOLSS  = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB','1.0'))
MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))
MSRPC_UUID_LSARPC   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))
MSRPC_UUID_SAMR     = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC','1.0'))

pipes = {
	'browser'  : MSRPC_UUID_BROWSER,
	'spoolss'  : MSRPC_UUID_SPOOLSS,
	'netlogon' : MSRPC_UUID_NETLOGON,
	'lsarpc'   : MSRPC_UUID_LSARPC,
	'samr'     : MSRPC_UUID_SAMR,
}

class SMB002PluginDef():
	def __init__(self):
		self.classname        = 'SMB002'
		self.version          = '0.1'
		self.triggerPorts     = '445'
		self.shortname        = 'SMBEthernalblue'
		self.name             = 'SMB Ethernalblue exploit - MS17-010'
		self.CVE_score        = 0
		self.shortdescription = ''
		self.longdescription  = ''
		self.resolution       = ''

class SMB002():
	def __init__(self, target = None, timeout = 1, args = None):
		self.plugindef       = SMB002PluginDef()
		self.args            = args
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
			conn = MYSMB(self.target.ip)
			try:
				if self.args is None:
					conn.login(self.args.SMBUsername, self.args.SMBPassword)
				elif self.args.smbcreds is None:
					conn.login(self.args.SMBUsername, self.args.SMBPassword)
				else:
					conn.login(self.args.smbcreds.SMBUsername, self.args.smbcreds.SMBPassword)
			except smb.SessionError as e:
				self.testresult   = TestResult.ERROR
				self.error_reason = 'Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0]
				return
			
			tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
			conn.set_default_tid(tid)
				
			# test if target is vulnerable
			TRANS_PEEK_NMPIPE = 0x23
			recvPkt = conn.send_trans(struct.pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
			status = recvPkt.getNTStatus()
			if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
				self.testresult   = TestResult.VULNERABLE
			else:
				self.testresult   = TestResult.NOTVULNERABLE

			conn.disconnect_tree(tid)
			conn.logoff()
			conn.get_socket().close()

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
	
	parser = argparse.ArgumentParser("This module is grabbing public info from SMB port")
	parser.add_argument("ip", help="Target IP address")
	parser.add_argument("port", type=int, help="Target port")
	parser.add_argument("-t", "--timeout", type=int, default = 5, help="Timeout")
	
	args = parser.parse_args()
	
	t = DummyTarget(args.ip,args.port)
	
	vuln = SMB001(t, timeout =  args.timeout)
	vuln.test()
	print(vuln.toJSON())