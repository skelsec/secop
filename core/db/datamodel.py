#!/usr/bin/env python
from datetime import datetime
import base64
import json
from . import db, app
from ..utils import Protocol, PortStatus, IPStatus, ScannerType, TestResult, UniversalEncoder, flatten

class project(db.Model):
	id           = db.Column(db.Integer(), primary_key = True)
	created_at   = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	description  = db.Column(db.String(1024), nullable=True)
	scans        = db.relationship('portscanner', backref='project', lazy='dynamic')


	def __init__(self, description = None):
		self.description = description
		return
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)

	def toDict(self):
		temp = {}
		temp['id']          = self.id
		temp['description'] = self.description
		temp['created_at']  = self.created_at
		return temp
		
	def toTSV(self, separator = '\t', keys = ['id', 'description', 'created_at']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])
		
		
class portscanner(db.Model):
	id            = db.Column(db.Integer(), primary_key = True)
	project_id    = db.Column(db.Integer(), db.ForeignKey('project.id'))
	scanner_type  = db.Column(db.Enum(ScannerType))
	filedata      = db.Column(db.LargeBinary(), nullable=True)
	ports         = db.Column(db.Text, nullable=False)
	ips           = db.Column(db.Text, nullable=False)
	cmd           = db.Column(db.Text, nullable=True)
	cmd_start_at  = db.Column(db.DateTime, nullable=True)
	cmd_finish_at = db.Column(db.DateTime, nullable=True)
	cmd_output    = db.Column(db.Text, nullable=True)
	args          = db.Column(db.Text, nullable=True)
	
	targets = db.relationship('target', backref='scanner', lazy='dynamic')

	def __init__(self, project, scanner_type, ips, ports, args = None, filedata = None):
		self.project_id    = project.id
		self.scanner_type = scanner_type
		self.ips   = ips
		self.ports = ports
		self.args = args
		
		return

	def toDict(self, verbose = False):
		temp = {}
		temp['id']            = self.id
		temp['project_id']    = self.project_id
		temp['scanner_type']  = self.scanner_type
		temp['ips']           = self.ips
		temp['ports']         = self.ports
		temp['cmd']           = self.cmd
		temp['cmd_start_at']  = self.cmd_start_at
		temp['cmd_finish_at'] = self.cmd_finish_at
		temp['args']          = self.args
		if verbose:
			temp['cmd_output']     = str(self.cmd_output)
		
		return temp
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'project_id','scanner_type','ips','ports','cmd','cmd_start_at','cmd_finish_at','args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])
		
class target(db.Model):
	id           = db.Column(db.Integer(), primary_key = True)
	scanner_id   = db.Column(db.Integer(), db.ForeignKey('portscanner.id'))
	ip           = db.Column(db.String(45), nullable=False) #45 to support ipv6
	rdns         = db.Column(db.String(1024), nullable=True)
	port         = db.Column(db.Integer(), nullable=False)
	ttl          = db.Column(db.Integer(), nullable=True)
	protocol     = db.Column(db.Enum(Protocol))
	scanned_at   = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	port_status  = db.Column(db.Enum(PortStatus))
	
	vuln_ftp001   = db.relationship('FTP001', backref='target', lazy='dynamic')
	vuln_smb001   = db.relationship('SMB001', backref='target', lazy='dynamic')
	vuln_http001   = db.relationship('HTTP001', backref='target', lazy='dynamic')
	vuln_ssl001   = db.relationship('SSL001', backref='target', lazy='dynamic')
	vuln_ldap001   = db.relationship('LDAP001', backref='target', lazy='dynamic')
	
	def __init__(self, scanner, ip, port, protocol, port_status, ttl = None, scanned_at = datetime.utcnow()):
		self.scanner_id = scanner.id
		self.ip = ip
		self.ttl = ttl
		self.port = port
		self.protocol = protocol
		self.port_status = port_status
		self.scanned_at = scanned_at
		return
		
	def getaddr(self):
		return (self.ip, int(self.port))
		
	def toDict(self):
		t = {}
		t['id']         = self.id
		t['scanner_id'] = self.scanner_id
		t['ip']         = self.ip
		t['rdns']       = self.rdns
		t['port']       = self.port
		t['ttl']        = self.ttl
		t['protocol']   = self.protocol
		t['scanned_at'] = self.scanned_at
		t['port_status'] = self.port_status
		
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'scanner_id','ip','port','rdns','ttl','protocol','scanned_at','port_status']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])

class plugin(db.Model):
	id               = db.Column(db.Integer(), primary_key = True)
	installed_at     = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	version          = db.Column(db.Integer(), nullable=False)
	shortname        = db.Column(db.Text, nullable=False)
	name             = db.Column(db.Text, nullable=True)
	CVE_score        = db.Column(db.Integer(), nullable=False)
	shortdescription = db.Column(db.Text, nullable=True)
	longdescription  = db.Column(db.Text, nullable=True)
	resolution       = db.Column(db.Text, nullable=True)
	triggerPorts     = db.Column(db.Text, nullable=False)
	
	def __init__(self, pluginObj, installed_at = datetime.utcnow()):
		self.installed_at     = installed_at
		self.version          = pluginObj.version
		self.shortname        = pluginObj.shortname
		self.name             = pluginObj.name
		self.CVE_score        = pluginObj.CVE_score
		self.shortdescription = pluginObj.shortdescription
		self.longdescription  = pluginObj.longdescription
		self.resolution       = pluginObj.resolution
		self.triggerPorts     = pluginObj.triggerPorts
	

class FTP001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True)
	args           = db.Column(db.Text, nullable=True)
	
	def __init__(self, target, vulnObj):
		#vulnObj is FTP001
		self.target_id       = target.id
		self.args            = json.dumps(vulnObj.args, cls = UniversalEncoder)
		self.testresult      = vulnObj.testresult
		self.error_reason    = vulnObj.error_reason
		self.tested_at       = vulnObj.tested_at
		
	def toDict(self):
		t = {}
		t['id']              = self.id
		t['target_id']       = self.target_id
		t['testresult']      = self.testresult
		t['error_reason']    = self.error_reason
		t['tested_at']       = self.tested_at
		t['args']            = self.args		
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'target_id','testresult','error_reason','tested_at', 'args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])

		
class SMB001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True)
	args           = db.Column(db.Text, nullable=True)
	
	SMBDomain       = db.Column(db.Text, nullable=True)
	SMBHostname     = db.Column(db.Text, nullable=True)
	SMBSigning      = db.Column(db.Boolean, nullable=True)
	SMBOsVersion    = db.Column(db.Text, nullable=True)
	SMBLanManClient = db.Column(db.Text, nullable=True)
	
	def __init__(self, target, vulnObj):
		#vulnObj is SMB001
		self.target_id       = target.id
		self.args            = json.dumps(vulnObj.args, cls = UniversalEncoder)
		self.testresult      = vulnObj.testresult
		self.error_reason    = vulnObj.error_reason
		self.tested_at       = vulnObj.tested_at
		self.SMBDomain       = vulnObj.SMBDomain
		self.SMBHostname     = vulnObj.SMBHostname
		self.SMBSigning      = vulnObj.SMBSigning
		self.SMBOsVersion    = vulnObj.SMBOsVersion 
		self.SMBLanManClient = vulnObj.SMBLanManClient

	def toDict(self):
		t = {}
		t['id']              = self.id
		t['target_id']       = self.target_id
		t['testresult']      = self.testresult
		t['error_reason']    = self.error_reason
		t['tested_at']       = self.tested_at
		t['SMBDomain']       = self.SMBDomain
		t['SMBHostname']     = self.SMBHostname
		t['SMBSigning']      = self.SMBSigning
		t['SMBOsVersion']    = self.SMBOsVersion
		t['SMBLanManClient'] = self.SMBLanManClient
		t['args']            = self.args
		
		
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'target_id','testresult','error_reason','tested_at','SMBDomain','SMBHostname','SMBSigning','SMBOsVersion','SMBLanManClient', 'args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])
		
class HTTP001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True)
	args           = db.Column(db.Text, nullable=True)
	
	screenshot     = db.Column(db.LargeBinary, nullable=True)
	
	def __init__(self, target, vulnObj):
		#vulnObj is HTTP001
		self.target_id       = target.id
		self.args            = json.dumps(vulnObj.args, cls = UniversalEncoder)
		self.testresult      = vulnObj.testresult
		self.error_reason    = vulnObj.error_reason
		self.tested_at       = vulnObj.tested_at
		self.screenshot      = vulnObj.screenshot

	def toDict(self, verbose = False):
		t = {}
		t['id']           = self.id
		t['target_id']    = self.target_id
		t['testresult']   = self.testresult
		t['error_reason'] = self.error_reason
		t['tested_at']    = self.tested_at
		t['args']         = self.args
		if verbose:
			t['screenshot']   = base64.b64encode(self.screenshot)
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'target_id','testresult','error_reason','tested_at','screenshot','args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])
		
class SSL001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True)
	args           = db.Column(db.Text, nullable=True)
	synopsis       = db.Column(db.Text, nullable=True)

	
	def __init__(self, target, vulnObj):
		#vulnObj is SSL001
		self.target_id       = target.id
		self.args            = json.dumps(vulnObj.args, cls = UniversalEncoder)
		self.testresult      = vulnObj.testresult
		self.error_reason    = vulnObj.error_reason
		self.tested_at       = vulnObj.tested_at
		self.synopsis        = vulnObj.synopsis


	def toDict(self):
		t = {}
		t['id']           = self.id
		t['target_id']    = self.target_id
		t['testresult']   = self.testresult
		t['error_reason'] = self.error_reason
		t['tested_at']    = self.tested_at
		t['args']         = self.args
		t['synopsis']     = self.synopsis
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'target_id','testresult','error_reason','tested_at','synopsis','args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])
		
		
class LDAP001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True)
	args           = db.Column(db.Text, nullable=True)
	
	def __init__(self, target, vulnObj):
		#vulnObj is LDAP001
		self.target_id       = target.id
		self.args            = json.dumps(vulnObj.args, cls = UniversalEncoder)
		self.testresult      = vulnObj.testresult
		self.error_reason    = vulnObj.error_reason
		self.tested_at       = vulnObj.tested_at
		
	def toDict(self):
		t = {}
		t['id']              = self.id
		t['target_id']       = self.target_id
		t['testresult']      = self.testresult
		t['error_reason']    = self.error_reason
		t['tested_at']       = self.tested_at
		t['args']            = self.args		
		return t
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toTSV(self, separator = '\t', keys = ['id', 'target_id','testresult','error_reason','tested_at', 'args']):
		t = json.loads(self.toJSON())
		return separator.join([flatten(t[x], separator) for x in keys])		
		
		
		
vulnLookupTable = {
				'SMB001'  : SMB001,
				'HTTP001' : HTTP001,
				'SSL001'  : SSL001,
				'FTP001'  : FTP001,
				'LDAP001' : LDAP001
			}
