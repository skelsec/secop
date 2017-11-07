#!/usr/bin/env python
from datetime import datetime
from . import db, app
from ..utils import Protocol, PortStatus, IPStatus, ScannerType, TestResult

class project(db.Model):
	id           = db.Column(db.Integer(), primary_key = True)
	created_at   = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	description  = db.Column(db.String(1024), nullable=True)
	scans        = db.relationship('portscanner', backref='project', lazy='dynamic')


	def __init__(self, description = None):
		self.description = description
		return

	def toDict(self):
		temp = {}
		temp['id'] = str(self.id)
		temp['description'] = str(self.description)
		temp['created_at'] = self.created_at.isoformat()
		return temp
		
		
class portscanner(db.Model):
	id           = db.Column(db.Integer(), primary_key = True)
	project_id    = db.Column(db.Integer(), db.ForeignKey('project.id'))
	scanner_type = db.Column(db.Enum(ScannerType))
	filedata     = db.Column(db.LargeBinary(), nullable=True)
	ports        = db.Column(db.Text, nullable=False)
	ips          = db.Column(db.Text, nullable=False)
	cmd          = db.Column(db.Text, nullable=True)
	cmd_start_at = db.Column(db.DateTime, nullable=True)
	cmd_finish_at = db.Column(db.DateTime, nullable=True)
	cmd_output   = db.Column(db.Text, nullable=True)
	args         = db.Column(db.Text, nullable=True)
	
	targets = db.relationship('target', backref='scanner', lazy='dynamic')

	def __init__(self, project, scanner_type, ips, ports, args = None, filedata = None):
		self.project_id    = project.id
		self.scanner_type = scanner_type
		self.ips   = ips
		self.ports = ports
		self.args = args
		
		return

	def toDict(self):
		temp = {}
		temp['scanid'] = str(self.id)
		temp['scanner_type'] = self.created_at.isoformat()
		return temp
		
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
	
	vuln_ftp01   = db.relationship('FTP01', backref='target', lazy='dynamic')
	
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
		
	def toJSON(self):
		return json.dumps(self.toDict(), cls = UniversalEncoder)
		
	def toDict(self):
		t = {}
		t['id'] = self.id
		t['scanner_id'] = self.scanner_id
		t['rdns'] = self.rdns
		t['port'] = self.port
		t['ttl'] = self.ttl
		t['protocol'] = self.protocol
		t['scanned_at'] = self.scanned_at
		t['port_status'] = self.port_status
		
		return t
		

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
	

class FTP01(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id       = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_version = db.Column(db.Integer(), nullable=False)
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True) #null is test failed
	synopsis       = db.Column(db.Text, nullable=True)
	
	def __init__(self, target, plugin_version, testresult, synopsis = None, error_reason = None, tested_at = datetime.utcnow()):
		self.target_id = target.id
		self.plugin_version = plugin_version
		self.testresult = testresult
		self.synopsis = synopsis
		self.error_reason = error_reason
		self.tested_at = tested_at	

		
class SMB001(db.Model):
	id             = db.Column(db.Integer(), primary_key = True)
	target_id      = db.Column(db.Integer(), db.ForeignKey('target.id'))
	plugin_id      = db.Column(db.Integer(), db.ForeignKey('plugin.id'))
	tested_at      = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	error_reason   = db.Column(db.Text, nullable=True)
	testresult     = db.Column(db.Enum(TestResult), nullable=True) #null is test failed
	
	SMBDomain       = db.Column(db.Text, nullable=True)
	SMBHostname     = db.Column(db.Text, nullable=True)
	SMBSigning      = db.Column(db.Boolean, nullable=True)
	SMBOsVersion    = db.Column(db.Text, nullable=True)
	SMBLanManClient = db.Column(db.Text, nullable=True)
	
	def __init__(self, target, vulnObj):
		#vulnObj is SMB001
		self.target_id      = target.id
		self.testresult     = vulnObj.testresult
		self.error_reason   = vulnObj.error_reason
		self.tested_at      = vulnObj.tested_at
		self.SMBDomain       = vulnObj.SMBDomain
		self.SMBHostname     = vulnObj.SMBHostname
		self.SMBSigning      = vulnObj.SMBSigning
		self.SMBOsVersion    = vulnObj.SMBOsVersion 
		self.SMBLanManClient = vulnObj.SMBLanManClient

		self.soc_timeout     = vulnObj.soc_timeout
		
vulnLookupTable = {
				'SMB001' : SMB001
			}		
"""
class servicetestresult(db.Model):
	id           = db.Column(db.Integer(), primary_key = True)
	targetid     = db.Column(db.Integer(), db.ForeignKey('target.id'))
	timestamp    = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	testsuccsess = db.Column(db.Boolean(), nullable=False)
	vulnerable   = db.Column(db.Boolean()) #if null, then test faled
	
	def __init__(self):
		return


##### each and every test case will have it's own table!!!!
##### we make it this way, because this makes the plugin results parsable
class servicetestdata(db.Model):
	id                  = db.Column(db.Integer(), primary_key = True)
	servicetestresultid = db.Column(db.Integer(), db.ForeignKey('servicetestresult.id'))

"""