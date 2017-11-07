from .utils import *
from .scanner.masscan  import Masscan
from .scanner.nmapscan import Nmapscan
from .db.datamodel import db, project, portscanner, target, PortStatus, IPStatus, ScannerType
from ipaddress import IPv4Network, IPv6Network

def deploy():
	db.create_all()
	
	
def start_scan(scanobj):
	if scanobj.scanner_type == ScannerType.NMAP:
		nmapscan = Nmapscan(scanobj)
		nmapscan.scan()
	elif scanobj.scanner_type == ScannerType.MASSCAN:
		masscan = Masscan(scanobj)
		masscan.scan()
	elif scanobj.scanner_type == ScannerType.FILE:
		start_filescan(scanobj)
	else:
		raise Exception('Scanner type not supported!')
		
def create_project(description = ''):
	proj = project()
	db.session.add(proj)
	db.session.commit()
	return proj

def create_scan(proj, scanner_type, targets, ports, args = None):
	scantype = None
	
	if scanner_type == 'NMAP':
		scantype = ScannerType.NMAP
	elif scanner_type == 'MASSCAN':
		scantype = ScannerType.MASSCAN
	elif scanner_type == 'FILE':
		scantype = ScannerType.FILE
	else:
		raise Exception('Scanner type not supported!')
		
	pss = portscanner(proj, scantype, targets.targetdef, ports.portdef, args)
		
	db.session.add(pss)
	db.session.commit()
		
	return pss