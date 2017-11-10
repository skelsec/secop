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
	
def get_all_projects():
	for proj in project.query.all():
		yield proj
	
def get_project(project_id):
	return project.query.get(project_id)
	
def get_portscanner(scan_id):
	return portscanner.query.get(scan_id)

def get_portscanner_for_project(project_id):
	for ps in get_project(project_id).scans.all():
		yield ps

def get_target_for_portscanner(scan_id):
	for t in get_portscanner(scan_id).targets.all():
		yield t
		
def get_target_for_project(project_id):
	for ps in get_portscanner_for_project(project_id):
		for t in get_target_for_portscanner(ps.id):
			yield t
	

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