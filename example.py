import multiprocessing
from core import core
from core.scanner.vulnscan import Vulnscan
from core.utils import Targets, Ports
from core.services.FTP.vuln.FTP001 import FTP001
from core.services.HTTP.info.HTTP001 import HTTP001
from core.services.LDAP.vuln.LDAP001 import LDAP001
from core.services.SMB.info.SMB001 import SMB001
from core.services.SSL.vuln.SSL001 import SSL001
	
if __name__ == '__main__':
	multiprocessing.freeze_support()
	vuln_args = {}
	vuln_args['socket'] = {}
	vuln_args['socket']['timeout'] = 1
	#vuln_args['socket']['isSSL']   = None
		
		
	vuln_args['PATH'] = {}
	vuln_args['PATH']['PhantomJS'] = '.\\bins\\phantomjs-2.1.1-windows\\bin\\phantomjs.exe'



	## install the app
	core.deploy()


	#core.create_scan('MASSCAN', targets, ports, args)

	targetdef = '127.0.0.1'
	portdef = '21,80,443,389,636,445'

	#1. parsing human input
	targets = Targets(targetdef)
	ports = Ports(portdef)

	#print(targets.targets)
	#print(ports.ports)

	#2. create project
	project = core.create_project()
	print('Project created with ID: %d' % (project.id,))

	#2. create scan
	scannerobj = core.create_scan(project,'MASSCAN', targets, ports)
	#scannerobj = core.create_scan(project, 'NMAP', targets, ports)
	print('Scanner created with ID: %d' % (scannerobj.id,))

	#3. start scan
	core.start_scan(scannerobj)
	#4. notify user scan has finished

	print('Scanner finsihed! Starting vulnerability scanning!')
	#vulns = [FTP001(), HTTP001(), LDAP001(), SMB001(), SSL001()]
	vulns = [FTP001(), LDAP001(), SMB001(), SSL001()]
	#this is how you can override trigger ports
	#v.plugindef.triggerPorts = '443'
		
	vs = Vulnscan(project, vulns, vuln_args)
	vs.scan()
	print('Done!')

	"""
	pids = []
	for project in core.get_all_projects():
		print(project.toTSV())
		pids.append(project.id)

	print('----------------SCANS')
	for pid in pids:
		for scanner in core.get_portscanner_for_project(pid):
			print(scanner.toTSV())

	print('----------------TARGETS')
	for target in core.get_target_for_project(1):
		print(target.toTSV())
	"""