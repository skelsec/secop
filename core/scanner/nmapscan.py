import os
import tempfile
import shlex
import json
from datetime import datetime
from ..db.datamodel import db, app, target
from ..utils import PortStatus, Protocol, execute
from ..ndiff import Scan, Host

class Nmapscan():
	def __init__(self, scanobj):
		self.scanobj    = scanobj
		self.nmap_bin   = app.config['NMAP_LOCATION']
		self.ports      = None
		self.ips        = scanobj.ips
		self.rate       = '7000'
		self.cmdpattern = '%s --max-rate %s -oX %s %s %s' 
		
		self.convert_ports()

	def convert_ports(self):
		t = self.scanobj.ports.strip()
		t = ','.join(self.scanobj.ports.split(' '))[:-1]
		self.ports = '-p' + t		
		
	def scan(self):
		app.logger.debug('NMAP scan starting') 
		try:
			temp = tempfile.NamedTemporaryFile(delete=False)
			temp.close()
			cmd = self.cmdpattern % (self.nmap_bin,  self.rate, temp.name, self.ports, self.ips)
			if app.config['PLATFORM_OS'] == 'Windows':
				args = cmd
			else:
				args = shlex.split(cmd)
			app.logger.debug('NMAP executing command: %s' % (cmd,))
			self.scanobj.cmd = cmd
			self.scanobj.cmd_start_at = datetime.utcnow()
			db.session.add(self.scanobj)
			db.session.commit()
			cmddata = []
			for output_str in execute(args, yield_output = True):
				cmddata.append(output_str)
				app.logger.debug(output_str)
			app.logger.debug('NMAP command finished execution')
			self.scanobj.cmd_finish_at = datetime.utcnow()
			self.scanobj.cmd_output = '\r\n'.join(cmddata)
			db.session.add(self.scanobj)
			db.session.commit()
			self.parse_result(temp.name)
			
		except Exception as e:
			app.logger.exception('Error while performing scan!') 
			
		finally:
			os.unlink(temp.name)
		
	def parse_result(self, xmlfile):
		app.logger.debug('NMAP parsing results')
		if os.path.getsize(xmlfile) < 10:
			app.logger.info('No results in file')
			return ips
		
		scan_a = Scan()
		scan_a.load_from_file(xmlfile)
		for host in scan_a.hosts:
			ip = str(host.addresses[0])
			rdns = None
			if len(host.hostnames) > 0:
				rdns = str(host.hostnames[0])
			
			
			for portt in host.ports:
				port, proto = portt
				
				if proto == 'tcp':
					protocol = Protocol.TCP
				elif proto == 'udp':
					protocol = Protocol.UDP
				else:
					raise Exception('Unknown protocol! %s' % proto)
					
				
				if host.ports[portt].state == 'open':
					status = PortStatus.OPEN
				elif host.ports[portt].state == 'closed':
					status = PortStatus.CLOSED
				elif host.ports[portt].state == 'filtered':
					status = PortStatus.FILTERED
				else:
					continue
					raise Exception('Unknown port status! %s' % host['ports'][0]['status'])
			
				t = target(self.scanobj, ip, port, protocol, status)
				db.session.add(t)
		db.session.commit()
		