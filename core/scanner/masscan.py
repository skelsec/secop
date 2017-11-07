import os
import tempfile
import shlex
import json
from datetime import datetime
from ..db.datamodel import db, app, target
from ..utils import PortStatus, Protocol, execute
from ..ndiff import Scan, Host

class Masscan():
	def __init__(self, scanobj):
		self.scanobj     = scanobj
		self.masscan_bin = app.config['MASSCAN_LOCATION']
		self.nmap_bin    = app.config['NMAP_LOCATION']
		self.ports       = None 
		self.ips         = scanobj.ips
		self.rate        = '7000'
		self.cmdpattern  = '%s %s %s --rate=%s -oJ %s'
		self.rdnspattern = '%s -T5 -sL -iL %s -oX %s'
		self.convert_ports()
		
	def convert_ports(self):
		t = self.scanobj.ports.strip()
		t = ','.join(self.scanobj.ports.split(' '))[:-1]
		self.ports = '-p ' + t
		
	def scan(self):
		app.logger.debug('MASSCAN scan starting') 
		try:
			temp = tempfile.NamedTemporaryFile(delete=False)
			temp.close()
			cmd = self.cmdpattern % (self.masscan_bin, self.ports, self.ips, self.rate, temp.name)
			if app.config['PLATFORM_OS'] == 'Windows':
				args = cmd
			else:
				args = shlex.split(cmd)
			app.logger.debug('MASSCAN executing command: %s' % (cmd,))
			self.scanobj.cmd = cmd
			self.scanobj.cmd_start_at = datetime.utcnow()
			db.session.add(self.scanobj)
			db.session.commit()
			cmddata = []
			for output_str in execute(args, yield_output = True):
				cmddata.append(output_str)
				app.logger.debug(output_str)
				
			app.logger.debug('MASSCAN command finished execution')
			self.scanobj.cmd_finish_at = datetime.utcnow()
			### targets is there for nmap scan
			targets = self.parse_result(temp.name)
			#do rdns lookup
			if len(targets) > 0:
				cmddata += self.rdns_scan(targets)
				self.scanobj.cmd_output = '\r\n'.join(cmddata)
				db.session.add(self.scanobj)
				db.session.commit()
		
		except Exception as e:
			app.logger.exception('Error while performing scan!')
			
		finally:
			os.unlink(temp.name)
			
	#to this date masscan does not perform rdns resolution. Therefore we use NMAP to do rdns resolution		
	def rdns_scan(self, ips):
		app.logger.debug('MASSCAN rdns resolution starting') 
		try:
			temp_target = tempfile.NamedTemporaryFile(delete=False)
			temp_xmlout = tempfile.NamedTemporaryFile(delete=False)
			for ip in ips:
				temp_target.write((ip + '\r\n').encode('ascii'))
			temp_target.close()
			temp_xmlout.close()
			cmd = self.rdnspattern % (self.nmap_bin, temp_target.name, temp_xmlout.name)
			if app.config['PLATFORM_OS'] == 'Windows':
				args = cmd
			else:
				args = shlex.split(cmd)
			
			cmddata = ['####### RDNS Resolution...']
			for output_str in execute(args, yield_output = True):
				app.logger.debug(output_str)
				cmddata.append(output_str)
			scan_a = Scan()
			scan_a.load_from_file(temp_xmlout.name)
			for host in scan_a.hosts:
				target.query.filter_by(scanner_id = self.scanobj.id).filter_by(ip = str(host.addresses[0])).update(dict(rdns = str(host.hostnames[0])))
				db.session.commit()
				
			return cmddata
				
		except Exception as e:
			app.logger.exception('Error while performing rdns resolution!') 
			
		finally:
			os.unlink(temp_target.name)
			os.unlink(temp_xmlout.name)
		
	def parse_result(self, jsonfile):
		app.logger.debug('MASSCAN finished, parsing output')
		ips = {}
		if os.path.getsize(jsonfile) < 10:
			app.logger.info('No results in file')
			return ips
		with open(jsonfile,'r') as f:
			data = f.read()
			
		marker = data.rfind(',')
		data = data[:marker] + data[marker+1:]
		ctr = 0
		for host in json.loads(data):
			ips[host['ip']] = 0
			ip = host['ip']
			port = host['ports'][0]['port']
			if host['ports'][0]['proto'] == 'tcp':
				protocol = Protocol.TCP
			elif host['ports'][0]['proto'] == 'udp':
				protocol = Protocol.UDP
			else:
				raise Exception('Unknown protocol! %s' % host['ports'][0]['port'])
			
			ttl = host['ports'][0]['ttl']
			if host['ports'][0]['status'] == 'open':
				status = PortStatus.OPEN
			elif host['ports'][0]['status'] == 'closed':
				status = PortStatus.CLOSED
			elif host['ports'][0]['status'] == 'filtered':
				status = PortStatus.FILTERED
			else:
				raise Exception('Unknown port status! %s' % host['ports'][0]['status'])
			
			t = target(self.scanobj, ip, port, protocol,status, ttl = ttl)
			db.session.add(t)
			ctr += 1
		db.session.commit()
		app.logger.debug('MASSCAN comitted %d targets to DB!' % (ctr,))
		return ips
		