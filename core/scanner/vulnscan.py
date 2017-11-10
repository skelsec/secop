import multiprocessing
import queue
import threading
import json
from datetime import datetime
import enum
import logging

from sqlalchemy import MetaData, Table

from ..db.datamodel import db, app, project, portscanner, target, vulnLookupTable
from ..utils import Ports, PortStatus

class WorkerCommand(enum.Enum):
	STOP = 0
	TEST = 1

class Vulnscan():
	def __init__(self, project, vulns, vulnargs, procCnt = 1, threadCnt = 1):
		self.project     = project
		self.vulns       = vulns
		self.vulnargs    = vulnargs
		self.procCnt     = procCnt
		self.threadCnt   = threadCnt
		self.stopEvent   = multiprocessing.Event()
		self.inQ         = multiprocessing.Queue()
		self.outQ        = multiprocessing.Queue()
		
		self.workers     = []
		self.reporter    = None
		
	def setup(self):
		self.reporter = VulnscanReporter(self.outQ, self.stopEvent, logObj = app.logger)
		self.reporter.daemon = True
		self.reporter.start()
		
		for i in range(self.procCnt):
			p = VulnscanWorker(self.inQ, self.outQ, self.stopEvent, threadCnt = self.threadCnt)
			p.daemon = True
			self.workers.append(p)
		
	def scan(self):
		app.logger.debug('VULNSCAN scan starting') 
		self.setup()
		
		app.logger.debug('VULNSCAN starting worker processes')
		for worker in self.workers:
			worker.start()
				
		app.logger.debug('VULNSCAN polling database for targets and starting scanning')
		for vuln in self.vulns:
			ports = Ports(vuln.plugindef.triggerPorts)
			for scan in self.project.scans.all():
				for t in scan.targets.filter(target.port.in_(ports.ports)).filter(target.port_status == PortStatus.OPEN).all():
					vulnclass = type(vuln)
					vt = VulnscanTask(t, vulnclass(), WorkerCommand.TEST, args = self.vulnargs)
					self.inQ.put(vt)
					
		app.logger.debug('VULNSCAN waiting for workers to finish...')
		for i in range(self.procCnt * self.threadCnt):
			self.inQ.put(VulnscanTask(workerCmd = WorkerCommand.STOP))
		
		for worker in self.workers:
			worker.join()
				
		app.logger.debug('VULNSCAN waiting for reporter to finish...')
		self.outQ.put(VulnscanTask(workerCmd = WorkerCommand.STOP))
		self.reporter.join()
					
class LogEntry():
	def __init__(self, level, src, msg):
		self.src   = src
		self.level = level
		self.msg   = msg
	
	
class VulnscanTask():
	def __init__(self, target = None, vuln = None, workerCmd = None, args = None):
		self.target    = target
		self.vuln      = vuln
		self.workerCmd = workerCmd
		self.vulnargs  = args

class VulnscanWorker(multiprocessing.Process):
	def __init__(self, inQ, outQ, stopEvent, threadCnt = 1):
		multiprocessing.Process.__init__(self)
		self.name = 'VulnscanWorker'
		self.inQ = inQ
		self.outQ = outQ
		self.threadCnt = threadCnt
		self.stopEvent = stopEvent
		self.threads = []
		
	def log(self, level, msg):
		self.outQ.put(LogEntry(level,self.name,msg))

	def setup(self):
		for i in range(self.threadCnt):
			t = threading.Thread(target = self.work, args = ())
			t.daemon = True
			self.threads.append(t)
		
	def run(self):
		try:
			self.log(logging.INFO, 'Starting up...')
			self.setup()

			for t in self.threads:
				t.start()

			for t in self.threads:
				t.join()
		except Exception as e:
			self.log(logging.WARNING, 'Worker exception! Terminating! Reason: %s' % (str(e),))
			
	def work(self):
		while not self.stopEvent.is_set():
			try:
				try:
					vt = self.inQ.get(timeout = 1)
				except queue.Empty:
					#this timeout exception is here to have a way of constantly checking the stopEvent
					continue
				if vt.workerCmd == WorkerCommand.STOP:
					return
				
				elif vt.workerCmd == WorkerCommand.TEST:
					vt.vuln.target = vt.target
					vt.vuln.args   = vt.vulnargs
					vt.vuln.test()
					self.outQ.put(vt)
				else:
					self.log(logging.WARNING, 'Unkown command! %s' % (str(WorkerCommand.TEST), ))
					continue
			except Exception as e:
				self.log(logging.WARNING, str(e))
				break
				
		self.log(logging.INFO, 'Stopping.')
				
class VulnscanReporter(threading.Thread):
	def __init__(self, outQ, stopEvent, logObj = None):
		threading.Thread.__init__(self)
		self.outQ = outQ
		self.stopEvent = stopEvent
		self.logObj = logObj
		self.name = 'VulnscanReporter'
		self.dbmetadata = None
	
	def setup(self):	
		return
		#self.dbmetadata = db.MetaData()
		#self.dbmetadata.reflect(app=app)
		
	def log(self, level, msg):
		self.handleLog(LogEntry(level,self.name,msg))
		
	def run(self):
		self.log(logging.INFO, 'Starting up...')
		self.setup()
		while not self.stopEvent.is_set():
			try:
				try:
					vt = self.outQ.get(timeout = 1)
				except queue.Empty:
					#this timeout exception is here to have a way of constantly checking the stopEvent
					continue
					
				if isinstance(vt, LogEntry):
					self.handleLog(vt)
					
				elif isinstance(vt, VulnscanTask):
					if vt.workerCmd == WorkerCommand.STOP:
						return
				
					elif vt.workerCmd == WorkerCommand.TEST:
						self.handleVulnscan(vt)
					else:
						self.log(logging.INFO, 'Unkown command! %s' % (str(WorkerCommand.TEST), ))
						continue 
				else:
					self.log(logging.INFO, 'Unknown object landed in the outQ! Type is: %s' % (type(vt),))
			except Exception as e:
				self.log(logging.INFO, str(e))
				break
				
		self.log(logging.INFO, 'Stopping.')
				
	def handleLog(self, log):
		self.logObj.log(log.level, '%s %s' % (log.src, log.msg))
		
	def handleVulnscan(self, vt):
		self.log(logging.INFO, 'Result: %s' % (vt.vuln.toJSON(),))
		### yeah, not the most elegant solution, probably there is a better way?
		vulnTable = vulnLookupTable[vt.vuln.plugindef.classname]
		t = vulnTable(vt.target, vt.vuln)
		db.session.add(t)
		db.session.commit()
	

if __name__ == '__main__':
	from ..services.SMB.info.SMB001 import SMB001
	
	v = SMB001()
	#this is how you can override trigger ports
	#v.plugindef.triggerPorts = '443'
	
	p = project.query.first()
	
	vs = Vulnscan(p,[v])
	vs.scan()
	print('Done!')
