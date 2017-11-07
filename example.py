from core import core
from core.utils import Targets, Ports

## install the app
core.deploy()


#core.create_scan('MASSCAN', targets, ports, args)

targetdef = '10.0.0.1, 192.168.42.143'
portdef = '443, 80, 445'

#1. parsing human input
targets = Targets(targetdef)
ports = Ports(portdef)

#print(targets.targets)
#print(ports.ports)

#2. create project
proejct = core.create_project()

#2. create scan
scannerobj = core.create_scan(proejct,'MASSCAN', targets, ports)
#scannerobj = core.create_scan(proejct, 'NMAP', targets, ports)

#3. start scan
core.start_scan(scannerobj)
#4. notify user scan has finished