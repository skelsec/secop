#https://github.com/lgandx/Responder/blob/master/tools/SMBFinger/Finger.py
#
import re,sys,socket,struct
import multiprocessing
from collections import OrderedDict

#https://gist.github.com/ImmortalPC/c340564823f283fe530b
def hexdump( src, length=16, sep='.' ):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump
	@note Full support for python2 and python3 !
	'''
	result = [];

	# Python3 support
	try:
		xrange(0,1);
	except NameError:
		xrange = range;

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length];
		hexa = '';
		isMiddle = False;
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' ';
			h = subSrc[h];
			if not isinstance(h, int):
				h = ord(h);
			h = hex(h).replace('0x','');
			if len(h) == 1:
				h = '0'+h;
			hexa += h+' ';
		hexa = hexa.strip(' ');
		text = '';
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c);
			if 0x20 <= c < 0x7F:
				text += chr(c);
			else:
				text += sep;
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text));

	return '\n'.join(result);

def longueur(payload):
	length = struct.pack(">i", len(payload))
	return length

class Packet():
	fields = OrderedDict([])
	def __init__(self, **kw):
		self.fields = OrderedDict(self.__class__.fields)
		for k,v in kw.items():
			if callable(v):
				self.fields[k] = v(self.fields[k])
			else:
				self.fields[k] = v
	def __bytes__(self):
		return b"".join(self.fields.values())
	
	
class SMBHeader(Packet):
	fields = OrderedDict([
		("proto",	    b"\xff\x53\x4d\x42"),
		("cmd",		b"\x72"),
		("error-code", b"\x00\x00\x00\x00" ),
		("flag1",	    b"\x00"),
		("flag2",	    b"\x00\x00"),
		("pidhigh",	b"\x00\x00"),
		("signature",  b"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("reserved",   b"\x00\x00"),
		("tid",		b"\x00\x00"),
		("pid",		b"\x00\x00"),
		("uid",		b"\x00\x00"),
		("mid",		b"\x00\x00"),
	])

class SMBNego(Packet):
	fields = OrderedDict([
		("Wordcount", b"\x00"),
		("Bcc",       b"\x62\x00"),
		("Data",      b"")
	])
	
	def calculate(self):
		self.fields["Bcc"] = struct.pack("<h",len(self.fields["Data"]))

class SMBNegoData(Packet):
	fields = OrderedDict([
		("BuffType",  b"\x02"),
		("Dialect",   b"NT LM 0.12\x00"),
	])


class SMBSessionFingerData(Packet):
	fields = OrderedDict([
		("wordcount",   b"\x0c"),
		("AndXCommand", b"\xff"),
		("reserved",    b"\x00" ),
		("andxoffset",  b"\x00\x00"),
		("maxbuff",     b"\x04\x11"),
		("maxmpx",      b"\x32\x00"),
		("vcnum",       b"\x00\x00"),
		("sessionkey",  b"\x00\x00\x00\x00"),
		("securitybloblength",b"\x4a\x00"),
		("reserved2",    b"\x00\x00\x00\x00"),
		("capabilities", b"\xd4\x00\x00\xa0"),
		("bcc1",         b""),
		("Data",         b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00"),
	])
	def calculate(self):
		self.fields["bcc1"] = struct.pack("<i", len(self.fields["Data"]))[:2]


##Now Lanman
class SMBHeaderLanMan(Packet):
	fields = OrderedDict([
		("proto",      b"\xff\x53\x4d\x42"),
		("cmd",        b"\x72"),
		("error-code", b"\x00\x00\x00\x00" ),
		("flag1",      b"\x08"),
		("flag2",      b"\x01\xc8"),
		("pidhigh",    b"\x00\x00"),
		("signature",  b"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("reserved",   b"\x00\x00"),
		("tid",        b"\x00\x00"),
		("pid",        b"\x3c\x1b"),
		("uid",        b"\x00\x00"),
		("mid",        b"\x00\x00"),
	])

class SMBNegoDataLanMan(Packet):
	fields = OrderedDict([
		("Wordcount", b"\x00"),
		("Bcc",       b"\x54\x00"),
		("BuffType",  b"\x02"),
		("Dialect",   b"NT LM 0.12\x00"),
	])
	def calculate(self):
		CalculateBCC = self.fields["BuffType"]+self.fields["Dialect"]
		self.fields["Bcc"] = struct.pack("<h",len(CalculateBCC))
		
		

def IsSigningEnabled(data): 
	if data[39] == b"\x0f":
		return True
	else:
		return False

def OsNameClientVersion(data):
	length = struct.unpack('<H',data[43:45])[0]
	if length > 255:
		OsVersion, ClientVersion = tuple([e.replace(b'\x00',b'') for e in data[48+length:].split(b'\x00\x00\x00')[:2]])
		return OsVersion, ClientVersion
	if length <= 255:
		OsVersion, ClientVersion = tuple([e.replace(b'\x00',b'') for e in data[47+length:].split(b'\x00\x00\x00')[:2]])
		return OsVersion, ClientVersion


def DomainGrab(soc):
	h = SMBHeaderLanMan(cmd=b"\x72",mid=b"\x01\x00",flag1=b"\x00", flag2=b"\x00\x00")
	n = SMBNegoDataLanMan()
	n.calculate()
	packet0 = bytes(h) + bytes(n)
	buffer0 = longueur(packet0)+packet0
	soc.send(buffer0)
	data = soc.recv(2048)
	if data[8:10] == b"\x72\x00":
		DomainJoined, Hostname = tuple([e.replace(b'\x00',b'') for e in data[81:].split(b'\x00\x00\x00')[:2]])
		if Hostname == '':
			DomainJoined = data[81:110].replace(b'\x00',b'')
			Hostname = data[113:].replace(b'\x00',b'')
		return Hostname.decode('utf-8'), DomainJoined.decode('utf-8')
	else:
		return ('','')


def SmbFinger(soc):	 
	h = SMBHeader(cmd=b"\x72",flag1=b"\x18",flag2=b"\x53\xc8")
	n = SMBNego(Data = bytes(SMBNegoData()))
	n.calculate()
	packet0 = bytes(h) + bytes(n)
	buffer0 = bytes(longueur(packet0))+bytes(packet0)
	soc.send(buffer0)
	data = soc.recv(2048)
	signing = IsSigningEnabled(data)
	if data[8:10] == b"\x72\x00":
		head = SMBHeader(cmd=b"\x73",flag1=b"\x18",flag2=b"\x17\xc8",uid=b"\x00\x00")
		t = SMBSessionFingerData()
		t.calculate() 
		packet0 =  bytes(head)+ bytes(t)
		buffer1 = longueur(packet0) + packet0
		soc.send(buffer1) 
		data = soc.recv(2048)
	if data[8:10] == b"\x73\x16":
		OsVersion, ClientVersion = OsNameClientVersion(data)
		if OsVersion[:5] == b'indow':
			OsVersion = b'W' + OsVersion
		return signing, OsVersion.decode('utf-8'), ClientVersion.decode('utf-8')


