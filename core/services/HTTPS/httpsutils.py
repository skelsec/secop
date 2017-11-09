import select
import struct
import time
import codecs

def recvall(s, length, timeout=5):
	endtime = time.time() + timeout
	rdata = b''
	remain = length
	while remain > 0:
		rtime = endtime - time.time() 
		if rtime < 0:
			return None
		r, w, e = select.select([s], [], [], 5)
		if s in r:
			data = s.recv(remain)
			# EOF?
			if not data:
				return None
			rdata += data
			remain -= len(data)
	return rdata
		
 
def ssl_recvmsg(s, timeout):
	desc = ''
	hdr = recvall(s, 5, timeout)
	if hdr is None:
		desc = 'Unexpected EOF receiving record header - server closed connection'
		return None, None, None, desc
	typ, ver, ln = struct.unpack('>BHH', hdr)
	pay = recvall(s, ln, 10)
	if pay is None:
		desc =  'Unexpected EOF receiving record payload - server closed connection'
		return None, None, None, desc
	desc = ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
	return typ, ver, pay, desc