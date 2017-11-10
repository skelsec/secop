def getURL(target, isSSL):
	url = 'http://'
	if isSSL:
		url = 'https://'
	return '%s%s:%d/' % (url, target.ip, target.port)