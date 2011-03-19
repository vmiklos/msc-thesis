import httplib
import urllib
import socket
import urlparse
import sys
import time
from sgmllib import SGMLParser

def parsehtml(page):
	class HTMLParser(SGMLParser):
		def reset(self):
			SGMLParser.reset(self)
			self.lastmod = None
			self.nextmod = False
		def handle_data(self, text):
			if text.strip() == "vti_timelastmodified":
				self.nextmod = True
			elif self.nextmod and not self.lastmod:
				self.nextmod = False
				self.lastmod = text.strip()
	parser = HTMLParser()
	parser.reset()
	parser.feed(page)
	parser.close()
	return parser.lastmod

headers = {
	'Authorization': 'Basic YWRtaW46YWxmcmVzY28='
	}
headers['Content-Type'] = 'application/x-vermeer-urlencoded'
headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'

url = "http://127.0.0.1:7070/alfresco"
fro = "local.doc"
space = "SPP"
to = "documentLibrary/local.doc"

pr = urlparse.urlparse(url)
host, port = pr.netloc.split(':')
urlpath = pr.path
conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/_vti_inf.html", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to log in")
print "ok, logged in"

print "running getDocsMetaInfo..."
params = {
		'method':'getDocsMetaInfo:12.0.0.6211',
		'url_list':'[http://%s:%s%s/%s/%s]' % (host, port, urlpath, space, to),
		'listHiddenDocs':'false',
		'listLinkInfo':'false'
	}
conn = httplib.HTTPConnection(host, port)
conn.request("POST", "%s/%s/_vti_bin/_vti_aut/author.dll" % (urlpath, space), urllib.urlencode(params)+"\n", headers)
response = conn.getresponse()
html = response.read()
if "failedUrls" in html:
	raise Exception("failed to get meta info")
lastmod = parsehtml(html).split('|')[1]

sock = open(fro)
buf = sock.read()
sock.close()

params = {
	'method': 'put document:12.0.0.6211',
	'service_name': '%s/%s' % (urlpath, space),
	'document': '[document_name=%s;meta_info=[vti_timelastmodified;TW|%s]]' % (to, lastmod),
	'put_option': 'edit',
	'comment': '',
	'keep_checked_out': 'false'
	}

print "running 'put document'..."
body = urllib.urlencode(params) + "\n" + buf
headers['Content-Type'] = 'application/x-vermeer-urlencoded'
headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'
conn = httplib.HTTPConnection(host, port)
conn.request("POST", "%s/%s/_vti_bin/_vti_aut/author.dll" % (urlpath, space), body, headers)
response = conn.getresponse()
if "successfully put document" not in response.read():
	raise Exception("failed to put document")
