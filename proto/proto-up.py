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
pr = urlparse.urlparse(url)
host, port = pr.netloc.split(':')
conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/_vti_inf.html", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to log in")
print "ok, logged in"

print "running getDocsMetaInfo..."
body = "method=getDocsMetaInfo%3a12%2e0%2e0%2e6211&url%5flist=%5bhttp%3a%2f%2f127%2e0%2e0%2e1%3a7070%2falfresco%2fSPP%2fdocumentLibrary%2flocal%2edoc%3bhttp%3a%2f%2f127%2e0%2e0%2e1%3a7070%2falfresco%2fSPP%2fdocumentLibrary%5d&listHiddenDocs=false&listLinkInfo=false\n"
conn = httplib.HTTPConnection(host, port)
conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
response = conn.getresponse()
html = response.read()
if "failedUrls" in html:
	raise Exception("failed to get meta info")
lastmod = parsehtml(html).split('|')[1]

sock = open('local.doc')
buf = sock.read()
sock.close()

params = {
	'method': 'put document:12.0.0.6211',
	'service_name': '/alfresco/SPP',
	'document': '[document_name=documentLibrary/local.doc;meta_info=[vti_timelastmodified;TW|%s]]' % lastmod,
	'put_option': 'edit',
	'comment': '',
	'keep_checked_out': 'false'
	}

print "running 'put document'..."
body = urllib.urlencode(params) + "\n" + buf
headers['Content-Type'] = 'application/x-vermeer-urlencoded'
headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'
conn = httplib.HTTPConnection(host, port)
conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
response = conn.getresponse()
if "successfully put document" not in response.read():
	raise Exception("failed to put document")
