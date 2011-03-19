import httplib
import urllib
import socket
import urlparse
import sys
import time

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

#print "running 'open service'..." # #4
#body = "method=open+service%3a12%2e0%2e0%2e6211&service%5fname=%2falfresco%2fSPP\n"
#conn = httplib.HTTPConnection(host, port)
#conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
#response = conn.getresponse()
#print response.status, response.reason
#print response.read()

print "running getDocsMetaInfo..." # #6
body = "method=getDocsMetaInfo%3a12%2e0%2e0%2e6211&url%5flist=%5bhttp%3a%2f%2f192%2e168%2e152%2e1%3a7070%2falfresco%2fSPP%2fdocumentLibrary%2flocal%2edoc%3bhttp%3a%2f%2f192%2e168%2e152%2e1%3a7070%2falfresco%2fSPP%2fdocumentLibrary%5d&listHiddenDocs=false&listLinkInfo=false\n"
conn = httplib.HTTPConnection(host, port)
conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
response = conn.getresponse()
print response.status, response.reason
print response.read()

#print "running 'checkout document'..." # #8
#body = "method=checkout+document%3a12%2e0%2e0%2e6211&service%5fname=%2falfresco%2fSPP&document%5fname=documentLibrary%2flocal%2edoc&force=0&timeout=10\n"
#conn = httplib.HTTPConnection(host, port)
#conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
#response = conn.getresponse()
#print response.status, response.reason
#print response.read()

#print "running 'uncheckout document'..."
#body = "method=uncheckout+document%3a12%2e0%2e0%2e6211&service%5fname=%2falfresco%2fSPP&document%5fname=documentLibrary%2flocal%2edoc&force=false&rlsshortterm=true\n"
#conn = httplib.HTTPConnection(host, port)
#conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
#response = conn.getresponse()
#print response.status, response.reason
#print response.read()

sock = open('local.doc')
buf = sock.read()
sock.close()

params = {
	'method': 'put document:12.0.0.6211',
	'service_name': '/alfresco/SPP',
	'document': '[document_name=documentLibrary/local.doc;meta_info=[vti_timelastmodified;TW|%s]]' % time.strftime("%d %b %Y %H:%M:%S -0000"),
	'put_option': 'edit',
	'comment': '',
	'keep_checked_out': 'false'
	}

print "running 'put document'..."
#params = "method=put+document%3a12%2e0%2e0%2e6211&service%5fname=%2falfresco%2fSPP&document=%5bdocument%5fname%3ddocumentLibrary%2flocal%2edoc%3bmeta%5finfo%3d%5bvti%5ftimelastmodified%3bTW%7c11+Mar+2011+16%3a39%3a35+%2d0000%5d%5d&put%5foption=edit&comment=&keep%5fchecked%5fout=false"
body = urllib.urlencode(params) + "\n" + buf
headers['Content-Type'] = 'application/x-vermeer-urlencoded'
headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'
conn = httplib.HTTPConnection(host, port)
#conn.set_debuglevel(1)
conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
response = conn.getresponse()
print response.status, response.reason
print response.read()
