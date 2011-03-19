import httplib
import socket
import urlparse

headers = {
	'Authorization': 'Basic YWRtaW46YWxmcmVzY28='
	}
url = "http://127.0.0.1:7070/alfresco"
pr = urlparse.urlparse(url)
host, port = pr.netloc.split(':')
conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/_vti_inf.html", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to log in")
print "ok, logged in"

sock = open('local.doc')
buf = sock.read()
sock.close()
params = "method=put+document%3a12%2e0%2e0%2e6211&service%5fname=%2falfresco%2fSPP&document=%5bdocument%5fname%3ddocumentLibrary%2flocal%2edoc%3bmeta%5finfo%3d%5bvti%5ftimelastmodified%3bTW%7c11+Mar+2011+16%3a39%3a35+%2d0000%5d%5d&put%5foption=edit&comment=&keep%5fchecked%5fout=false"
body = params + "\n" + buf
headers['Content-Type'] = 'application/x-vermeer-urlencoded'
headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'
conn = httplib.HTTPConnection(host, port)
#conn.set_debuglevel(1)
conn.request("POST", "/alfresco/SPP/_vti_bin/_vti_aut/author.dll", body, headers)
response = conn.getresponse()
print response.status, response.reason
print response.read()
