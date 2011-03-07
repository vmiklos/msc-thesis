import httplib
import base64

host = '192.168.239.3'
port = 7070
headers = {'Authorization' : 'Basic ' + base64.encodestring('admin:alfresco')}

conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/_vti_inf.html", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to log in")

conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/alfresco/SPP/documentLibrary/local.doc", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to read file")

sock = open("local.doc", "w")
sock.write(response.read())
sock.close()
