import httplib
import base64
import urlparse
import sys
from sgmllib import SGMLParser

def ask(k, v):
	line = None
	try:
		if sys.argv[1] == "-y":
			line = v
	except IndexError:
		pass
	if not line:
		sys.stdout.write('%s [%s] ' % (k, v))
		line = sys.stdin.readline().strip()
	if not len(line):
		line = v
	return line

def parsehtml(page):
	class HTMLParser(SGMLParser):
		def reset(self):
			SGMLParser.reset(self)
			self.items = {}
		def start_tr(self, attrs):
			fileattribute = None
			id = None
			for k, v in attrs:
				if k == "fileattribute":
					fileattribute = v
				elif k == "id":
					id = v
			if fileattribute and id:
				self.items[id] = fileattribute
	parser = HTMLParser()
	parser.reset()
	parser.feed(page)
	parser.close
	return parser.items

# defaults
url = "http://127.0.0.1:7070/alfresco"
user = 'admin'
password = 'alfresco'

url = ask('url', url)
user = ask('user', user)
password = ask('password', password)

pr = urlparse.urlparse(url)
host, port = pr.netloc.split(':')
path = pr.path
headers = {'Authorization' : 'Basic ' + base64.encodestring('admin:alfresco')}

# log in
conn = httplib.HTTPConnection(host, port)
conn.request("GET", "/_vti_inf.html", headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to log in")
print "ok, logged in"

# list folders
while True:
	conn = httplib.HTTPConnection(host, port)
	conn.request("GET", "%s/_vti_bin/owssvr.dll?location=&dialogview=FileOpen&FileDialogFilterValue=*.*" % path, headers = headers)
	response = conn.getresponse()
	if response.status != 200:
		raise Exception("failed to read dir '%s/'" % path)
	# extract the list of folders from the html response
	html = response.read()
	itemlist = parsehtml(html)
	print "available items:"
	names = sorted(itemlist.keys())
	for n in names:
		t = itemlist[n]
		print "%s\t%s" % (n.split('/')[-1], t)
	item = ask('item', names[0].split('/')[-1])
	itemurl = "/".join(names[0].split('/')[:-1]) + "/" + item
	path += "/" + item
	if itemlist[itemurl] == "file":
		break
print "ok, selected %s" % path

conn = httplib.HTTPConnection(host, port)
conn.request("GET", path, headers = headers)
response = conn.getresponse()
if response.status != 200:
	raise Exception("failed to read file '%s'" % path)

localpath = path.split('/')[-1]
sock = open(localpath, "w")
sock.write(response.read())
sock.close()
print "saved to %s" % localpath
