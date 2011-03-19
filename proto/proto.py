import httplib
import base64
import urlparse
import sys
from sgmllib import SGMLParser

class Handler:
	def __init__(self):
		# defaults
		self.url = "http://127.0.0.1:7070/alfresco"
		self.user = 'admin'
		self.password = 'alfresco'
		self.action = "open"
		self.openpath = None

		self.url = self.ask('url', self.url)
		self.user = self.ask('user', self.user)
		self.password = self.ask('password', self.password)

		pr = urlparse.urlparse(self.url)
		self.host, self.port = pr.netloc.split(':')
		self.path = pr.path
		self.headers = {'Authorization' : 'Basic ' + base64.encodestring('%s:%s' % (self.user, self.password))}

		# log in
		conn = httplib.HTTPConnection(self.host, self.port)
		conn.request("GET", "/_vti_inf.html", headers = self.headers)
		response = conn.getresponse()
		if response.status != 200:
			raise Exception("failed to log in")
		print "ok, logged in"
	
	def handle(self):
		while True:
			print "possible actions: open, save, exit"
			self.action = self.ask('action', self.action)

			if self.action == "open":
				self.handle_open()
			elif self.action == "save":
				self.handle_save()
			elif self.action in ("exit", "q"):
				break

	def ask(self, k, v):
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

	def parsefileopen(self, page):
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
		parser.close()
		return parser.items

	def handle_open(self):
		path = self.path
		# list folders
		while True:
			conn = httplib.HTTPConnection(self.host, self.port)
			conn.request("GET", "%s/_vti_bin/owssvr.dll?location=&dialogview=FileOpen&FileDialogFilterValue=*.*" % path, headers = self.headers)
			response = conn.getresponse()
			if response.status != 200:
				raise Exception("failed to read dir '%s/'" % path)
			# extract the list of folders from the html response
			html = response.read()
			itemlist = self.parsefileopen(html)
			print "available items:"
			names = sorted(itemlist.keys())
			for n in names:
				t = itemlist[n]
				print "%s\t%s" % (n.split('/')[-1], t)
			item = self.ask('item', names[0].split('/')[-1])
			itemurl = "/".join(names[0].split('/')[:-1]) + "/" + item
			path += "/" + item
			if itemlist[itemurl] == "file":
				break
		print "ok, selected %s" % path
		# so that we can do a simple save later
		self.openpath = path

		conn = httplib.HTTPConnection(self.host, self.port)
		conn.request("GET", path, headers = self.headers)
		response = conn.getresponse()
		if response.status != 200:
			raise Exception("failed to read file '%s'" % path)

		localpath = path.split('/')[-1]
		sock = open(localpath, "w")
		sock.write(response.read())
		sock.close()
		print "saved to %s" % localpath

	def handle_save(self):
		if not self.openpath:
			print "have to open first!"
			return
		path = self.openpath

		localpath = path.split('/')[-1]
		print "uploading '%s' to '%s'" % (localpath, path)

if __name__ == "__main__":
	h = Handler()
	h.handle()
