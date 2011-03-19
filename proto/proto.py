import httplib
import base64
import urlparse
import urllib
import sys
from sgmllib import SGMLParser
import glob
import os
import time

class Handler:
	def __init__(self):
		# defaults
		self.url = "http://127.0.0.1:7070/alfresco"
		self.user = 'admin'
		self.password = 'alfresco'
		self.action = "open"

		self.url = self.ask('url', self.url)
		self.user = self.ask('user', self.user)
		self.password = self.ask('password', self.password)

		pr = urlparse.urlparse(self.url)
		self.host, self.port = pr.netloc.split(':')
		self.path = pr.path
		self.headers = {'Authorization' : 'Basic ' + base64.encodestring('%s:%s' % (self.user, self.password)).strip()}

		# log in
		conn = httplib.HTTPConnection(self.host, self.port)
		conn.request("GET", "/_vti_inf.html", headers = self.headers)
		response = conn.getresponse()
		if response.status != 200:
			raise Exception("failed to log in")
		print "ok, logged in"
	
	def handle(self):
		while True:
			print "possible actions: open, saveas, exit"
			self.action = self.ask('action', self.action)

			if self.action == "open":
				self.handle_open()
			elif self.action == "saveas":
				self.handle_saveas()
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
		class FileopenParser(SGMLParser):
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
		parser = FileopenParser()
		parser.reset()
		parser.feed(page)
		parser.close()
		return parser.items

	def select_remote_path(self):
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
			try:
				if itemlist[itemurl] == "file":
					break
			except KeyError:
				return path, False
		return path, True

	def handle_open(self):
		path, existing = self.select_remote_path()
		print "ok, selected %s" % path

		conn = httplib.HTTPConnection(self.host, self.port)
		conn.request("GET", path, headers = self.headers)
		response = conn.getresponse()
		if response.status != 200:
			raise Exception("failed to read file '%s'" % path)

		localpath = path.split('/')[-1]
		sock = open(localpath, "w")
		sock.write(response.read())
		sock.close()
		print "downloaded to %s" % localpath

	def parselastmod(self, page):
		class LastmodParser(SGMLParser):
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
		parser = LastmodParser()
		parser.reset()
		parser.feed(page)
		parser.close()
		return parser.lastmod

	def handle_saveas(self):
		headers = self.headers.copy()
		headers['Content-Type'] = 'application/x-vermeer-urlencoded'
		headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'

		print "selecting local source"
		localpath = os.getcwd() + "/"

		# select local path
		names = glob.glob("*")
		print "available items:"
		for i in names:
			if os.path.isdir(i):
				continue
			print "%s\tfile" % (i.split('/')[-1])
		item = self.ask('item', names[0].split('/')[-1])
		fro = localpath + item
		print "ok, selected local source: %s" % localpath

		# select remove path
		remotepath, existing = self.select_remote_path()
		remotepath = remotepath.replace(self.path, '')
		l = remotepath.split('/')
		space = l[1]
		to = '/'.join(l[2:])

		if existing:
			# run getDocsMetaInfo
			params = {
				'method':'getDocsMetaInfo:12.0.0.6211',
				'url_list':'[http://%s:%s%s/%s/%s]' % (self.host, self.port, self.path, space, to),
				'listHiddenDocs':'false',
				'listLinkInfo':'false'
				}
			conn = httplib.HTTPConnection(self.host, self.port)
			conn.request("POST", "%s/%s/_vti_bin/_vti_aut/author.dll" % (self.path, space), urllib.urlencode(params)+"\n", headers)
			response = conn.getresponse()
			html = response.read()
			if "failedUrls" in html:
				raise Exception("failed to get meta info")
			lastmod = self.parselastmod(html).split('|')[1]
		else:
			lastmod = time.strftime("%d %b %Y %H:%M:%S -0000")

		# run 'put document'
		sock = open(fro)
		buf = sock.read()
		sock.close()

		params = {
			'method': 'put document:12.0.0.6211',
			'service_name': '%s/%s' % (self.path, space),
			'document': '[document_name=%s;meta_info=[vti_timelastmodified;TW|%s]]' % (to, lastmod),
			'put_option': 'edit',
			'comment': '',
			'keep_checked_out': 'false'
			}
		body = urllib.urlencode(params) + "\n" + buf
		conn = httplib.HTTPConnection(self.host, self.port)
		conn.request("POST", "%s/%s/_vti_bin/_vti_aut/author.dll" % (self.path, space), body, headers)
		response = conn.getresponse()
		if "successfully put document" not in response.read():
			raise Exception("failed to put document")
		print "uploaded to %s" % remotepath

if __name__ == "__main__":
	h = Handler()
	h.handle()
