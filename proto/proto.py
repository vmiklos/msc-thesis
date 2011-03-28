#!/usr/bin/env python

import base64
import urlparse
import urllib
import urllib2
import cgi
import sys
from sgmllib import SGMLParser
import glob
import os
import time
from xml.dom import minidom
from ntlm import HTTPNtlmAuthHandler

class Handler:
	def __init__(self):
		self.c = 0 # test file counter
		self.headers = {}
		basic_auth = False

		if "--alfresco" in sys.argv:
			self.url = "http://127.0.0.1:7070/alfresco"
			self.user = 'admin'
			self.password = 'alfresco'
			basic_auth = True
		else:
			self.url = "http://vmiklos-sp:80"
			self.user = r'vmiklos-sp\Administrator'
			self.password = 'LaborImage'
		self.action = "open"
		self.openedurl = None
		self.openedfile = None

		if not "--test" in sys.argv:
			self.url = self.ask('url', self.url)
			self.user = self.ask('user', self.user)
			self.password = self.ask('password', self.password)

		pr = urlparse.urlparse(self.url)
		self.host, self.port = pr.netloc.split(':')
		self.path = pr.path
		if basic_auth:
			self.headers = {'Authorization' : 'Basic ' + base64.encodestring('%s:%s' % (self.user, self.password)).strip()}

		# log in
		response = self.urlopen("/_vti_inf.html", headers = self.headers)
		if response.code != 200:
			raise Exception("failed to log in")
		print "ok, logged in"

	def urlopen(self, path, body = None, headers = None):
		url = "http://%s:%s%s" % (self.host, self.port, path)

		# create and install NTLM authentication handler + opener
		passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
		passman.add_password(None, url, self.user, self.password)

		auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
		opener = urllib2.build_opener(auth_NTLM)
		urllib2.install_opener(opener)

		req = urllib2.Request(url, data = body, headers = headers)
		return urllib2.urlopen(req)
	
	def handle(self):
		while True:
			print "possible actions: create-space|cs, open|o, open-older|oo, save|s, save-as|sa, delete|d, list-versions|lv, restore-version|rv, quit|q"
			self.action = self.ask('action', self.action)

			if self.action in ("open", "o"):
				self.handle_open()
			elif self.action in ("save", "s"):
				if self.openedurl:
					self.handle_saveas(self.openedfile, self.openedurl)
				else:
					print "no opened file!"
			elif self.action in ("save-as", "sa"):
				self.handle_saveas()
			elif self.action in ("delete", "d"):
				self.handle_delete()
			elif self.action in ("quit", "q"):
				break
			elif self.action in ("list-versions", "lv"):
				self.handle_list_versions()
			elif self.action in ("open-older", "oo"):
				self.handle_open_older()
			elif self.action in ("restore-version", "rv"):
				self.handle_restore_version()
			elif self.action in ("create-space", "cs"):
				self.handle_create_space()

	def update_file(self, f, mode="a", content=None):
		sock = open(f, mode)
		self.c += 1
		if not content:
			content = self.c
		sock.write("%s\n" % content)
		sock.close()

	def read_file(self, path):
		sock = open(path)
		buf = sock.read()
		sock.close()
		return buf

	def test(self):
		# To test: folder listing, create space

		print "-> testing save-as"
		self.update_file("test.txt", "w")
		try:
			self.handle_delete('/SPP/documentLibrary/test.txt')
		except Exception:
			# we just want to make sure we upload a new file
			pass
		self.handle_saveas("test.txt", "/SPP/documentLibrary/test.txt", None)

		print "-> testing save"
		self.update_file("test.txt")
		self.handle_saveas("test.txt", "/SPP/documentLibrary/test.txt", None)

		print "-> testing save with a comment"
		self.update_file("test.txt")
		self.handle_saveas("test.txt", "/SPP/documentLibrary/test.txt", "test")

		print "-> testing open"
		os.unlink("test.txt")
		self.handle_open("/SPP/documentLibrary/test.txt")

		print "-> testing delete"
		self.handle_delete('/SPP/documentLibrary/test.txt')

		print "-> testing list-versions"
		# put two versions
		self.update_file("test.txt", content="foo")
		self.handle_saveas("test.txt", "/SPP/documentLibrary/test.txt", None)
		self.update_file("test.txt", content="bar")
		self.handle_saveas("test.txt", "/SPP/documentLibrary/test.txt", None)
		assert len(self.handle_list_versions('/SPP/documentLibrary/test.txt')) == 2

		print "-> testing restore-version"
		self.handle_restore_version('/SPP/documentLibrary/test.txt', '1.0')
		self.handle_open("/SPP/documentLibrary/test.txt")
		assert not "bar" in self.read_file("test.txt")

		print "-> testing open-older"
		self.handle_open_older('/SPP/documentLibrary/test.txt', '1.1')
		assert "bar" in self.read_file("test.txt")

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
						id = urllib.unquote(v)
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
			items = path.split('/')
			path_space = "/".join(items[:2])
			path_location = urllib.quote("/".join(items[2:]))
			response = self.urlopen("%s/_vti_bin/owssvr.dll?location=%s&dialogview=FileOpen&FileDialogFilterValue=*.*" % (path_space, path_location), headers = self.headers)
			if response.code != 200:
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

	def handle_open_older(self, remotepath=None, version=None):
		# select remove path
		if not remotepath:
			remotepath, existing = self.select_remote_path()
			remotepath = remotepath.replace(self.path, '')
		print "The following versions are available:"
		versions = self.handle_list_versions(remotepath)
		if not version:
			version = self.ask('version', versions[0].version)
		url = None
		for i in versions:
			if i.version == version:
				url = i.url
				break
		self.handle_open(url.replace('http://%s:%s%s' % (self.host, self.port, self.path), ''))

	def handle_open(self, path=None):
		if not path:
			path, existing = self.select_remote_path()
			print "ok, selected %s" % path
		else:
			path = self.path + path

		response = self.urlopen(urllib.quote(path), headers = self.headers)
		if response.code != 200:
			raise Exception("failed to read file '%s'" % path)

		localpath = path.split('/')[-1]
		sock = open(localpath, "w")
		sock.write(response.read())
		sock.close()
		print "downloaded to %s" % localpath
		self.openedfile = localpath
		self.openedurl = path.replace(self.path, '')

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

	def handle_list_versions(self, remotepath=None):
		class Version:
			def __init__(self, version, date, author, size, comment, url):
				self.version = version.replace('@', '')
				self.date = date
				self.author = author
				self.size = size
				self.comment = comment
				self.url = url.replace('versionStore://', 'versionStore:/')
			def __lt__(self, other):
				key = lambda x: map(int, x.split('.'))
				return key(self.version) < key(other.version)

		headers = self.headers.copy()
		headers['SOAPAction'] = 'http://schemas.microsoft.com/sharepoint/soap/GetVersions'

		# select remove path
		existing = True
		if not remotepath:
			remotepath, existing = self.select_remote_path()
			remotepath = remotepath.replace(self.path, '')
		if not existing:
			raise Exception("can list of versions of existing files only")

		l = remotepath.split('/')
		space = l[1]
		to = '/'.join(l[2:])

		soapheaders = self.headers.copy()
		soapbody = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetVersions xmlns="http://schemas.microsoft.com/sharepoint/soap/">
<fileName>%s</fileName>
</GetVersions>
</soap:Body>
</soap:Envelope>""" % to
		response = self.urlopen("%s/%s/_vti_bin/_vti_aut/lists.asmx" % (self.path, space), soapbody, headers)
		xml = minidom.parseString(response.read())
		versions = []
		for i in xml.getElementsByTagName('result'):
			versions.append(Version(i.getAttribute('version'),
				i.getAttribute('created'),
				i.getAttribute('createdBy'),
				i.getAttribute('size'),
				i.getAttribute('comments'),
				i.getAttribute('url')))
		versions.sort(reverse=True)
		print "No.\tModified\tModified By\tSize\tComments"
		for i in versions:
			print "\t".join([i.version, i.date, i.author, i.size, i.comment])
		return versions

	def handle_create_space(self):
		def unescape(s):
			s = s.replace("&lt;", "<")
			s = s.replace("&gt;", ">")
			# this has to be last:
			s = s.replace("&amp;", "&")
			return s

		headers = self.headers.copy()
		headers['SOAPAction'] = 'http://schemas.microsoft.com/sharepoint/soap/dws/CreateDws'
		headers['Content-Type'] = 'text/xml; charset=utf-8'

		space = self.ask('name', '')
		soapbody = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<CreateDws xmlns="http://schemas.microsoft.com/sharepoint/soap/dws/">
<name/>
<users/>
<title>%s</title>
<documents/>
</CreateDws>
</s:Body>
</s:Envelope>""" % space
		# no space in the url, we're creating a new one!
		response = self.urlopen("%s/_vti_bin/dws.asmx" % self.path, soapbody, headers)
		if response.code != 200:
			raise Exception("failed to create space, http error %s" % response.code)
		ret = response.read()
		try:
			xml = minidom.parseString(ret)
			inner = unescape(xml.getElementsByTagName('CreateDwsResult')[0].firstChild.toxml())
			xml = minidom.parseString(inner)
			url = xml.getElementsByTagName('Url')[0].firstChild.toxml()
			print 'created space at %s' % url
		except Exception:
			print "response is invalid xml: '%s'" % ret

	def handle_restore_version(self, remotepath=None, version=None):
		headers = self.headers.copy()
		headers['SOAPAction'] = 'http://schemas.microsoft.com/sharepoint/soap/RestoreVersion'

		# select remove path
		if not remotepath:
			remotepath, existing = self.select_remote_path()
			remotepath = remotepath.replace(self.path, '')
			if not existing:
				raise Exception("can restore older version of existing files only")

		l = remotepath.split('/')
		space = l[1]
		to = '/'.join(l[2:])

		# select version
		print "The following versions are available:"
		versions = self.handle_list_versions(remotepath)
		if not version:
			version = self.ask('version', versions[0].version)

		soapheaders = self.headers.copy()
		soapbody = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<RestoreVersion xmlns="http://schemas.microsoft.com/sharepoint/soap/">
<fileName>%s</fileName>
<fileVersion>%s</fileVersion>
</RestoreVersion>
</soap:Body>
</soap:Envelope>""" % (to, version)
		response = self.urlopen("%s/%s/_vti_bin/_vti_aut/versions.asmx" % (self.path, space), soapbody, headers)
		xml = minidom.parseString(response.read())
		if len(versions) + 1 != len(xml.getElementsByTagName("result")):
			raise Exception("failed to create a new version")

	def urlencode(self, l):
		"""a version of urllib.urlencode that preserves ordering"""
		ret = []
		for k, v in l:
			ret.append("%s=%s" % (urllib.quote(k), urllib.quote(v)))
		return "&".join(ret)

	def handle_delete(self, remotepath=None):
		headers = self.headers.copy()
		headers['Content-Type'] = 'application/x-vermeer-urlencoded'
		headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'

		# select remote path
		if not remotepath:
			remotepath, existing = self.select_remote_path()
			remotepath = remotepath.replace(self.path, '')

			if not existing:
				raise Exception("non-existing document")
		l = remotepath.split('/')
		space = l[1]
		to = '/'.join(l[2:])

		# run 'remove documents'
		params = self.urlencode([
			('method','remove documents:12.0.0.6211'),
			('service_name','%s/%s' % (self.path, space)),
			('url_list','[%s]' % to)
			])
		response = self.urlopen("%s/%s/_vti_bin/_vti_aut/author.dll" % (self.path, space), params+"\n", headers)
		html = response.read()
		if "successfully removed documents" not in html:
			raise Exception("failed to remove document: '%s'" % html)
		print "deleted %s" % remotepath

	def get_lastmod(self, existing, space, to, headers):
		if existing:
			# run getDocsMetaInfo
			params = self.urlencode([
				('method','getDocsMetaInfo:12.0.0.6211'),
				('url_list','[http://%s:%s%s/%s/%s]' % (self.host, self.port, self.path, space, to)),
				('listHiddenDocs','false'),
				('listLinkInfo','false')
				])
			response = self.urlopen("%s/%s/_vti_bin/_vti_aut/author.dll" % (self.path, space), params+"\n", headers)
			html = response.read()
			if "failedUrls" in html:
				existing = False
			else:
				lastmod = self.parselastmod(html).split('|')[1]
		if not existing:
			lastmod = time.strftime("%d %b %Y %H:%M:%S -0000")
		return lastmod

	def handle_saveas(self, fro=None, remotepath=None, comment=False):
		headers = self.headers.copy()
		headers['Content-Type'] = 'application/x-vermeer-urlencoded'
		headers['X-Vermeer-Content-Type'] = 'application/x-vermeer-urlencoded'

		print "selecting local source"
		localpath = os.getcwd() + "/"

		if not fro:
			# select local path
			names = glob.glob("*")
			print "available items:"
			for i in names:
				if os.path.isdir(i):
					continue
				print "%s\tfile" % (i.split('/')[-1])
			item = self.ask('item', names[0].split('/')[-1])
			fro = localpath + item
		print "ok, selected local source: %s" % fro

		if not remotepath:
			# select remove path
			remotepath, existing = self.select_remote_path()
			remotepath = remotepath.replace(self.path, '')
		else:
			existing = True
		l = remotepath.split('/')
		space = l[1]
		to = '/'.join(l[2:])

		if comment == False:
			comment = self.ask('comment', None)

		if comment:
			# check out the document
			lastmod = self.get_lastmod(existing, space, to, headers)
			soapheaders = self.headers.copy()
			soapheaders['SOAPAction'] = 'http://schemas.microsoft.com/sharepoint/soap/CheckOutFile'
			soapbody = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<CheckOutFile xmlns="http://schemas.microsoft.com/sharepoint/soap/">
<pageUrl>http://%s:%s%s/%s/%s</pageUrl><checkoutToLocal>true</checkoutToLocal><lastmodified>%s</lastmodified></CheckOutFile>
</soap:Body>
</soap:Envelope>""" % (self.host, self.port, self.path, space, to, lastmod)
			response = self.urlopen("%s/%s/_vti_bin/_vti_aut/lists.asmx" % (self.path, space), soapbody, soapheaders)
			xml = minidom.parseString(response.read())
			if xml.getElementsByTagName('CheckOutFileResult')[0].firstChild.toxml() != 'true':
				raise Exception("failed to check out document")

		# run 'put document'
		lastmod = self.get_lastmod(existing, space, to, headers)
		sock = open(fro)
		buf = sock.read()
		sock.close()

		params = self.urlencode([
			('method', 'put document:12.0.0.6211'),
			('service_name', '%s/%s' % (self.path, space)),
			('document', '[document_name=%s;meta_info=[vti_timelastmodified;TW|%s]]' % (to, lastmod)),
			('put_option', 'edit'),
			('comment', ''),
			('keep_checked_out', 'false')
			])
		body = params + "\n" + buf
		response = self.urlopen("%s/%s/_vti_bin/_vti_aut/author.dll" % (self.path, space), body, headers)
		ret = response.read()
		failed = None
		if "successfully put document" not in ret:
			failed = ret

		if comment:
			# check in the document
			soapheaders = self.headers.copy()
			soapheaders['SOAPAction'] = 'http://schemas.microsoft.com/sharepoint/soap/CheckInFile'
			soapbody = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<CheckInFile xmlns="http://schemas.microsoft.com/sharepoint/soap/">
<pageUrl>http://%s:%s%s/%s/%s</pageUrl><comment>%s</comment><CheckinType>0</CheckinType></CheckInFile>
</soap:Body>
</soap:Envelope>""" % (self.host, self.port, self.path, space, to, cgi.escape(comment))
			response = self.urlopen("%s/%s/_vti_bin/_vti_aut/lists.asmx" % (self.path, space), soapbody, soapheaders)
			xml = minidom.parseString(response.read())
			if xml.getElementsByTagName('CheckInFileResult')[0].firstChild.toxml() != 'true':
				raise Exception("failed to check in document")
		if failed:
			# don't raise it earlier, so we check in even if put failed
			raise Exception("failed to put document: '%s'" % failed)

		print "uploaded to %s" % remotepath

if __name__ == "__main__":
	h = Handler()
	if not "--test" in sys.argv:
		h.handle()
	else:
		h.test()
