import json
import xml.dom.minidom
from burp import IBurpExtender
from burp import IParameter
#from burp import IMenuItemHandler
from burp import IContextMenuFactory
from burp import IExtensionHelpers
from burp import IRequestInfo
from javax.swing import JMenuItem
from java.awt.datatransfer import Clipboard,StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent

class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):

	#List of BLACKLISTed HTTP headers, feel free to edit :)
	BLACKLIST = ['Content-Length', 'Host', 'Cookie', 'User-Agent', 'Referer', 'Accept-Encoding', 'Accept-Language', 'Connection', 'Accept', 'Pragma', 'Cache-Control', 'Proxy-Connection']
	OPTS = {}

	def __init__(self):
		self.fMap = { IRequestInfo.CONTENT_TYPE_URL_ENCODED : self.handleURLEncoded,
					IRequestInfo.CONTENT_TYPE_JSON : self.handleJSON,
					IRequestInfo.CONTENT_TYPE_XML: self.handleXML,
					IRequestInfo.CONTENT_TYPE_NONE : self.handleNone,
					IRequestInfo.CONTENT_TYPE_UNKNOWN : self.handleNone }
		self.menuItem = JMenuItem('curlit')
		self.menuItem.addActionListener(self)
					
	def _build(self):
		#Grab first selected message, bail if none

		iRequestInfo = self._helpers.analyzeRequest(self.ctxMenuInvocation.getSelectedMessages()[0])
		self.body = ''.join(map(chr, self.ctxMenuInvocation.getSelectedMessages()[0].getRequest())).split('\r\n\r\n')[1]
		if iRequestInfo is None:
			return 
		
		#Build payload - add your static flags here, like -s or -i
		payload = ('curl -isk ') # % (msg.getUrl()))
		#Turn all headers into dictionary, remove BLACKLISTed ones
		headers = dict(item.split(': ') for item in iRequestInfo.getHeaders()[1:])
		headers = dict( (k,v) for k, v in headers.iteritems() if k not in self.BLACKLIST )
		#print('Whitelisted Headers:\n\t' + '\n\t'.join(headers))

		#om nom cookies
		cookies = [c for c in iRequestInfo.getParameters() if c.getType() == IParameter.PARAM_COOKIE]
		#print('Found Cookies:\n\t' + '\n\t'.join([('%s=%s' % (c.getName(), c.getValue())) for c in cookies]))


		#print('DEBUG: Dumping All Parms')
		#for p in iRequestInfo.getParameters(): print ('\t%s : %s - %d' % (p.getName(), p.getValue(), p.getType()))

		#Set other command line args
		self.OPTS['-X'] = iRequestInfo.getMethod() 
		self.OPTS['-b'] = '; '.join([('%s=%s' % (c.getName(), c.getValue())) for c in cookies])

		#Add all the headers to the payload
		for k,v in headers.iteritems(): payload += '-H \'%s: %s\' \\\n' % (k, v)

		#Invoke handlers to handle content type
		#print('content type: ' + str(iRequestInfo.getContentType()))
		reqType = iRequestInfo.getContentType()
		#print("Content Type Found: %d" % reqType)
		if reqType in self.fMap:
			#print('Invoking %s' % self.fMap[reqType].func_name)
			self.fMap[reqType](iRequestInfo)

		#Add all the OPTS to the payload
		for k,v, in self.OPTS.iteritems(): payload += ('%s \'%s\' \\\n' % (k, v))

		#Append URL to end of payload
		payload += '"%s"' % iRequestInfo.getUrl().toString()
		#Nasty - invocation of some java code to get the string on the clipboard
		s = StringSelection(payload)
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s,s) #put string on clipboard
		print(payload) #print string

		self.OPTS = {}

	def actionPerformed(self, actionEvent):
		self._build()

	def handleXML(self, requestInfo):
		self.OPTS['-d'] = ''.join([line.strip() for line in xml.dom.minidom.parseString(self.body).toprettyxml().split('\n')])
		pass

	def handleJSON(self, requestInfo):
		#No point in using the parameter objects, should just shove the body in
		#Ghetto format by loading string then dumping
		#THIS SHOULD WORK BUT JYTHON DOESNT HAVE THE DAMN JSON MODULE
		self.OPTS['-d'] = json.dumps(json.loads(self.body))

	def handleNone(self, requestInfo):
		if len(self.body) > 0:
			self.OPTS['-d'] = self.body

	def handleMultiPart():
		pass

	def handleAMF():
		pass

	def handleURLEncoded(self, requestInfo):
		self.OPTS['-d'] = '&'.join( [('%s=%s' % (p.getName(), p.getValue())) for p in requestInfo.getParameters() if p.getType() == IParameter.PARAM_BODY])

	def registerExtenderCallbacks(self, callbacks):
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName('curlit')
		callbacks.registerContextMenuFactory(self)
		self.mCallBacks = callbacks
		print('curlit up')
		return
	
	def createMenuItems(self, ctxMenuInvocation):
		self.ctxMenuInvocation = ctxMenuInvocation
		return [self.menuItem]


