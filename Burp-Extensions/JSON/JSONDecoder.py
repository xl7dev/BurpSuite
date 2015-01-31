# Burp Extension - JSON decoder
# Copyright : Michal Melewski <michal.melewski@gmail.com>

# TODO: make sure to remove json garbage (like }];)
 
import json

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		
		callbacks.setExtensionName('JSON Decoder')
		callbacks.registerMessageEditorTabFactory(self)
		
		return
	
	def createNewInstance(self, controller, editable): 
		return JSONDecoderTab(self, controller, editable)
		
class JSONDecoderTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._extender = extender
		self._helpers = extender._helpers
		self._editable = editable
		
		self._txtInput = extender._callbacks.createTextEditor()
		self._txtInput.setEditable(editable)
		
		return
		
	def getTabCaption(self):
		return "JSON Decoder"
		
	def getUiComponent(self):
		return self._txtInput.getComponent()
		
	def isEnabled(self, content, isRequest):	
		if isRequest:
			r = self._helpers.analyzeRequest(content)
		else:
			r = self._helpers.analyzeResponse(content)
			
		for header in r.getHeaders():
			if header.startswith("Content-Type:"): 
				if header.split(":")[1].find("application/json") > 0: 
					return True
				else:
					return False
			
		return False
		
	def setMessage(self, content, isRequest):
		if content is None:
			self._txtInput.setText(None)
			self._txtInput.setEditable(False)
		else:
			if isRequest:
				r = self._helpers.analyzeRequest(content)
			else:
				r = self._helpers.analyzeResponse(content)
			
			msg = content[r.getBodyOffset():].tostring()
		
			pretty_msg = json.dumps(json.loads(msg), sort_keys=True, indent=4)
			
			self._txtInput.setText(pretty_msg)
			self._txtInput.setEditable(self._editable)
			
		self._currentMessage = content
		return
		
	def getMessage(self):	
		if self._txtInput.isTextModified():
			try:
				data = json.dumps(json.loads(self._txtInput.getText()))
			except:
				data = self._helpers.bytesToString(self._txtInput.getText())
				
			# Reconstruct request/response
			r = self._helpers.analyzeRequest(self._currentMessage)
				
			return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
		else:
			return self._currentMessage
		
	def isModified(self):
		return self._txtInput.isTextModified()
		
	def getSelectedData(self):
		return self._txtInput.getSelectedText()
