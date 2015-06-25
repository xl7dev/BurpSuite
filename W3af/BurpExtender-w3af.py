# BurpExtender.py - use w3af plugins (http://w3af.sourceforge.net) with Burp Suite
# Author: David Robert david@ombrepixel.com
# Version 0.1 09/09/2010

# ========= You need to edit below =============

# Here you define the name of the plugins you want (category.plugin)
plugins = ['grep.domXss',  'grep.error500', 'grep.errorPages', 'grep.feeds',  
           'grep.fileUpload','grep.hashFind', 'grep.httpAuthDetect',
           'grep.privateIP', 'grep.ssn', 'grep.strangeHeaders',
           'grep.strangeHTTPCode', 'grep.strangeReason', 'grep.svnUsers',
           'grep.wsdlGreper']

# Here you should define the location of your w3af installation
w3afPath="C:\\local\\Program Files\\w3af\\w3af"
# Example for Unix "/usr/local/w3af/w3af"
# ========= You need to edit above =============

import sys
import urllib2
sys.path.append(w3afPath)

# Burp Suite related
from burp import IBurpExtender

# w3af srelated
import core.data.kb.knowledgeBase as kb
from core.data.parsers.urlParser import getPathQs
from core.data.url.httpResponse import httpResponse
from core.controllers.misc.factory import factory
from core.controllers.w3afException import w3afException


class BurpExtender(IBurpExtender):
    
    #  List of instanciated plugins objects
    loadedPlugins=[]
    
    def __init__(self):
        # Instanciate the w3af plugins
        print "loading w3af plugins"
        print "--------------------"
        for pluginName in plugins:
            try:
                print "Loading %s... " % pluginName ,
                plugin = factory('plugins.' + pluginName)
                self.loadedPlugins.append(plugin)
                print "%s%s" % (' '*(30-len(pluginName)),  "Success")              
            except w3afException, e:
                #print str(e)  # This needs to be uncommented to see what is the exception
                print "%s%s" % (' '*(30-len(pluginName)),  "Failed")
        print "\nFailed plugins are ignored and won't be proceeded. You can uncomment"
        print "the line 'print str(e)' in the module to see the actual exception"

    def processProxyMessage(self,messageReference, messageIsRequest, remoteHost,
                      remotePort, serviceIsHttps, httpMethod, url, resourceType, 
                      statusCode, responseContentType, message, interceptAction):
        curl = "%s://%s:%d%s" % ("https" if serviceIsHttps else "http", \
              remoteHost, remotePort, url)
        headers = self.mCallBacks.getHeaders(message)
        if messageIsRequest:
            # Need to build a urllib2 Request object
            wRequest=RequestMessage(message, headers)
            request=urllib2.Request(curl,wRequest.data,wRequest.headers)
            evasion = False
            for plugin in self.loadedPlugins:
                if plugin.getType() == "evasion":
                    evasion = True
                    request=self.processEvasionPlugin(plugin, request)
                if evasion: return self.createBurpRequest(request,httpMethod)    
        elif responseContentType and responseContentType.count("text"):
            # Few objets needed by w3af httpResponse object
            wMessage = Message(message, headers)
            response = httpResponse(int(statusCode), wMessage.message, \
                wMessage.headers, curl, curl, wMessage.msg, id=messageReference+1)
            for plugin in self.loadedPlugins:
                if plugin.getType() == "grep":
                    self.processGrepPlugin(plugin, response)
        return message

    def processEvasionPlugin(self,plugin,request):
        pluginName=plugin.__class__.__name__
        try:
            new_req=plugin.modifyRequest(request)
            return new_req
        except:
            print "ignoring issue with plugin: evasion." + pluginName
            return None
            
    def processGrepPlugin(self,plugin,response):
        pluginName=plugin.__class__.__name__
        try:
            # I am assuming that grep plugins don't look at requests, it is not the case
            # for one of them so it will be caught as an exception
            plugin.grep(None,response)
        except:
            print "ignoring issue with plugin: grep." + pluginName
        # Retrieve report
        kbData=kb.kb.getData(pluginName)
        if kbData and kbData.has_key(pluginName):
            for vuln in kbData[pluginName]: 
                if (vuln.getURL()==response.getURL()):
                    desc = "%s: %s" % (pluginName, vuln.getDesc())
                    print "Issue found with w3af plugin " + desc
                    self.mCallBacks.issueAlert("w3af " + desc)
    
    def createBurpRequest(self,request,method):
        """Create a Burp formated request from 
        a urllib2 request object
        """
        new_req=[]
        path = getPathQs(request.get_full_url())
        new_req.append(method + ' ' + path + ' ' + 'HTTP/1.1')
        # Unfortunatly a dict is not sorted so random order. We need to work with urllib2 though
        # with w3af, so I may need to find a way to fix this
        for key in request.headers.keys():
            new_req.append("%s: %s" % (key, request.headers[key]))
        if method == 'POST':
            new_req.append('')
            new_req.append(request.get_data())
        new_req = '\r\n'.join(new_req) + '\r\n\r\n'
        return new_req
    
    def registerExtenderCallbacks(self, callbacks):
        self.mCallBacks = callbacks

class Message:
    """Create a number of attributes useful
    for creating w3af objects"""
    
    def __init__(self, message, headers):
         # Create a headers dictionary
        self.message = message.tostring()
        self.headers = {}
        for line in headers[1:]:
            try:
                index=line.index(':')
                self.headers[line[:index]]=line[index+1:].strip()
            except:
                pass # We will just ignore malformed headers
        # Extract return message (eg. OK, NOT MODIFIED.)
        self.msg=' '.join(headers[0].split(' ')[2:])
        
class RequestMessage(Message):
    """Create a number of attributes useful
    for creating w3af objects, add attributes
    related to requests"""
    
    def __init__(self, message, headers):
        Message.__init__(self, message, headers)
        messageLines = self.message.splitlines()    
        # Extract post data as string
        try:
            index=messageLines.index('')
            if index == len(messageLines)-1: self.data = None
            else: self.data=''.join(messageLines[index+1:])
        except:
            self.data=None
        
