from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerCheck
from burp import IParameter
from burp import IHttpRequestResponse
from burp import IScanIssue
import string
from  array import array

class BurpExtender(IBurpExtender, IScannerInsertionPointProvider, IScannerCheck):
    
    
    def	registerExtenderCallbacks(self, callbacks):
    
        self._helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        
        callbacks.setExtensionName("Passive XSS detector")
        
        callbacks.registerScannerCheck(self)
        
        return


    def consolidateDuplicateIssues(self,existingIssue, newIssue):
      if (existingIssue.getIssueName() == newIssue.getIssueName() ):
        return -1
      else:
        return 0
      

    def doPassiveScan(self, baseRequestResponse):
      params = self.getParams(baseRequestResponse.getRequest() )
      if len(params) > 0:
        (reflectParams,matches) = self.findMatches(baseRequestResponse, params) 
        issues = []
        if len(matches) > 0:
          issues.append(CustomScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                        [self.callbacks.applyMarkers(baseRequestResponse, None, matches )],
                        "Possible XSS",
                        reflectParams,
                        "Information"))
          return issues
      return None

    # finds input parameters we can search for later
    def getParams(self,request): 
      info = self._helpers.analyzeRequest(request)

      params = info.getParameters()
      return params

    #search for literal matches to the input parameters 
    def findMatches(self,requestResponse,params):
      matches = []
      reflectParams = []
      for param in params:
        argument =  self._helpers.urlDecode(param.getValue())
        responseLength = len(requestResponse.getResponse())
        if len(argument) > 3:
            start = 0 
            start = self._helpers.indexOf(requestResponse.getResponse(),argument, True, start,responseLength)
            if start < 0:
              # not found
              break
            matches.append( array('i', [start, start + len(argument) ]) )  # Jython wants a typed array
            reflectParams.append(param.getName())
      reflectParams = set(reflectParams)
      return (list(reflectParams),matches)

## Implement the IScanIssue interface
class CustomScanIssue(IScanIssue):
  def __init__(self, httpservice, url, requestresponsearray, name, params, severity, ):
    self.purl = url
    self.phttpservice = httpservice
    self.prequestresponsearray = requestresponsearray
    self.pname = name
    self.pparams = params
    self.pseverity = severity

  def getUrl(self):
    return self.purl

  def getHttpMessages(self):
    return self.prequestresponsearray

  def getHttpService(self):
    return self.phttpservice 
  
  def getParams(self):
    return self.pparams 

  def setParams(self,params):
    self.pparams = params

  def getRemediationDetail(self):
    return None

  def getIssueDetail(self):
    return "The following params were reflected: %s"% "<br>* ".join(self.pparams)

  def getIssueBackground(self):
    return None

  def getRemediationBackground(self):
    return None

  def getIssueType(self):
    return 0

  def getIssueName(self):
    return self.pname

  def getSeverity(self):
    return self.pseverity

  def getConfidence(self):
    return "Certain"
