from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IResponseInfo
import traceback, re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("findip")
        reip1 = re.compile(r'\b10\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', re.IGNORECASE)
        reip2 = re.compile(r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', re.IGNORECASE)
        reip3 = re.compile(r'\b192\.168\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', re.IGNORECASE)
        
        self.reip = []
        self.reip.append(reip1)
        self.reip.append(reip2)
        self.reip.append(reip3)
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 4:       
            global url
            if messageIsRequest:
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(request)
                headers = analyzedRequest.getHeaders()
                host = ''
                post = ''
                get = ''
                url = ''
                for header in headers:
                    #print header
                    if header.startswith("Host:"):
                        host = header.split("Host:")[1]
                    elif header.startswith("POST"):
                        post = " post: "+header.split("POST")[1]
                    elif header.startswith("GET"):
                        get = " get: "+header.split("GET")[1]
                url = host+get+post
                #print url
            if not messageIsRequest:
                ip = []
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                for header in headers:
                    #print 'header:::'+header+':::endheader'
                    for i in range(0,3,1):
                        reip = self.reip[i]
                        for ip1 in reip.findall(header):
                            if ip1 not in ip:
                                ip.append(ip1)
                                print url
                                print ip1+'\n'   
                #cookies = analyzedResponse.getCookies()
                #for cookie in cookies:
                    #print 'cookie:::'+cookie+':::endcookie'
                    #for ip2 in reip.findall(cookie):
                        #print ip2
                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                for i in range(0,3,1):
                    reip = self.reip[i]
                    for ip3 in reip.findall(body_string):
                        if ip3 not in ip:
                            ip.append(ip3)
                            print url
                            print ip3+'\n'   
                    