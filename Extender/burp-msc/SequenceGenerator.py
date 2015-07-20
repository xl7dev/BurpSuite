import sys
import re
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation

# Java imports
from javax.swing import JMenuItem
from java.util import List, ArrayList
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import JPanel

##Read configs?

class Message():
  def __init__(self):
    self.url = ""
    self.host = ""
    self.body = ""
    self.data = []
  def __str__(self):
    print "printing message"
    print self.url

##Read configs?

class Message():
  def __init__(self):
    self.url = ""
    self.host = ""
    self.body = ""
    self.data = []
  def __str__(self):
    print "printing message"
    print self.url
    print self.host
    print self.body
    print self.data

class BurpExtender(IBurpExtender, IContextMenuFactory):
  message_list = ArrayList();
  #messages = []
  messages = []

  def getFilePath(self):
      chooseFile = JFileChooser()
      panel = JPanel()
      ret = chooseFile.showDialog(panel, "Choose output file (*.msc)")
      if ret == JFileChooser.APPROVE_OPTION: 
        file=chooseFile.getSelectedFile()
      return file 

  def makeMSC(self):
    tmp=["Client"]
    out='''
msc {
  hscale = "2";

'''
    #Grab the hosts
    for message in self.messages:
      if (message["request"]["host"] not in tmp):
        tmp.append(message["request"]["host"])
    out += "  " + ','.join('"%s"'% host for host in tmp)
    out += ";\n"

    #Iterate and record each message
    for message in self.messages:
      if message["request"] != None: 
        sender = "Client"
        recipient = '"%s"' % message["request"]["host"]
        label = message["request"]["data"]
        out += "  %s=>%s [ label = \"%s\" ];\n" % (sender,recipient,label)
      if message["response"] != {}: 
        sender= '"%s"' % message["request"]["host"]
        recipient = "Client"
        label = message["response"]["data"]
        out += "  %s<=%s [ label = \"%s\" ];\n" % (recipient,sender,label)
    out += "\n}\n"
    print out
    #Should check if path already exists
    path = self.getFilePath()
    filename = path.getCanonicalPath()
    #Forcibly add the extension
    if '.msc' not in filename:
      filename += ".msc" 
    f = open(filename, "w")
    f.write(out)
    f.close()

    #Uses the messages global array to generate the MSC file

  def parse_header(self,http_input):
    url = ""
    host = ""
    body = ""
    data = []
    for line in http_input.split('\n'):
      if re.match('GET|POST', line):
        #print "case1"
        #print line
        url = line.split()[1] #url will be 2nd word 
      elif re.match('^Host:', line):
        #print "case2"
        #print line
        host = line.split()[-1] #host will be the last word
      elif re.match('Cookie:', line):
        #print "case3"
        #print line
        data = re.findall('(\S*?)=',line)
        print "Cookie: " + str(data)
      elif re.match('Set-Cookie:',line): 
        #data = re.search('(\S+)=\S*;',line) #exclusive to responses
        data.append(re.search('Set-Cookie: (\S*?)=',line).group(1)) #exclusive to responses
        print "Set-Cookie: " + str(data)
      ret = {'url':url,'host':host,'body':body,'data':data}
    return ret

  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.setExtensionName('MSC Exporter')
    callbacks.registerContextMenuFactory(self)
    return

  def createMenuItems(self, invocation):
    menuItemList = None
    context = invocation.getInvocationContext()

    #if IBurpExtenderCallbacks.TOOL_SCANNER == invocation.getToolFlag():
    if (context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY):
      menuItemList = ArrayList()
      menuItemList.add(JMenuItem("Export as MSC", actionPerformed = self.onClick))
      self.message_list = invocation.getSelectedMessages()
    return menuItemList

  def onClick(self, event):
    print "count: %d" % len(self.message_list)
    count = 0
    for message in self.message_list:
      m = {}
      #print "checking message: %d"  % count
      count +=1
      if message.getRequest() != None: 
        request = message.getRequest().tostring()
        reqobj = self.parse_header(request)
        m["request"]=reqobj
      else:
        m["request"]={}
      if message.getResponse() != None: 
        response = message.getResponse().tostring()
        respobj = self.parse_header(response)
        m["response"]=respobj
      else:
        m["response"]={}
      self.messages.append(m)
    #print self.messages
    #getFilePath()
    print "message count: " + str(len(self.messages))
    self.makeMSC()
    #empty out everything
    self.messages = []
