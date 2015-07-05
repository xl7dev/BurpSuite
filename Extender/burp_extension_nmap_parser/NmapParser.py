'''
NmapParser.py is used parse a nmap ouput.xml for ports and service names belonging to
web applications, adding hosts to scope with the option to start spidering.
'''

from burp import IBurpExtender
from burp import ITab
from java.net import URL
from java.awt import Dimension
from javax import swing
import xml.sax
import os.path
import threading
from java.lang import Runnable

class PyRunnable(Runnable):

    """This class is used to wrap a python callable object into a Java Runnable that is 
       suitable to be passed to various Java methods that perform callbacks.
    """

    def __init__(self, target, *args, **kwargs):
    
        """Creates a PyRunnable.
        
           target - The callable object that will be called when this is run.
           *args - Variable positional arguments
           **wkargs - Variable keywoard arguments.
        """
        self.target = target
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
    
        self.target(*self.args, **self.kwargs)

class BurpExtender(IBurpExtender, ITab):
    
    # implement IBurpExtender
    
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        self._callbacks.setExtensionName("NMAP Parser")
        # Variable to store Location of .xml
        self._fileLocation = None
        # build UI
        self._jPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        getFileButton = swing.JButton('Open Nmap .xml File',actionPerformed=self.getFile)
        self._fileText = swing.JTextArea("", 1, 50)
        boxHorizontal.add(getFileButton)
        boxHorizontal.add(self._fileText)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter Ports to Parse (Ex: 80, 443)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Multiple queries can be added, seperated by a space."))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._portField = swing.JTextField('',30)
        boxHorizontal.add(self._portField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter Keywords in Service Name to Parse (Ex: web, http)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Multiple queries can be added, seperated by a space."))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._serviceField = swing.JTextField('',30)
        boxHorizontal.add(self._serviceField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._spiderCheckBox = swing.JCheckBox('Spider Found Hosts')
        boxHorizontal.add(self._spiderCheckBox)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._hostNameCheckBox = swing.JCheckBox('Use Hostname if Found')
        boxHorizontal.add(self._hostNameCheckBox)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        submitQueryButton = swing.JButton('Parse NMAP File',actionPerformed=self.nmapParse)
        boxHorizontal.add(submitQueryButton)
        clearSearchButton = swing.JButton('Clear Output',actionPerformed=self.clearOutput)
        boxHorizontal.add(clearSearchButton)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Output"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._resultsTextArea = swing.JTextArea()
        resultsOutput = swing.JScrollPane(self._resultsTextArea)
        resultsOutput.setPreferredSize(Dimension(500,200))
        boxHorizontal.add(resultsOutput)
        boxVertical.add(boxHorizontal)
        self._jPanel.add(boxVertical)
        # add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)
        return
    # Function to Retrieve XML File
    def getFile(self, button):
    
        chooser = swing.JFileChooser()
        c = chooser.showOpenDialog(None)
        if chooser is not None:
            if (chooser.currentDirectory and chooser.selectedFile.name) is not None:
                self._fileLocation = str(chooser.currentDirectory) + os.sep + str(chooser.selectedFile.name)
                self._fileText.setText(self._fileLocation)
            else:
                self._fileText.setText("File Not Valid, Try Again")
    # Function to clear GUI Output
    def clearOutput(self, button):
    
        self._resultsTextArea.setText("")
    # run main funciton for Parsing Nmap XML
    def nmapParse(self, button):
    
        def nmapParse_run(nmapFile, portField, serviceField, checkbox, hostName):
        
            try: # Attempt to open XML file
                source = open(nmapFile)
            except:
                self.appendToResults("Nmap File not found (Check if Path and Filename is Correct)\n")
                return
            resultList = []
            try: # Attempt to get list of ports to parse
                portList = portField.split(",")
                for i in portList:
                    i.strip()
                    i.lstrip()
            except:
                self.appendToResults("Error with Port List\n")
                return
            try: # Attempt to get list of service names to parse
                serviceList = serviceField.split(",")
                for i in serviceList:
                    i.strip()
                    i.lstrip()
            except:
                self.appendToResults("Error with Service List")
                return
            self.appendToResults("Attempting to Parse XML File\n")
            try: # Attempt to parse XML
                Handler = NMAPContentHandler()
                if hostName.isSelected():
                    Handler._useHostname = True
                xml.sax.parse(source, Handler)
                source.close()
                self.appendToResults("Finished Parsing File\n")
                for result in Handler._list:
                    for portCheck in portList:
                        if portCheck == result[1]:
                            if [result[0],result[1],result[2]] not in resultList:
                                resultList.append([result[0],result[1],result[2]])
                    for serviceCheck in serviceList:
                        if serviceCheck in result[2]:
                            if [result[0],result[1],result[2]] not in resultList:
                                resultList.append([result[0],result[1],result[2]])
            except:
                self.appendToResults("Error Parsing Nmap File\n")
                return
            # Take parsed results and attempt to make request to host and port using HTTP/HTTPS, adding successful request/response to scope
            for list in resultList:
                uUrl = URL("http", list[0], int(list[1]), "/")
                newRequest = self._helpers.buildHttpRequest(uUrl)
                try:
                    requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(uUrl.getHost()), int(list[1]), str(uUrl.getProtocol()) == "https"), newRequest)
                    if not requestResponse.getResponse() == None:
                        if not self._callbacks.isInScope(uUrl):
                            self.appendToResults("Adding http://" + (str(uUrl.getHost())) + " port " + str(list[1]) + " to the sitemap\n")
                            self._callbacks.includeInScope(uUrl)
                        self._callbacks.addToSiteMap(requestResponse)
                        if checkbox.isSelected():
                            self.appendToResults("Spidering http://" + (str(uUrl.getHost())) + " Port " + str(list[1]) + "\n")
                            self._callbacks.sendToSpider(uUrl)
                            
                    else:
                        uUrl = URL("https", list[0], int(list[1]), "/")
                            
                        newRequest = self._helpers.buildHttpRequest(uUrl)
                        try:
                            requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(uUrl.getHost()), int(list[1]), str(uUrl.getProtocol()) == "https"), newRequest)
                            if not requestResponse.getResponse() == None:
                                if not self._callbacks.isInScope(uUrl):
                                    self.appendToResults("Adding https://" + (str(uUrl.getHost())) + " port " + str(list[1]) + " to the sitemap\n")
                                    self._callbacks.includeInScope(uUrl)
                                self._callbacks.addToSiteMap(requestResponse)
                                if checkbox.isSelected():
                                    self.appendToResults("Spidering https://" + (str(uUrl.getHost())) + " Port " + str(list[1]) + "\n")
                                    self._callbacks.sendToSpider(uUrl)
                            else:
                                self.appendToResults("Host " + list[0] + " with Port " + list[1] + " was unsuccessful under both HTTP and HTTPS protocols\n")
                        except:
                            self.appendToResults("Request was not successful\n")
                except:
                    self.appendToResults("Request was not successful\n")
            self.appendToResults("Finished NMAP Parser\n")
        
        # start a thread to run the above nested function
        # since this will run in the background it should prevent the GUI from blocking
        t = threading.Thread(target=nmapParse_run, args=[self._fileLocation, self._portField.text, self._serviceField.text, self._spiderCheckBox, self._hostNameCheckBox])
        t.daemon = True    # don't keep the process running after all the other threads quit (Might not mean anything in Jython)
        t.start()
        
    # Funciton to pass output to GUI
    def appendToResults(self, s):
    
        """Appends results to the resultsTextArea in a thread safe mannor. Results will be
           appended in the order that this function is called.
        """
        def appendToResults_run(s):
        
            self._resultsTextArea.append(s)
        
        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, s))
    
    # implement ITab

    def getTabCaption(self):
    
        return "NMAP Parser"
    
    def getUiComponent(self):
    
        return self._jPanel

# XML SAX Parsing Handler
class NMAPContentHandler(xml.sax.ContentHandler):
    
    def __init__(self):
    
        xml.sax.ContentHandler.__init__(self)
        self._state = None
        self._addr = None
        self._portid = None
        self._servicename = None
        self._hostname = None
        self._useHostname = False
        self._list = []
        
    def startElement(self, name, attrs):
    
        #print("startElement '" + name + "'")
        if name == "status":
            if attrs.getValue("state") == "up":
                self._state = True
            else:
                self._state = False
        if name == "address" and self._state:
            if attrs.getValue("addrtype") == "ipv4":
                self._addr = attrs.getValue("addr")
        if name == "hostname" and self._state:
            hname = attrs.getValue("name")
            if attrs.getValue("type") == "user":
                self._hostname = hname
        if name == "port" and self._state:
            if attrs.getValue("protocol") == "tcp":
                self._portid = attrs.getValue("portid")
        if name == "service" and self._state:
            self._servicename = attrs.getValue("name")
            
 
    def endElement(self, name):
    
        #print("endElement '" + name + "'")
        if name == 'nmaprun':
            pass
                
        if name == 'port':
            #print "end port"
            if self._hostname is not None and self._useHostname:
                if [self._hostname, self._portid, self._servicename] not in self._list:
                    self._list.append([self._hostname, self._portid, self._servicename])
            else:
                if [self._addr, self._portid, self._servicename] not in self._list:
                    self._list.append([self._addr, self._portid, self._servicename])

    def characters(self, content):
    
        #print("characters '" + content + "'")
        pass
        