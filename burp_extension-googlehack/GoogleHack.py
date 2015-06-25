'''
GoogleHack.py is used to add domains in scope and query rules to a queue and execute
each query against google adding items found that obey scope rules to the target window.

Currently, the extension is ran without using googles API due to requiring an API key.
'''

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.net import URL
from java.awt import Dimension
from javax import swing
from javax.swing.table import AbstractTableModel
from StringIO import StringIO
import re
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

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def    registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        self._callbacks.setExtensionName("Google Hacking")
        # lists of hosts with querys
        self._listQuerys = []
        # build UI
        self._jPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter URL (Must Be In Scope):"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._hostField = swing.JTextField('',30)
        boxHorizontal.add(self._hostField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Enter Search Term (Example: .bac, .old, blank for root)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Multiple comma seperated queries can be added. (Remember to URL encode all queries)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._queryField = swing.JTextField('',30)
        boxHorizontal.add(self._queryField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        submitQueryButton = swing.JButton('Add to Queue',actionPerformed=self.runQuery)
        boxHorizontal.add(submitQueryButton)
        self._outputTextArea = swing.JTextArea()
        textOutput = swing.JScrollPane(self._outputTextArea)
        textOutput.setPreferredSize(Dimension(250,125))
        clearQueryButton = swing.JButton('Clear Queue',actionPerformed=self.clearQueue)
        boxHorizontal.add(clearQueryButton)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Queue"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(textOutput)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel("Max number of results to query for each: (Must be Integer)"))
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        self._indexField = swing.JTextField('100',3)
        boxHorizontal.add(self._indexField)
        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()
        submitSearchButton = swing.JButton('Perform Google Hacking',actionPerformed=self.googleSiteIndex)
        boxHorizontal.add(submitSearchButton)
        clearSearchButton = swing.JButton('Clear Search Output',actionPerformed=self.clearOutput)
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
        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)
        return
        
    # run Query for Add to Queue Button
    def runQuery(self, button):
    
        if self._queryField.text == "":
            self._outputTextArea.append("Host " + self._hostField.text + " with no search params (/)\n")
            self._listQuerys.append(self._hostField.text)
        else:
            inputString = self._queryField.text
            for word in inputString.split(','):
                word = word.strip()
                word = word.lstrip()
                if word == "/":
                    self._outputTextArea.append("Host " + self._hostField.text + " with search params " + word + "\n")
                    self._listQuerys.append(self._hostField.text)
                else:
                    self._outputTextArea.append("Host " + self._hostField.text + " with search params " + word + "\n")
                    self._listQuerys.append(self._hostField.text + "%20" + word)
    # Clear Queue Function
    def clearQueue(self, button):
    
        self._outputTextArea.setText("")
        self._listQuerys = []
    # Clear GUI Output Function
    def clearOutput(self, button):
    
        self._resultsTextArea.setText("")
    # run main funciton for getting Google results and adding them to Target
    def googleSiteIndex(self, button):
    
        def googleSiteIndex_run(querys, maxIndex):
            
            for i in querys:
                try:
                    maxIndex = int(maxIndex)
                except:
                    self.appendToResults("Index Value was not a valid Integer\n")
                    return
                # setup counts to stay within provided index range
                resultsCount = 0
                currentIndex = 0
                previousIndex = -1
                self.appendToResults("Starting Google Hack for " + i.strip() + "\n")
                while (currentIndex < maxIndex) and (previousIndex != currentIndex):
                    previousIndex = currentIndex
                    googleRequest = self.buildGoogleRequest(i, currentIndex)
                    try:
                        googleResponse = self._callbacks.makeHttpRequest('www.google.com', int('80'), False, googleRequest).tostring()
                    except: 
                        self.appendToResults("Call to google was not made: (Could not make a connection)\n")
                        return
                    if re.findall(r'<a href="([^<]+)" class=l', googleResponse) and resultsCount < maxIndex:
                        currentIndex += 100
                        for urlInSearch in re.findall(r'<a href="([^<]+)" class=l', googleResponse):
                            if resultsCount < maxIndex:
                                uUrl = URL(urlInSearch)
                                port = 80
                                if str(uUrl.getProtocol()) == "https":
                                    port = 443
                                if self._callbacks.isInScope(uUrl):
                                    newRequest = self.buildGenericRequest(uUrl)
                                    try:
                                        requestResponse = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(uUrl.getHost()), port, str(uUrl.getProtocol()) == "https"), newRequest) 
                                        self._callbacks.addToSiteMap(requestResponse)
                                        resultsCount += 1
                                        self.appendToResults("Adding " + urlInSearch + " to Target:\n")
                                    except:
                                        self.appendToResults("Call to URL found was not made: (Could not make a connection)\n")
                                else:
                                    self.appendToResults(urlInSearch + " was found but not in Scope (Not Adding to Target)\n")
                    else:
                        previousIndex = currentIndex
                self.appendToResults("Reached end of query " + i.strip() + " with " + str(resultsCount) + " results found\n\n")
        
        # start a thread to run the above nested function
        # since this will run in the background it should prevent the GUI from blocking
        t = threading.Thread(target=googleSiteIndex_run, args=[self._listQuerys[:], self._indexField.text])
        t.daemon = True    # don't keep the process running after all the other threads quit (Might not mean anything in Jython)
        t.start()
        
    # Fnction to provide output to GUI
    def appendToResults(self, s):
    
        """Appends results to the resultsTextArea in a thread safe mannor. Results will be
           appended in the order that this function is called.
        """
        def appendToResults_run(s):
        
            self._resultsTextArea.append(s)
        
        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, s))
    
        
    # build request to make call to google.com for
    # building of request required to add User-Agent for proper google response
    def buildGoogleRequest(self, url, currentIndex):
    
        requestString = StringIO()
        requestString.write("GET /search?q=site:")
        requestString.write(url)
        requestString.write("&start=")
        requestString.write(str(currentIndex))
        requestString.write("&num=100&complete=0&filter=0 HTTP/1.1\r\n")
        requestString.write("HOST: www.google.com\r\n")
        requestString.write("User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.28) Gecko/00000000 Firefox/30.0.00\r\n")
        requestString.write('\r\n\r\n')
        Request = map(lambda x: ord(x), requestString.getvalue())
        requestString.close()
        return Request
        
    # build generic request to make call to URL found in google search for adding to Target
    # built generic request to add Google as referrer
    def buildGenericRequest(self, url):
    
        requestString = StringIO()
        requestString.write("GET ")
        if url.getPath() is not None:
            requestString.write(str(url.getPath()))
        if url.getQuery() is not None:
            requestString.write(str(url.getQuery()))
        requestString.write(" HTTP/1.1\r\n")
        requestString.write("HOST: ")
        requestString.write(str(url.getHost()))
        requestString.write("\r\n")
        requestString.write("User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.28) Gecko/00000000 Firefox/30.0.00\r\n")
        requestString.write("Referer: wwww.google.com/\r\n")
        requestString.write('\r\n\r\n')
        Request = map(lambda x: ord(x), requestString.getvalue())
        requestString.close()
        return Request

    # implement ITab
    
    def getTabCaption(self):
    
        return "Google Hacking"
    
    def getUiComponent(self):
    
        return self._jPanel
