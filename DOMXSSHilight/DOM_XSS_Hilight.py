"""
Name: DOM XSS Hilighter
Version: 1.0
Date: 28/08/2013
Author: Mesbahi Alaeddine
Contact: alaeddine.mesbahi@gmail.com
Description: A Burp plugin in Python. The plugin hilights requests with both sinks and sources and add a new button
  to hilight sinks and hosts in the Javascript code. The plugin is using DOM XSS Wiki regex http://code.google.com/p/domxsswiki/wiki/FindingDOMXSS.
  The plugin aids at detecting DOM XSS, hilight requests do not necessarily have DOM XSS vulnerabilties.
"""

# setup Imports
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IMenuItemHandler

from javax.swing import JFrame, JPanel, JTextArea, JTextPane, JScrollPane
from javax.swing.text import StyleConstants
from java.awt import Color

import re

# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API
class BurpExtender(IBurpExtender, IHttpListener, IMenuItemHandler):

    # define registerExtenderCallbacks: From IBurpExtender Interface
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("DOM XSS Hilight")

        #add the button
        self._callbacks.registerMenuItem("Search DOM XSS Pattern", self)
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 4: #if tool is Proxy Tab
            if not messageIsRequest:#only handle responses
                response = messageInfo.getResponse() #get Response from IHttpRequestResponse instance
                analyzedResponse = self._helpers.analyzeResponse(response) # returns IResponseInfo
                strResponse = ''.join([chr(c%256) for c in response])
                if self.filter(strResponse):
                    self.action(messageInfo)

    #handle the click on the button
    def menuItemClicked(self, caption, messageInfo):
        response = messageInfo[0].getResponse()
        strResponse = ''.join([chr(c%256) for c in response])
        frame = JFrame('DOM XSS',size = (300,300))
        parentPanel = JPanel()


        #printedCode = JTextPane(text = strResponse)
        #'''
        #colored code
        printedCode = JTextPane()
        styledDoc = printedCode.getStyledDocument()
        style = printedCode.addStyle('ColoredCode',None)
        self.filter2(strResponse,styledDoc,style)
        #'''
        #Scroll Bar
        scrollPanel = JScrollPane(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        scrollPanel.preferredSize = 1500,800
        scrollPanel.viewport.view = printedCode

        #Final Inclusion of Panels
        parentPanel.add(scrollPanel)
        frame.add(parentPanel)
        frame.visible = True


    def filter2(self, messageContent,styledDoc,style):
        pattern = '((location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database))|(((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\())|(after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\()'
        compiledPattern = re.compile(pattern)

        initPos = 0
        for find in compiledPattern.finditer(messageContent):
            StyleConstants.setForeground(style, Color.black)
            styledDoc.insertString(styledDoc.getLength(),messageContent[initPos:find.start()] , style)
            StyleConstants.setForeground(style, Color.red)
            styledDoc.insertString(styledDoc.getLength(),find.group(), style)
            initPos = find.start()+len(find.group())

        StyleConstants.setForeground(style, Color.black)
        styledDoc.insertString(styledDoc.getLength(),messageContent[initPos:] , style)
        return




    def filter(self, messageContent):
        pattern = '((location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database))'
        pattern2 = '(((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\())'
        compiledPattern = re.compile(pattern)
        compiledPattern2 = re.compile(pattern2)


        patternJQuerySinks = '(after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\()'
        compiledPatternJQuerySinks = re.compile(patternJQuerySinks)

        result = False

        lstMessageContent = messageContent.split('\n')
        for line in lstMessageContent:
            results = compiledPattern.findall(line)
            results2 = compiledPattern2.findall(line)
            results3 = compiledPatternJQuerySinks.findall(line)
            if results and (results2 or results3):
                print "[*] Line: '''%s'''" % line
                for result in results:
                    print "[*] Sources:''' %s'''" % str(result[0])

                for result2 in results2:
                    print "[*] Sinks:''' %s'''" % str(result2[0])

                for result3 in results3:
                    print "[*] Sinks JQuery:''' %s'''" % str(result3[0])

                result = True
        return result


    def action(self, args):
        messageInfo = args
        messageInfo.setHighlight("red")







