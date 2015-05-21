'''
PayloadParser.py is used parse though provided text files of Payloads including or excluding characters supplied as input.
The Extensions also allows you to save the payload list for importing into Intruder
'''
from burp import IBurpExtender
from burp import ITab
from java.net import URL
from java.awt import Dimension
from java.awt import Component
from java import awt
from javax import swing
import threading
from java.lang import Runnable
import re
import os.path
import os

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
        # set our extension name
        self._callbacks.setExtensionName("Payload Parser")
        # build UI
        self._jPanel = swing.JPanel()
        self._jPanel.layout = awt.BorderLayout()
        self._jPanel.border = swing.BorderFactory.createTitledBorder("Input characters to display payload strings with characters included or excluded")
        inputPanel = swing.JPanel()
        inputPanel.layout = awt.BorderLayout()
        radioPanel = swing.JPanel()
        self.text1 = swing.JTextField( actionPerformed = self.radioCallback )
        inputPanel.add(self.text1, inputPanel.layout.CENTER)
        buttonGroup = swing.ButtonGroup()
        self._radioButtonInclude = swing.JRadioButton("Include")
        buttonGroup.add(self._radioButtonInclude)
        radioPanel.add(self._radioButtonInclude)
        self._radioButtonExclude = swing.JRadioButton("Exclude")
        buttonGroup.add(self._radioButtonExclude)
        radioPanel.add(self._radioButtonExclude)
        self._radioButtonInclude.setSelected(True)
        inputPanel.add(radioPanel, inputPanel.layout.LINE_END)
        self._jPanel.add(inputPanel, self._jPanel.layout.PAGE_START)
        self.textArea = swing.JTextArea()
        scrollPane = swing.JScrollPane(self.textArea)
        self._jPanel.add(scrollPane, self._jPanel.layout.CENTER)
        boxVertical = swing.Box.createVerticalBox()
        saveLabel = swing.JLabel("Save Payloads (In Burp Root Dir): Can be Imported into Intruder")
        boxVertical.add(saveLabel)
        boxHorizontal = swing.Box.createHorizontalBox()
        saveLabel2 = swing.JLabel("Save As:")
        boxHorizontal.add(saveLabel2)
        self._saveTextField = swing.JTextField('',30)
        boxHorizontal.add(self._saveTextField)
        submitSaveButton = swing.JButton('Save',actionPerformed=self.savePayload)
        boxHorizontal.add(submitSaveButton)
        boxVertical.add(boxHorizontal)
        self._jPanel.add(boxVertical, self._jPanel.layout.PAGE_END)
        # add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)
        return
    # Function to Save Payload to File
    def savePayload(self, event):
    
        if self._saveTextField.text == "":
            print "Save Field is Blank, Try Again"
        else:
            
            self.textArea.setText("")
            if self._radioButtonInclude.isSelected():
                self.parsePayload( True, True)
            if self._radioButtonExclude.isSelected():
                self.parsePayload( False, True)
    # create Callback for Radio Buttons
    def radioCallback(self, event):
    
        self.textArea.setText("")
        if self._radioButtonInclude.isSelected():
            self.parsePayload( True, False)
        if self._radioButtonExclude.isSelected():
            self.parsePayload( False, False)

    # run main funciton for Parsing Payload Strings
    def parsePayload(self, includeExclude, isSave):
    
        def parsePayloadRun(inputText, includeExclude, isSave):
        
            if isSave:
                try:
                    saveFile = open(self._saveTextField.text,"w")
                except:
                    print "Could Not Open File for Saving, Try Again:"
            self.appendToResults("")
            if len(inputText) > 0:
                var =  "[" + inputText + "]"
                
                for r,d,f in os.walk("payloads" + os.sep):
                    for files in f:
                        if files.endswith(".txt"):
                            path = os.path.join(r,files)
                            payloads = open(path, 'r')
                            self.appendToResults("\n\n=== " + path + " ===\n\n")
                            if includeExclude:
                                for line in payloads:
                                    if re.findall(var, line):
                                        self.appendToResults(line)
                                        if isSave:
                                            try:
                                                saveFile.write(line)
                                            except:
                                                self.appendToResults("-------Could Not Write String to Output File------")
                            else:
                                for line in payloads:
                                    if not re.findall(var, line):
                                        self.appendToResults(line)
                                        if isSave:
                                            try:
                                                saveFile.write(line)
                                            except:
                                                self.appendToResults("-------Could Not Write String to Output File------")
            try:
                saveFile.close()
            except:
                pass
        
        # start a thread to run the above nested function
        # since this will run in the background it should prevent the GUI from blocking
        t = threading.Thread(target=parsePayloadRun, args=[self.text1.getText(), includeExclude, isSave])
        t.daemon = True    # don't keep the process running after all the other threads quit (Might not mean anything in Jython)
        t.start()
        
    # Funciton to sent output to GUI
    def appendToResults(self, s):
    
        """Appends results to the resultsTextArea in a thread safe mannor. Results will be
           appended in the order that this function is called.
        """
        def appendToResults_run(s):
        
            self.textArea.append(s)
        
        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, s))
    
    # implement ITab
    
    def getTabCaption(self):
        return "Payload Parser"
    
    def getUiComponent(self):
        return self._jPanel
