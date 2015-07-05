##########
##
##  Author：[Syclover - Kavia]
##
##########
from javax.swing import JPanel
from javax.swing import Box
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JDialog
from javax.swing import JLabel
from javax.swing import JTextField
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
from javax.swing import JTable

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener

from random import randint

class BurpExtender(IBurpExtender,ITab,IHttpListener):
    def registerExtenderCallbacks(self,callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("KkMultiProxy")
        self.PROXY_LIST = []

        self.jPanel = JPanel()
        boxVertical = Box.createVerticalBox()
        boxHorizontal = Box.createHorizontalBox()

        boxHorizontal.add(JButton("File",actionPerformed=self.getFile))
        self.FileText = JTextField("")
        boxHorizontal.add(self.FileText)
        boxVertical.add(boxHorizontal)

        TableHeader = ('IP','PORT')
        TableModel = DefaultTableModel(self.PROXY_LIST,TableHeader)
        self.Table = JTable(TableModel)
        boxVertical.add(self.Table)

        boxHorizontal = Box.createHorizontalBox()
        boxHorizontal.add(JButton("Add",actionPerformed=self.addIP))
        boxHorizontal.add(JButton("Delete",actionPerformed=self.deleteIP))
        boxHorizontal.add(JButton("Save",actionPerformed=self.saveIP))
        boxVertical.add(boxHorizontal)

        self.jPanel.add(boxVertical)

        self.callbacks.addSuiteTab(self)
        self.callbacks.registerHttpListener(self)
        return

    def getFile(self,button):
        dlg = JFileChooser()
        result = dlg.showOpenDialog(None)
        if result == JFileChooser.APPROVE_OPTION:
            f = dlg.getSelectedFile()
            path = f.getPath()
            self.FileText.setText(path)
            try:
                self.getIPList(path)
            except:
                exit(0)

    def addIP(self,button):
        #chooser = JFileChooser()
        #chooser.showOpenDialog(None)
        demo = DialogDemo(self.Table)

    def deleteIP(self,button):
        selectRows = len(self.Table.getSelectedRows()) 
        TableModel = self.Table.getModel()
        if selectRows:
            selectedRowIndex = self.Table.getSelectedRow()
            TableModel.removeRow(selectedRowIndex)

    def saveIP(self,button):
        TableModel = self.Table.getModel()
        rowCount = TableModel.getRowCount()
        result_str = ""
        for i in range(rowCount):
            if i == 0:
                result_str+=TableModel.getValueAt(i,0)+':'+TableModel.getValueAt(i,1)
            else:
                result_str+='|'+TableModel.getValueAt(i,0)+':'+TableModel.getValueAt(i,1)
        print result_str
        f = open(self.FileText.getText(),'w+')
        f.write(result_str)
        f.close()
    def getTabCaption(self):
        return "MultiProxy"

    def getUiComponent(self):
        return self.jPanel

    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
        if messageIsRequest:
            httpService = messageInfo.getHttpService()
            print httpService.getHost()

            # if the host is HOST_FROM, change it to HOST_TO
            i = randint(0,len(self.TableDatas)-1)
            messageInfo.setHttpService(self.helpers.buildHttpService(self.PROXY_LIST[i]['ip'], self.PROXY_LIST[i]['port'], httpService.getProtocol()))
            print messageInfo.getHttpService().getHost()

    def getIPList(self,path):
        f = open(path,'r+')
        content = f.read()
        f.close()
        if content:
            ip_array = content.split('|')
            for _ip in ip_array:
                ip = _ip.split(':')[0]
                port = _ip.split(':')[1]
                self.PROXY_LIST.append([ip,port])
        print self.PROXY_LIST

class DialogDemo(JDialog):
    def __init__(self,table):

        self.setTitle("Add Proxy")
        self.setSize(200,100)
        self.setVisible(True)
        self.table = table
        #self.getContentPane().add(about,BorderLayout.CENTER)

        boxHorizontal = Box.createHorizontalBox()
        boxVertical = Box.createVerticalBox()
        boxHorizontal.add(JLabel("IP:"))
        self.jIpText = JTextField(20)
        boxHorizontal.add(self.jIpText)
        boxVertical.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        boxHorizontal.add(JLabel("PROT:"))
        self.jPortText = JTextField(20)
        boxHorizontal.add(self.jPortText)
        boxVertical.add(boxHorizontal)

        boxHorizontal = Box.createHorizontalBox()
        boxHorizontal.add(JButton("Add",actionPerformed=self.addIP))
        boxVertical.add(boxHorizontal)

        self.getContentPane().add(boxVertical,BorderLayout.CENTER)
    def addIP(self,button):
        TableModel = self.table.getModel()
        TableModel.addRow([self.jIpText.getText(),self.jPortText.getText()])
