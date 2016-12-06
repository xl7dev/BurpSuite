import os, zipfile, shutil, inspect, random, sys, re, subprocess, platform
import xml.etree.ElementTree as ET
try:
    sys.path.append('XlsxWriter-0.7.3')
    import xlsxwriter
    xlsxwriterImported = True
except:
    xlsxwriterImported = False
from burp import ITab
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IMessageEditorController
from ConfigParser import SafeConfigParser
from java.io import File
from javax.imageio import ImageIO
from threading import Lock
from java.awt import Color
from java.awt import RenderingHints
from java.awt import Toolkit
from java.util import ArrayList
from java.util import LinkedList
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JLabel
from javax.swing import JMenu
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import ImageIcon
from javax.swing import JTextArea
from javax.swing import JSplitPane
from javax.swing import JTextField
from javax.swing import JMenuItem
from javax.swing import JCheckBox
from javax.swing import JScrollPane
from javax.swing import JComboBox
from javax.swing import JOptionPane
from javax.swing import JPopupMenu
from javax.swing import JFileChooser
from javax.swing import JTabbedPane
from javax.swing import BorderFactory
from javax.swing import DefaultListModel
from javax.swing import ScrollPaneConstants
from javax.swing import DefaultComboBoxModel
from javax.swing.event import DocumentListener
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel
from javax.swing.border import LineBorder
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.datatransfer import Clipboard
from java.awt.datatransfer import DataFlavor
from java.awt.image import BufferedImage
from java.awt.datatransfer import Transferable
from javax.xml.parsers import DocumentBuilderFactory
from javax.xml.transform import TransformerFactory
from javax.xml.transform.dom import DOMSource
from javax.xml.transform.stream import StreamResult
from javax.swing.filechooser import FileNameExtensionFilter

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, AbstractTableModel, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("PT Vulnerabilities Manager")
        
        self.config = SafeConfigParser()
        self.createSection('projects')
        self.createSection('general')
        self.config.read('config.ini')
        homeDir = os.path.expanduser("~")
        self.chooser = JFileChooser(homeDir)
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        self.logTable = Table(self)
        self.logTable.getColumnModel().getColumn(0).setMaxWidth(35)
        self.logTable.getColumnModel().getColumn(1).setMinWidth(100)

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)

        self.initVulnerabilityTab()
        self.initProjSettingsTab()
        self.initTabs()
        self.initCallbacks()

        if self.projPath.getText() != None:
            self.loadVulnerabilities(self.projPath.getText())

        print "Thank you for installing PT Vulnerabilities Manager v1.0 extension"
        print "by Barak Tawily\n\nGithub:\nhttps://github.com/Quitten/PT-Manager\n\n\n"
        print "Disclaimer:\nThis extension might create folders and files in your hardisk which might be declared as sensitive information, make sure you are creating projects under encrypted partition"
        return

    def initVulnerabilityTab(self):
        #
        ##  init vulnerability tab
        #

        nameLabel = JLabel("Vulnerability Name:")
        nameLabel.setBounds(10, 10, 140, 30)

        self.addButton = JButton("Add",actionPerformed=self.addVuln)
        self.addButton.setBounds(10, 500, 100, 30) 

        rmVulnButton = JButton("Remove",actionPerformed=self.rmVuln)
        rmVulnButton.setBounds(465, 500, 100, 30)

        mitigationLabel = JLabel("Mitigation:")
        mitigationLabel.setBounds(10, 290, 150, 30)
        
        addSSBtn = JButton("Add SS",actionPerformed=self.addSS)
        addSSBtn.setBounds(750, 40, 110, 30) 

        deleteSSBtn = JButton("Remove SS",actionPerformed=self.removeSS)
        deleteSSBtn.setBounds(750, 75, 110, 30) 

        piclistLabel = JLabel("Images list:")
        piclistLabel.setBounds(580, 10, 140, 30)

        self.screenshotsList = DefaultListModel()
        self.ssList = JList(self.screenshotsList)
        self.ssList.setBounds(580, 40, 150, 250)
        self.ssList.addListSelectionListener(ssChangedHandler(self))
        self.ssList.setBorder(BorderFactory.createLineBorder(Color.GRAY))

        previewPicLabel = JLabel("Selected image preview: (click to open in image viewer)")
        previewPicLabel.setBounds(580, 290, 500, 30)


        copyImgMenu = JMenuItem("Copy")
        copyImgMenu.addActionListener(copyImg(self))

        self.imgMenu = JPopupMenu("Popup")
        self.imgMenu.add(copyImgMenu)

        self.firstPic = JLabel()
        self.firstPic.setBorder(BorderFactory.createLineBorder(Color.GRAY))
        self.firstPic.setBounds(580, 320, 550, 400)
        self.firstPic.addMouseListener(imageClicked(self))

        self.vulnName = JTextField("")
        self.vulnName.setBounds(140, 10, 322, 30)

        self.newVulnBtn = JButton("New", actionPerformed=self.newVulnBtnClicked)
        self.newVulnBtn.setBounds(465, 10, 100, 30)

        sevirities = ["Unclassified", "Critical","High","Medium","Low"]
        self.threatLevel = JComboBox(sevirities);
        self.threatLevel.setBounds(140, 45, 140, 30)

        colors = ["Color:", "Green", "Red"]
        self.colorCombo = JComboBox(colors);
        self.colorCombo.setBounds(465, 45, 100, 30)

        severityLabel = JLabel("Threat Level:")
        severityLabel.setBounds(10, 45, 100, 30)

        descriptionLabel = JLabel("Description:")
        descriptionLabel.setBounds(10, 80, 100, 30)

        self.descriptionString = JTextArea("", 5, 30)
        self.descriptionString.setWrapStyleWord(True);
        self.descriptionString.setLineWrap(True)
        self.descriptionString.setBounds(10, 110, 555, 175)
        descriptionStringScroll = JScrollPane(self.descriptionString)
        descriptionStringScroll.setBounds(10, 110, 555, 175)
        descriptionStringScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)


        self.mitigationStr = JTextArea("", 5, 30)
        self.mitigationStr.setWrapStyleWord(True);
        self.mitigationStr.setLineWrap(True)
        self.mitigationStr.setBounds(10, 320, 555, 175)
        mitigationStrScroll = JScrollPane(self.mitigationStr)
        mitigationStrScroll.setBounds(10, 320, 555, 175)
        mitigationStrScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)

        self.pnl = JPanel()
        self.pnl.setBounds(0, 0, 1000, 1000);
        self.pnl.setLayout(None);
        self.pnl.add(addSSBtn)
        self.pnl.add(piclistLabel)
        self.pnl.add(nameLabel)
        self.pnl.add(deleteSSBtn)
        self.pnl.add(rmVulnButton)
        self.pnl.add(severityLabel)
        self.pnl.add(mitigationLabel)
        self.pnl.add(descriptionLabel)
        self.pnl.add(previewPicLabel)
        self.pnl.add(mitigationStrScroll)
        self.pnl.add(descriptionStringScroll)
        self.pnl.add(self.ssList)
        self.pnl.add(self.firstPic)
        self.pnl.add(self.vulnName)
        self.pnl.add(self.addButton)
        self.pnl.add(self.threatLevel)
        self.pnl.add(self.newVulnBtn)
        self.pnl.add(self.colorCombo)
        
    def initProjSettingsTab(self):
        # init project settings 
        
        projNameLabel = JLabel("Name:")
        projNameLabel.setBounds(10, 50, 140, 30)

        self.projName = JTextField("")
        self.projName.setBounds(140, 50, 320, 30)
        self.projName.getDocument().addDocumentListener(projTextChanged(self))

        detailsLabel = JLabel("Details:")
        detailsLabel.setBounds(10, 120, 140, 30)

        reportLabel = JLabel("Generate Report:")
        reportLabel.setBounds(10, 375, 140, 30)

        types = ["HTML","DOCX","XLSX"]
        self.reportType = JComboBox(types)
        self.reportType.setBounds(10, 400, 140, 30)

        generateReportButton = JButton("Generate", actionPerformed=self.generateReport)
        generateReportButton.setBounds(160, 400, 90, 30)


        self.projDetails = JTextArea("", 5, 30)
        self.projDetails.setWrapStyleWord(True);
        self.projDetails.setLineWrap(True)

        projDetailsScroll = JScrollPane(self.projDetails)
        projDetailsScroll.setBounds(10, 150, 450, 175)
        projDetailsScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED)

        projPathLabel = JLabel("Path:")
        projPathLabel.setBounds(10, 90, 140, 30)

        self.projPath = JTextField("")
        self.projPath.setBounds(140, 90, 320, 30)

        chooseProjPathButton = JButton("Browse...",actionPerformed=self.chooseProjPath)
        chooseProjPathButton.setBounds(470, 90, 100, 30)
        
        importProjButton = JButton("Import",actionPerformed=self.importProj)
        importProjButton.setBounds(470, 10, 100, 30)

        exportProjButton = JButton("Export",actionPerformed=self.exportProj)
        exportProjButton.setBounds(575, 10, 100, 30)

        openProjButton = JButton("Open Directory",actionPerformed=self.openProj)
        openProjButton.setBounds(680, 10, 130, 30)

        currentProjectLabel = JLabel("Current:")
        currentProjectLabel.setBounds(10, 10, 140, 30)

        projects = self.config.options('projects')
        self.currentProject = JComboBox(projects)
        self.currentProject.addActionListener(projectChangeHandler(self))
        self.currentProject.setBounds(140, 10, 140, 30)

        self.autoSave = JCheckBox("Auto Save Mode") 
        self.autoSave.setEnabled(False)  # implement this feature
        self.autoSave.setBounds(300, 10, 140, 30)
        self.autoSave.setToolTipText("Will save any changed value when focus lost in the vulnerability tab")

        addProjButton = JButton("Add / Update",actionPerformed=self.addProj)
        addProjButton.setBounds(10, 330, 150, 30)

        removeProjButton = JButton("Remove Current",actionPerformed=self.rmProj)
        removeProjButton.setBounds(315, 330, 146, 30)

        generalOptions = self.config.options('general')
        if 'default project' in generalOptions:
            defaultProj = self.config.get('general','default project')
            defaultProj = self.config.get('projects',defaultProj)
            xmlPath = defaultProj + "/project.xml"
            self.loadProject(xmlPath)

        self.clearProjTab = True
        self.projectSettings = JPanel()
        self.projectSettings.setBounds(0, 0, 1000, 1000)
        self.projectSettings.setLayout(None)
        self.projectSettings.add(reportLabel)
        self.projectSettings.add(detailsLabel)
        self.projectSettings.add(projPathLabel)
        self.projectSettings.add(addProjButton)
        self.projectSettings.add(openProjButton)
        self.projectSettings.add(projNameLabel)
        self.projectSettings.add(projDetailsScroll)
        self.projectSettings.add(importProjButton)
        self.projectSettings.add(exportProjButton)
        self.projectSettings.add(removeProjButton)
        self.projectSettings.add(generateReportButton)
        self.projectSettings.add(chooseProjPathButton)
        self.projectSettings.add(currentProjectLabel)
        self.projectSettings.add(self.projPath)
        self.projectSettings.add(self.autoSave)
        self.projectSettings.add(self.projName)
        self.projectSettings.add(self.reportType)
        self.projectSettings.add(self.currentProject)

    def initTabs(self):
        #
        ##  init autorize tabs
        #
        
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.scrollPane = JScrollPane(self.logTable)
        self._splitpane.setLeftComponent(self.scrollPane)
        colorsMenu = JMenu("Paint")
        redMenu = JMenuItem("Red")
        noneMenu = JMenuItem("None")
        greenMenu = JMenuItem("Green")
        redMenu.addActionListener(paintChange(self, "Red"))
        noneMenu.addActionListener(paintChange(self, None))
        greenMenu.addActionListener(paintChange(self, "Green"))
        colorsMenu.add(redMenu)
        colorsMenu.add(noneMenu)
        colorsMenu.add(greenMenu)
        
        
        self.menu = JPopupMenu("Popup")
        self.menu.add(colorsMenu)

        self.tabs = JTabbedPane()
        
        self.tabs.addTab("Request", self._requestViewer.getComponent())
        self.tabs.addTab("Response", self._responseViewer.getComponent())

        self.tabs.addTab("Vulnerability", self.pnl)

        self.tabs.addTab("Project Settings", self.projectSettings)
        
        self.tabs.setSelectedIndex(3)
        self._splitpane.setRightComponent(self.tabs)

    def initCallbacks(self):
        #
        ##  init callbacks
        #

        # customize our UI components
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self.logTable)
        self._callbacks.customizeUiComponent(self.scrollPane)
        self._callbacks.customizeUiComponent(self.tabs)
        self._callbacks.registerContextMenuFactory(self)
        # add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)


    def loadVulnerabilities(self, projPath):
        self.clearList(None)
        selected = False
        for root, dirs, files in os.walk(projPath): # make it go only for dirs
            for dirName in dirs:
                xmlPath = projPath+"/"+dirName+"/vulnerability.xml"
                document = self.getXMLDoc(xmlPath)
                nodeList = document.getDocumentElement().getChildNodes()
                vulnName = nodeList.item(0).getTextContent()
                severity = nodeList.item(1).getTextContent()
                description = nodeList.item(2).getTextContent()
                mitigation = nodeList.item(3).getTextContent()
                color = nodeList.item(4).getTextContent()
                vulnObject = vulnerability(vulnName,severity,description,mitigation,color)
                self._lock.acquire()
                row = self._log.size()
                self._log.add(vulnObject)
                self.fireTableRowsInserted(row, row)
                self._lock.release()
                if vulnName == self.vulnName.getText():
                    self.logTable.setRowSelectionInterval(row,row)
                    selected = True
        if selected == False and self._log.size() > 0:
            self.logTable.setRowSelectionInterval(0, 0)
            self.loadVulnerability(self._log.get(0))
        
    def createSection(self, sectioName):
        self.config.read('config.ini')
        if not (sectioName in self.config.sections()):
            self.config.add_section(sectioName)
            cfgfile = open("config.ini",'w')
            self.config.write(cfgfile)
            cfgfile.close()

    def saveCfg(self):
        f = open('config.ini', 'w')
        self.config.write(f)
        f.close()

    def getXMLDoc(self, xmlPath):
        try:
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlPath)
            return document
        except:
            self.popup("XML file not found")
            return

    def saveXMLDoc(self, doc, xmlPath):
        transformerFactory = TransformerFactory.newInstance()
        transformer = transformerFactory.newTransformer()
        source = DOMSource(doc)
        result = StreamResult(File(xmlPath))
        transformer.transform(source, result)

    def generateReport(self,event):
        if self.reportType.getSelectedItem() == "HTML":
            path = self.reportToHTML()
        if self.reportType.getSelectedItem() == "XLSX":
            path = self.reportToXLS()
        if self.reportType.getSelectedItem() == "DOCX":
            path = self.generateReportFromDocxTemplate('template.docx',"newfile.docx", 'word/document.xml')
        n = JOptionPane.showConfirmDialog(None, "Report generated successfuly:\n%s\nWould you like to open it?" % (path), "PT Manager", JOptionPane.YES_NO_OPTION)
        if n == JOptionPane.YES_OPTION:
            self.openFolderOrFile(path)

    def exportProj(self,event):
        self.chooser.setDialogTitle("Save project")
        Ffilter = FileNameExtensionFilter("Zip files", ["zip"])
        self.chooser.setFileFilter(Ffilter)
        returnVal = self.chooser.showSaveDialog(None)
        if returnVal == JFileChooser.APPROVE_OPTION:
            dst = str(self.chooser.getSelectedFile())
            shutil.make_archive(dst,"zip",self.getCurrentProjPath())
            self.popup("Project export successfuly")

    def importProj(self,event):
        self.chooser.setDialogTitle("Select project zip to directory")
        Ffilter = FileNameExtensionFilter("Zip files", ["zip"])
        self.chooser.setFileFilter(Ffilter)
        returnVal = self.chooser.showOpenDialog(None)
        if returnVal == JFileChooser.APPROVE_OPTION:
            zipPath = str(self.chooser.getSelectedFile())
            self.chooser.setDialogTitle("Select project directory")
            self.chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            returnVal = self.chooser.showOpenDialog(None)
            if returnVal == JFileChooser.APPROVE_OPTION:
                projPath = str(self.chooser.getSelectedFile()) + "/PTManager"
                with zipfile.ZipFile(zipPath, "r") as z:
                    z.extractall(projPath)

                xmlPath = projPath + "/project.xml"
                document = self.getXMLDoc(xmlPath)
                nodeList = document.getDocumentElement().getChildNodes()
                projName = nodeList.item(0).getTextContent()
                nodeList.item(1).setTextContent(projPath)
                self.saveXMLDoc(document, xmlPath)
                self.config.set('projects', projName, projPath)
                self.saveCfg()
                self.reloadProjects()
                self.currentProject.getModel().setSelectedItem(projName)
                self.clearVulnerabilityTab() 

    def reportToXLS(self):
        if not xlsxwriterImported:
            self.popup("xlsxwriter library is not imported")
            return
        workbook = xlsxwriter.Workbook(self.getCurrentProjPath() + '/PT Manager Report.xlsx')
        worksheet = workbook.add_worksheet()
        bold = workbook.add_format({'bold': True})
        worksheet.write(0, 0, "Vulnerability Name", bold)
        worksheet.write(0, 1, "Threat Level", bold)
        worksheet.write(0, 2, "Description", bold)
        worksheet.write(0, 3, "Mitigation", bold)
        row = 1
        for i in range(0,self._log.size()):
            worksheet.write(row, 0, self._log.get(i).getName())
            worksheet.write(row, 1, self._log.get(i).getSeverity())
            worksheet.write(row, 2, self._log.get(i).getDescription())
            worksheet.write(row, 3, self._log.get(i).getMitigation())
            row = row + 1
            # add requests and images as well
        workbook.close()
        return self.getCurrentProjPath() + '/PT Manager Report.xlsx'
        
    def reportToHTML(self):
        htmlContent = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="he" dir="ltr">
    <head>
        <title>PT Manager Report</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <style>
        body {
        background-repeat: no-repeat;
        background-attachment: fixed;
        font-family: Arial,Tahoma,sens-serif;
        font-size: 13px;
        margin: auto;
        }

        #warpcenter {
            width: 900px;
            margin: 0px auto;
        }

        table {
            border: 2px dashed #000000;
        }

        td {
            border-top: 2px dashed #000000;
            padding: 10px;
        }

        img {
                border: 0px;
        }
</style>
<script language="javascript">
    function divHideShow(divToHideOrShow) 
    {
        var div = document.getElementById(divToHideOrShow);

        if (div.style.display == "block") 
        {
            div.style.display = "none";
        }
        else 
        {
            div.style.display = "block";
        }

        
    }         
</script>
    </head>

    <body>
        <div id="warpcenter">

<h1> PT Manager Report </h1>
<h2> Project: %s</h1>
    """ % (self.projName.getText())

        for i in range(0,self._log.size()):
            name = self._log.get(i).getName()
            requestPath = self.getVulnReqResPath("request",name) .replace("\\","\\\\")
            requestHTML = "No Request"
            if os.path.exists(requestPath):
                requestHTML = """<input type="button" value="Load" onclick="document.getElementById('requestFrame%s').src = '%s'"/><br><br><iframe id="requestFrame%s" width="870" height="500"></iframe>""" % (i, requestPath, i)
            responsePath = self.getVulnReqResPath("response",name).replace("\\","\\\\")
            responseHTML = "No Response"
            if os.path.exists(responsePath):
                responseHTML = """<input type="button" value="Load" onclick="document.getElementById('responseFrame%s').src = '%s'"/><br><br><iframe id="responseFrame%s" width="870" height="500"></iframe>""" % (i, responsePath, i)

            images = ""
            for fileName in os.listdir(self.projPath.getText()+"/"+self.clearStr(name)):
                if fileName.endswith(".jpg"):
                    images += "%s<br><img src=\"%s\"><br><br>" % (fileName, self.projPath.getText()+"/"+self.clearStr(name) + "/" + fileName)
            description = self.newlineToBR(self._log.get(i).getDescription())
            mitigation = self.newlineToBR(self._log.get(i).getMitigation())
            htmlContent +=  self.convertVulntoTable(i,name,self._log.get(i).getSeverity(), description,mitigation, requestHTML, responseHTML, images)
        htmlContent += "<p align=\"right\">Developed by Barak Tawily</p></div></body></html>"
        f = open(self.getCurrentProjPath() + '/PT Manager Report.html', 'w')
        f.writelines(htmlContent)
        f.close()
        return self.getCurrentProjPath() + '/PT Manager Report.html'

    def newlineToBR(self,string):
        return "<br />".join(string.split("\n"))

    def getFileContent(self,path):
        f = open(path, "rb")
        content = f.read()
        f.close()
        return content

    def convertVulntoTable(self, number, name, severity, description, mitigation, request = "None", response = "None", images = "None"):
        name = self.htmlEscape(name)
        description = self.htmlEscape(description)
        mitigation = self.htmlEscape(mitigation)
        return """<div style="width: 100%%;height: 30px;text-align: center;background-color:#E0E0E0;font-size: 17px;font-weight: bold;color: #000;padding-top: 10px;">%s <a href="javascript:divHideShow('Table_%s');" style="color:#191970">(OPEN / CLOSE)</a></div>
        <div id="Table_%s" style="display: none;">
            <table width="100%%" cellspacing="0" cellpadding="0" style="margin: 0px auto;text-align: left;border-top: 0px;">
                <tr>
                    <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Threat Level: </span> 
                        <span style="color:#8b8989">%s</span>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Description</span> 
                        <a href="javascript:divHideShow('Table_%s_Command_03');" style="color:#191970">OPEN / CLOSE >>></a>
                        </div>

                        <div id="Table_%s_Command_03" style="display: none;margin-top: 25px;">
                        %s
                        </div>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Mitigration</span> 
                        <a href="javascript:divHideShow('Table_%s_Command_04');" style="color:#191970">OPEN / CLOSE >>></a>
                        </div>

                        <div id="Table_%s_Command_04" style="display: none;margin-top: 25px;">
                        %s
                        <b>
                                            </td>
                                        </tr>

                                        <tr>
                                            <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Request</span> 
                        <a href="javascript:divHideShow('Table_%s_Command_05');" style="color:#191970">OPEN / CLOSE >>></a>
                        </div>

                        <div id="Table_%s_Command_05" style="display: none;margin-top: 25px;">
                        %s
                        <b>
                                            </td>
                                        </tr>


                                                        <tr>
                                            <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Response</span> 
                        <a href="javascript:divHideShow('Table_%s_Command_06');" style="color:#191970">OPEN / CLOSE >>></a>
                        </div>

                        <div id="Table_%s_Command_06" style="display: none;margin-top: 25px;">
                        %s
                        <b>
                                            </td>
                                        </tr>

                                                        <tr>
                                            <td>
                        <div style="font-size: 16px;font-weight: bold;">
                        <span style="color:#000000">Images</span> 
                        <a href="javascript:divHideShow('Table_%s_Command_07');" style="color:#191970">OPEN / CLOSE >>></a>
                        </div>

                        <div id="Table_%s_Command_07" style="display: none;margin-top: 25px;">
                        %s
                        <b>
                    </td>
                </tr>
            </table>
        </div><br><br>""" % (name,number,number,severity,number,number,description,number,number,mitigation,number,number,request,number,number,response,number,number,images)

    def clearVulnerabilityTab(self, rmVuln=True):
        if rmVuln:
            self.vulnName.setText("")
        self.descriptionString.setText("")
        self.mitigationStr.setText("")
        self.colorCombo.setSelectedIndex(0)
        self.threatLevel.setSelectedIndex(0)
        self.screenshotsList.clear()
        self.addButton.setText("Add")
        self.firstPic.setIcon(None)

    def saveRequestResponse(self, type, requestResponse, vulnName):
        path = self.getVulnReqResPath(type,vulnName)
        f = open(path, 'wb')
        f.write(requestResponse)
        f.close()

    def openFolderOrFile(self, path):
        plat = platform.platform()
        if "on-Windows" in plat:
            path = path.replace("/","\\")
            subprocess.Popen(["explorer", path])
        elif "on-Linux" in plat:
            subprocess.Popen(["xdg-open", path])
        elif "on-Mac" or "on-Darwin" in plat:
            subprocess.Popen(["open", path])

    def newVulnBtnClicked(self, event):
        self.clearVulnerabilityTab(True)
        self.addButton.setText("Add")

    def openProj(self, event):
        self.openFolderOrFile(self.projPath.getText())

    def getVulnReqResPath(self, requestOrResponse, vulnName):
        return self.getCurrentProjPath() + "/" + self.clearStr(vulnName) + "/"+requestOrResponse+"_" + self.clearStr(vulnName)

    def htmlEscape(self,data):
        return data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

    def generateReportFromDocxTemplate(self, zipname, newZipName, filename):      
        newZipName = self.getCurrentProjPath() + "/" + newZipName
        with zipfile.ZipFile(zipname, 'r') as zin:
            with zipfile.ZipFile(newZipName, 'w') as zout:
                zout.comment = zin.comment
                for item in zin.infolist():
                    if item.filename != filename:
                        zout.writestr(item, zin.read(item.filename))
                    else:
                        xml_content = zin.read(item.filename)
                        result = re.findall("(.*)<w:body>(?:.*)<\/w:body>(.*)",xml_content)[0]
                        newXML = result[0]
                        templateBody = re.findall("<w:body>(.*)<\/w:body>", xml_content)[0]
                        newBody = ""

                        for i in range(0,self._log.size()):
                            tmp = templateBody
                            tmp = tmp.replace("$vulnerability", self.htmlEscape(self._log.get(i).getName()))
                            tmp = tmp.replace("$severity", self.htmlEscape(self._log.get(i).getSeverity()))
                            tmp = tmp.replace("$description", self.htmlEscape(self._log.get(i).getDescription()))
                            tmp = tmp.replace("$mitigation", self.htmlEscape(self._log.get(i).getMitigation()))
                            newBody = newBody + tmp
                         
                        newXML = newXML + newBody
                        newXML = newXML + result[1]

        with zipfile.ZipFile(newZipName, mode='a', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(filename, newXML)
        return newZipName


    def chooseProjPath(self, event):
        self.chooser.setDialogTitle("Select target directory")
        self.chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        returnVal = self.chooser.showOpenDialog(None)
        if returnVal == JFileChooser.APPROVE_OPTION:
            projPath = str(self.chooser.getSelectedFile()) + "/PTManager"
            if not os.path.exists(projPath):
                os.makedirs(projPath)
            else:
                self.popup("Error: PTManager folder already exists, please choose other folder")
            self.projPath.setText(projPath)

    def reloadProjects(self):
        self.currentProject.setModel(DefaultComboBoxModel(self.config.options('projects')))

    def rmProj(self, event): #uncomment the following comments in the function if you would like to remove the directory - insecure
        # projPath = self.projPath.getText()
        # if not os.path.exists(projPath+"/project.xml"):
        #     self.popup("project.xml not found, cant delete the directory")
        #     return
        # if self.popUpAreYouSure("Are you sure you want to delete the following directory path? (including it's content sub directories and files)\n%s" % (projPath)) == JOptionPane.YES_OPTION:
        if self.popUpAreYouSure("Are you sure you want to delete this project from the config file?\nNote: it will not be removed from the directory on your file system.") == JOptionPane.YES_OPTION:
            self._requestViewer.setMessage("None", False)
            self._responseViewer.setMessage("None", False)
            # shutil.rmtree(projPath)
            self.config.remove_option('projects',self.currentProject.getSelectedItem())
            self.reloadProjects()
            self.currentProject.setSelectedIndex(0)
            self.loadVulnerabilities(self.projPath.getText())

    def popup(self,msg):
        JOptionPane.showMessageDialog(None,msg)

    def addProj(self, event):
        projPath = self.projPath.getText()
        if projPath == None or projPath == "":
            self.popup("Please select path")
            return
        self.config.set('projects', self.projName.getText(), projPath)
        self.saveCfg()
        xml = ET.Element('project')
        name = ET.SubElement(xml, "name")
        path = ET.SubElement(xml, "path")
        details = ET.SubElement(xml, "details")
        autoSaveMode = ET.SubElement(xml, "autoSaveMode")

        name.text = self.projName.getText()
        path.text = projPath
        details.text = self.projDetails.getText()
        autoSaveMode.text = str(self.autoSave.isSelected())
        tree = ET.ElementTree(xml)
        try:
            tree.write(self.getCurrentProjPath()+'/project.xml')
        except:
            self.popup("Invalid path")
            return

        self.reloadProjects()
        self.clearVulnerabilityTab()
        self.clearList(None)
        self.currentProject.getModel().setSelectedItem(self.projName.getText())

    def resize(self, image, width, height):
        bi = BufferedImage(width, height, BufferedImage.TRANSLUCENT)
        g2d = bi.createGraphics()
        g2d.addRenderingHints(RenderingHints(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY))
        g2d.drawImage(image, 0, 0, width, height, None)
        g2d.dispose()
        return bi;

    def clearStr(self, var):
        return var.replace(" " , "_").replace("\\" , "").replace("/" , "").replace(":" , "").replace("*" , "").replace("?" , "").replace("\"" , "").replace("<" , "").replace(">" , "").replace("|" , "").replace("(" , "").replace(")" , "")

    def popUpAreYouSure(self, msg = "Are you sure?"):
        dialogResult = JOptionPane.showConfirmDialog(None,msg,"Warning",JOptionPane.YES_NO_OPTION)
        if dialogResult == 0:
            return 0
        return 1

    def removeSS(self,event):
        if self.popUpAreYouSure() == JOptionPane.YES_OPTION:
            os.remove(self.getCurrentVulnPath() + "/" + self.ssList.getSelectedValue())
            self.ssList.getModel().remove(self.ssList.getSelectedIndex())
            self.firstPic.setIcon(ImageIcon(None))

    def addSS(self,event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        try:
            image = clipboard.getData(DataFlavor.imageFlavor)
        except:
            self.popup("Clipboard not contains image")
            return
        vulnPath = self.projPath.getText() + "/" + self.clearStr(self.vulnName.getText())
        if not os.path.exists(vulnPath):
            os.makedirs(vulnPath)
        name = self.clearStr(self.vulnName.getText()) + str(random.randint(1, 99999))+".jpg"
        fileName = self.projPath.getText()+"/"+ self.clearStr(self.vulnName.getText()) + "/" + name
        file = File(fileName)
        bufferedImage = BufferedImage(image.getWidth(None), image.getHeight(None), BufferedImage.TYPE_INT_RGB);
        g = bufferedImage.createGraphics();
        g.drawImage(image, 0, 0, bufferedImage.getWidth(), bufferedImage.getHeight(), Color.WHITE, None);
        ImageIO.write(bufferedImage, "jpg", file)
        self.addVuln(None)
        self.ssList.setSelectedValue(name,True)

    def rmVuln(self, event):
        if self.popUpAreYouSure() == JOptionPane.YES_OPTION:
            self._requestViewer.setMessage("None", False)
            self._responseViewer.setMessage("None", False)
            shutil.rmtree(self.getCurrentVulnPath())
            self.clearVulnerabilityTab()
            self.loadVulnerabilities(self.getCurrentProjPath())

    def addVuln(self, event):
        newName = self.vulnName.getText()
        if self.addButton.getText() != "Add":
            row = self.logTable.getSelectedRow()
            old = self.logTable.getValueAt(row,1)
            if newName != old:
                if self.popUpAreYouSure("Are you sure you want to change the vulnerability name?") == JOptionPane.YES_OPTION:
                    self.changeVulnName(newName,old)
                else:
                    self.vulnName.setText(old)
                    return
        if self.colorCombo.getSelectedItem() == "Color:":
            colorTxt = None
        else:
            colorTxt = self.colorCombo.getSelectedItem()
        self._lock.acquire()
        row = self._log.size()
        vulnObject = vulnerability(self.vulnName.getText(),self.threatLevel.getSelectedItem(),self.descriptionString.getText(),self.mitigationStr.getText() ,colorTxt)
        self._log.add(vulnObject) 
        self.fireTableRowsInserted(row, row)
        self._lock.release()

        vulnPath = self.projPath.getText() + "/" + self.clearStr(self.vulnName.getText())
        if not os.path.exists(vulnPath):
            os.makedirs(vulnPath)

        xml = ET.Element('vulnerability')
        name = ET.SubElement(xml, "name")
        severity = ET.SubElement(xml, "severity")
        description = ET.SubElement(xml, "description")
        mitigation = ET.SubElement(xml, "mitigation")
        color = ET.SubElement(xml, "color")
        name.text = self.vulnName.getText()
        severity.text = self.threatLevel.getSelectedItem()
        description.text = self.descriptionString.getText()
        mitigation.text = self.mitigationStr.getText()
        color.text = colorTxt
        tree = ET.ElementTree(xml)
        tree.write(vulnPath+'/vulnerability.xml')

        self.loadVulnerabilities(self.getCurrentProjPath())
        self.loadVulnerability(vulnObject)
                
    def changeVulnName(self,new,old):
        newpath = self.getCurrentProjPath() + "/" + self.clearStr(new)
        oldpath = self.getCurrentProjPath() + "/" + self.clearStr(old)
        os.rename(oldpath, newpath)
        self.changeCurrentVuln(new,0, newpath + "/vulnerability.xml")

    def getCurrentVulnPath(self):
        return self.projPath.getText() + "/" + self.clearStr(self.vulnName.getText())

    def getCurrentProjPath(self):
        return self.projPath.getText()

    def loadSS(self, imgPath):
        image = ImageIO.read(File(imgPath))
        if image.getWidth() <= 550 and image.getHeight() <= 400:
            self.firstPic.setIcon(ImageIcon(image))
            self.firstPic.setSize(image.getWidth(),image.getHeight())
        else:
            self.firstPic.setIcon(ImageIcon(self.resize(image,550, 400)))
            self.firstPic.setSize(550,400)

    def clearProjectTab(self):
        self.projPath.setText("")
        self.projDetails.setText("")

    def clearList(self, event):
        self._lock.acquire()
        self._log = ArrayList()
        row = self._log.size()
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # implement IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages();
        if responses > 0:
            ret = LinkedList()
            requestMenuItem = JMenuItem("Send to PT Manager");
            requestMenuItem.addActionListener(handleMenuItems(self,responses[0], "request"))
            ret.add(requestMenuItem);
            return(ret);
        return null;
    #
    # implement ITab
    #
    def getTabCaption(self):
        return "PT Manager"
    
    def getUiComponent(self):
        return self._splitpane

        #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Vulnerability Name"
        if columnIndex == 2:
            return "Threat Level"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        vulnObject = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex+1
        if columnIndex == 1:
            return vulnObject.getName()
        if columnIndex == 2:
            return vulnObject.getSeverity()
        if columnIndex == 3:
            return vulnObject.getMitigation()
        if columnIndex == 4:
            return vulnObject.getColor()

        return ""

    def changeCurrentVuln(self,value,fieldNumber, xmlPath = "def"):
        if xmlPath == "def":
            xmlPath = self.getCurrentVulnPath() + "/vulnerability.xml"
        document = self.getXMLDoc(xmlPath)
        nodeList = document.getDocumentElement().getChildNodes()
        nodeList.item(fieldNumber).setTextContent(value)
        self.saveXMLDoc(document, xmlPath)
        self.loadVulnerabilities(self.getCurrentProjPath())

    def loadVulnerability(self, vulnObject):
        self.addButton.setText("Update")
        self.vulnName.setText(vulnObject.getName())
        self.threatLevel.setSelectedItem(vulnObject.getSeverity())
        self.descriptionString.setText(vulnObject.getDescription())
        self.mitigationStr.setText(vulnObject.getMitigation())

        if vulnObject.getColor() == "" or vulnObject.getColor() == None:
            self.colorCombo.setSelectedItem("Color:")
        else:
            self.colorCombo.setSelectedItem(vulnObject.getColor())
        self.screenshotsList.clear()

        for fileName in os.listdir(self.projPath.getText()+"/"+self.clearStr(vulnObject.getName())):
            if fileName.endswith(".jpg"):
                self.screenshotsList.addElement(fileName)
                imgPath = self.projPath.getText()+"/"+self.clearStr(vulnObject.getName())+'/'+fileName
                self.loadSS(imgPath)

        if (self.screenshotsList.getSize() == 0):
            self.firstPic.setIcon(None)
        else:
            self.ssList.setSelectedIndex(0)

        path = self.getVulnReqResPath("request",vulnObject.getName())
        if os.path.exists(path):
            f = self.getFileContent(path)
            self._requestViewer.setMessage(f, False)
        else:
            self._requestViewer.setMessage("None", False)
        
        path = self.getVulnReqResPath("response",vulnObject.getName())
        if os.path.exists(path):
            f = self.getFileContent(path)
            self._responseViewer.setMessage(f, False)
        else:
            self._responseViewer.setMessage("None", False)

    def loadProject(self, projXMLPath):
        document = self.getXMLDoc(projXMLPath)
        nodeList = document.getDocumentElement().getChildNodes()
        projName = nodeList.item(0).getTextContent()
        path = nodeList.item(1).getTextContent()
        details = nodeList.item(2).getTextContent()
        if nodeList.item(3).getTextContent() == "True":
            autoSaveMode = True
        else:
            autoSaveMode = False
        self.projPath.setText(path)
        self.clearProjTab = True
        self.projName.setText(projName)
        self.projDetails.setText(details)
        self.autoSave.setSelected(autoSaveMode)
        self.currentProject.setSelectedItem(projName.lower())
        self.config.set('general', "default project", self.currentProject.getSelectedItem())
        self.saveCfg()
        self.clearVulnerabilityTab()
        self.loadVulnerabilities(self.projPath.getText())

class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
        self.getColumnModel().getColumn(1).setPreferredWidth(200)
        return

    def prepareRenderer(self, renderer, row, column):
        c = JTable.prepareRenderer(self,renderer, row, column)
        selectedRow = self._extender.logTable.getSelectedRow()
        if row == selectedRow:
            return c
        if self._extender.getValueAt(row,4) == "Green":
            c.setBackground(Color.GREEN)
        elif self._extender.getValueAt(row,4) == "Red":
            c.setBackground(Color.RED)
        else:
            c.setBackground(None)
        
        return c

    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        vulnObject = self._extender._log.get(row)
        self._extender.loadVulnerability(vulnObject)
        JTable.changeSelection(self, row, col, toggle, extend)
        return

class mouseclick(MouseAdapter):

    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())

class imageClicked(MouseAdapter):

    def __init__(self, externder):
        self._extender = externder

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.imgMenu.show(evt.getComponent(), evt.getX(), evt.getY())
        else:
            path = self._extender.getCurrentVulnPath() + "/" + self._extender.ssList.getSelectedValue()
            self._extender.openFolderOrFile(path)

class paintChange(ActionListener):
    def __init__(self, extender, color):
        self._extender = extender
        self._color = color

    def actionPerformed(self, e): 
        self._extender.changeCurrentVuln(self._color,4)     

class copyImg(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        img = ImageIO.read(File(self._extender.getCurrentVulnPath() + "/" + self._extender.ssList.getSelectedValue()))
        trans = ImageTransferable(img)
        c = Toolkit.getDefaultToolkit().getSystemClipboard()
        c.setContents( trans, None )
        
class ImageTransferable(Transferable):
    def __init__(self,image):
        self._image = image

    def getTransferData(self, flavor):
        return self._image

    def getTransferDataFlavors(self):
        return [DataFlavor.imageFlavor]


class ssChangedHandler(ListSelectionListener):
    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, e):
        if self._extender.ssList.getSelectedValue() != None:
            self._extender.loadSS(self._extender.projPath.getText()+'/'+self._extender.clearStr(self._extender.vulnName.getText()) + "/" + self._extender.clearStr(self._extender.ssList.getSelectedValue()))

class projTextChanged(DocumentListener):
    def __init__(self, extender):
        self._extender = extender

    def removeUpdate(self, e):
        if len(inspect.stack()) == 1:
            if self._extender.clearProjTab:
                self._extender.clearProjectTab()
                self._extender.clearProjTab = False
        return
        

    def insertUpdate(self, e):
        if len(inspect.stack()) == 1:
            if self._extender.clearProjTab:
                self._extender.clearProjectTab()
                self._extender.clearProjTab = False
        return

class projectChangeHandler(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        xmlPath = self._extender.config.get('projects',self._extender.currentProject.getSelectedItem()) + "/project.xml"
        self._extender.loadProject(xmlPath)
        
class vulnerability():
    def __init__(self,name,severity,description,mitigation,color):
        self.name = name
        self.severity = severity
        self.description = description
        self.mitigation = mitigation
        self.color = color

    def getName(self):
        return self.name

    def getSeverity(self):
        return self.severity

    def getDescription(self):
        return self.description
    
    def getMitigation(self):
        return self.mitigation
    
    def getColor(self):
        return self.color

class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):

        vulns = []
        for i in range(0,self._extender._log.size()):
            vulns.append(self._extender._log.get(i).getName())

        vulnName = self._extender.vulnName.getText()
        selectedVuln = JOptionPane.showInputDialog(
                    None,
                    "Select related vulnerability:\n",
                    "PT Manager",
                    JOptionPane.PLAIN_MESSAGE,
                    None,
                    vulns,
                    vulnName)

        if selectedVuln != None:
            if self._messageInfo.getRequest() != None:
                self._extender.saveRequestResponse('request',self._messageInfo.getRequest(),selectedVuln)
            else:
                self._extender.saveRequestResponse('request',"None",selectedVuln)
            if self._messageInfo.getResponse() != None:
                self._extender.saveRequestResponse('response',self._messageInfo.getResponse(),selectedVuln)
            else:
                self._extender.saveRequestResponse('response',"None",selectedVuln)
            self._extender.loadVulnerability(self._extender._log.get(vulns.index(vulnName)))