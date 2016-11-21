# Copyright (c) 2016 Mick Ayzenberg - Security Innovation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IContextMenuFactory

from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from java.lang import Boolean;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JPanel;
from javax.swing import JButton;
from javax.swing import JTable;
from javax.swing import JOptionPane;
from javax.swing import SwingUtilities;
from javax.swing import JMenuItem;
from javax.swing import JCheckBox;
from javax.swing import JLabel;
from javax.swing import JFileChooser;
from javax.swing import JPopupMenu;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import TableCellRenderer;
from javax.swing.table import JTableHeader;
from java.awt import Color;
from javax.swing.plaf import UIResource;
from java.awt.event import MouseListener;
from java.awt.event import MouseAdapter;
from java.awt.event import ActionListener;
from javax.swing.border import MatteBorder;

from org.python.core.util import StringUtil
from threading import Lock
from threading import Thread
import traceback
import re
from java import io

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our Burp callbacks object
        self._callbacks = callbacks
        # obtain an Burp extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("AuthMatrix - v0.4")

        # DB that holds everything users, roles, and messages
        self._db = MatrixDB()

        # For saving/loading config
        self._fc = JFileChooser()        

        # Used by ActionListeners
        selfExtender = self
        self._selectedColumn = -1
        self._selectedRow = -1


        # Table of User entries
        self._userTable = UserTable(self, model = UserTableModel(self._db))
        roleScrollPane = JScrollPane(self._userTable)
        self._userTable.redrawTable()

        # Table of Request (AKA Message) entries
        self._messageTable = MessageTable(self, model = MessageTableModel(self._db))
        messageScrollPane = JScrollPane(self._messageTable)
        self._messageTable.redrawTable()


        # Semi-Generic Popup stuff
        def addPopup(component, popup):
            class genericMouseListener(MouseAdapter):
                def mousePressed(self, e):
                    if e.isPopupTrigger():
                        self.showMenu(e)
                def mouseReleased(self, e):
                    if e.isPopupTrigger():
                        self.showMenu(e)
                def showMenu(self, e):
                    if type(component) is JTableHeader:
                        table = component.getTable()
                        column = component.columnAtPoint(e.getPoint())
                        if type(table) is MessageTable and column >= selfExtender._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT or type(table) is UserTable and column >= selfExtender._db.STATIC_USER_TABLE_COLUMN_COUNT:
                            selfExtender._selectedColumn = column
                        else:
                            return
                    else:
                        selfExtender._selectedRow = component.rowAtPoint(e.getPoint())
                    popup.show(e.getComponent(), e.getX(), e.getY())
            component.addMouseListener(genericMouseListener())

        class actionRunMessage(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        indexes = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getMessageByRow(rowNum)._index for rowNum in selfExtender._messageTable.getSelectedRows()]
                    t = Thread(target=selfExtender.runMessagesThread, args = [indexes])
                    t.start()
                    selfExtender._selectedColumn = -1
                    # Redrawing the table happens in colorcode within the thread

        class actionRemoveMessage(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._messageTable.getSelectedRows():
                        indexes = [selfExtender._db.getMessageByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getMessageByRow(rowNum)._index for rowNum in selfExtender._messageTable.getSelectedRows()]
                    for i in indexes:
                        selfExtender._db.deleteMessage(i)
                    selfExtender._selectedColumn = -1
                    selfExtender._messageTable.redrawTable()

        class actionRemoveUser(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedRow >= 0:
                    if selfExtender._selectedRow not in selfExtender._userTable.getSelectedRows():
                        indexes = [selfExtender._db.getUserByRow(selfExtender._selectedRow)._index]
                    else:
                        indexes = [selfExtender._db.getUserByRow(rowNum)._index for rowNum in selfExtender._userTable.getSelectedRows()]
                    for i in indexes:
                        selfExtender._db.deleteUser(i)
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()

        # TODO combine these next two classes
        # TODO Also, clean up the variable names where M and U are in place of MessageTable and UserTable
        class actionRemoveRoleHeaderFromM(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedColumn >= 0:
                    selfExtender._db.deleteRole(selfExtender._db.getRoleByMColumn(selfExtender._selectedColumn)._index)
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()
                    selfExtender._messageTable.redrawTable()

        class actionRemoveRoleHeaderFromU(ActionListener):
            def actionPerformed(self,e):
                if selfExtender._selectedColumn >= 0:
                    selfExtender._db.deleteRole(selfExtender._db.getRoleByUColumn(selfExtender._selectedColumn)._index)
                    selfExtender._selectedColumn = -1
                    selfExtender._userTable.redrawTable()
                    selfExtender._messageTable.redrawTable()


        # Message Table popups
        messagePopup = JPopupMenu()
        addPopup(self._messageTable,messagePopup)
        messageRun = JMenuItem("Run Request(s)")
        messageRun.addActionListener(actionRunMessage())
        messagePopup.add(messageRun)
        messageRemove = JMenuItem("Remove Request(s)")
        messageRemove.addActionListener(actionRemoveMessage())
        messagePopup.add(messageRemove)

        messageHeaderPopup = JPopupMenu()
        addPopup(self._messageTable.getTableHeader(),messageHeaderPopup)
        roleRemoveFromM = JMenuItem("Remove Role")
        roleRemoveFromM.addActionListener(actionRemoveRoleHeaderFromM())
        messageHeaderPopup.add(roleRemoveFromM)

        # User Table popup
        userPopup = JPopupMenu()
        addPopup(self._userTable,userPopup)
        userRemove = JMenuItem("Remove Users(s)")
        userRemove.addActionListener(actionRemoveUser())
        userPopup.add(userRemove)

        userHeaderPopup = JPopupMenu()
        addPopup(self._userTable.getTableHeader(),userHeaderPopup)
        roleRemoveFromU = JMenuItem("Remove Role")
        roleRemoveFromU.addActionListener(actionRemoveRoleHeaderFromU())
        userHeaderPopup.add(roleRemoveFromU)

        # Top pane
        topPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,roleScrollPane,messageScrollPane)
        topPane.setResizeWeight(0.3)

        # request tabs added to this tab on click in message table
        self._tabs = JTabbedPane()


        # Button pannel
        buttons = JPanel()
        runButton = JButton("Run", actionPerformed=self.runClick)
        newUserButton = JButton("New User", actionPerformed=self.getInputUserClick)
        newRoleButton = JButton("New Role", actionPerformed=self.getInputRoleClick)
        #debugButton = JButton("Debug", actionPerformed=self.printDB)
        saveButton = JButton("Save", actionPerformed=self.saveClick)
        loadButton = JButton("Load", actionPerformed=self.loadClick)
        clearButton = JButton("Clear", actionPerformed=self.clearClick)
        buttons.add(runButton)
        buttons.add(newUserButton)
        buttons.add(newRoleButton)
        #buttons.add(debugButton)
        buttons.add(saveButton)
        buttons.add(loadButton)
        buttons.add(clearButton)

        bottomPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._tabs, buttons)
        bottomPane.setResizeWeight(0.95)

        # Main Pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, topPane, bottomPane)
        self._splitpane.setResizeWeight(0.5)



        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(topPane)
        callbacks.customizeUiComponent(bottomPane)
        callbacks.customizeUiComponent(messageScrollPane)
        callbacks.customizeUiComponent(roleScrollPane)
        callbacks.customizeUiComponent(self._messageTable)
        callbacks.customizeUiComponent(self._userTable)
        callbacks.customizeUiComponent(self._tabs)
        callbacks.customizeUiComponent(buttons)

        # Handles checkbox color coding
        # Must be bellow the customizeUiComponent calls
        self._messageTable.setDefaultRenderer(Boolean, SuccessBooleanRenderer(self._db))


        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)        
        # register SendTo option
        callbacks.registerContextMenuFactory(self)

        return
        
    ##
    ## implement ITab
    ##
    
    def getTabCaption(self):
        return "AuthMatrix"
    
    def getUiComponent(self):
        return self._splitpane
       

    ##
    ## Creates the sendto tab in other areas of Burp
    ##

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()

        def addRequestsToTab(e):
            for messageInfo in messages:
                # saveBuffers is required since modifying the original from its source changes the saved objects, its not a copy
                messageIndex = self._db.createNewMessage(self._callbacks.saveBuffersToTempFiles(messageInfo), 
                    self._helpers.analyzeRequest(messageInfo).getUrl())
                #self._messageTable.getModel().addRow(row)
            self._messageTable.redrawTable()

        ret = []
        menuItem = JMenuItem("Send request(s) to AuthMatrix");
        menuItem.addActionListener(addRequestsToTab)
        ret.append(menuItem)
        return(ret)

    
    ##
    ## implement IMessageEditorController
    ## this allows our request/response viewers to obtain details about the messages being displayed
    ##
    ## TODO: Is this necessary? The request viewers may not require this since they aren't editable
    ##

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    ##
    ## Actions on Bottom Row Button Clicks
    ##

    def printDB(self, e):
        out = ""
        for a in self._db.arrayOfUsers:
            out += str(a._index)+" "+a._name+" : "+str(a._roles)+"\n"
        for b in self._db.arrayOfMessages:
            out += str(b._index)+" "+str(b._roles)+"\n"
        JOptionPane.showMessageDialog(self._splitpane,out)

    def getInputUserClick(self, e):
        newUser = JOptionPane.showInputDialog(self._splitpane,"Enter New User:")
        if not newUser is None:
            self._db.getOrCreateUser(newUser)
            self._userTable.redrawTable()

    def getInputRoleClick(self, e):
        newRole = JOptionPane.showInputDialog(self._splitpane,"Enter New Role:")
        if not newRole is None:
            self._db.getOrCreateRole(newRole)
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def saveClick(self, e):
        returnVal = self._fc.showSaveDialog(self._splitpane)
        if returnVal == JFileChooser.APPROVE_OPTION:
            f = self._fc.getSelectedFile()
            if f.exists():
                result = JOptionPane.showConfirmDialog(self._splitpane, "The file exists, overwrite?", "Existing File", JOptionPane.YES_NO_OPTION)
                if result != JOptionPane.YES_OPTION:
                    return
            fileName = f.getPath()
            outs = io.ObjectOutputStream(io.FileOutputStream(fileName))
            outs.writeObject(self._db.getSaveableObject())
            outs.close()

    def loadClick(self,e):
        returnVal = self._fc.showOpenDialog(self._splitpane)
        if returnVal == JFileChooser.APPROVE_OPTION:
            warning = """
            CAUTION: 

            Loading a saved configuration deserializes data. 
            This action may pose a security threat to the application.
            Only proceed when the source and contents of this file is trusted. 

            Load Selected File?
            """
            result = JOptionPane.showOptionDialog(self._splitpane, warning, "Caution", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, None, ["OK", "Cancel"],"OK")
            if result != JOptionPane.YES_OPTION:
                return
            f = self._fc.getSelectedFile()
            fileName = f.getPath()
            
            ins = io.ObjectInputStream(io.FileInputStream(fileName))
            dbData=ins.readObject()
            ins.close()

            self._db.load(dbData,self._callbacks, self._helpers)
            self._userTable.redrawTable()
            self._messageTable.redrawTable()

    def clearClick(self,e):
        self._db.clear()
        self._tabs.removeAll()
        self._userTable.redrawTable()
        self._messageTable.redrawTable()

    def runClick(self,e):
        t = Thread(target=self.runMessagesThread)
        self._tabs.removeAll()
        t.start()

    ##
    ## Methods for running messages and analyzing results
    ##

    def runMessagesThread(self, messageIndexes=None):
        self._db.lock.acquire()
        try:
            indexes = messageIndexes
            if not indexes:
                indexes = self._db.getActiveMessageIndexes()
            self.clearColorResults(indexes)
            for index in indexes:
                self.runMessage(index)
                #self.colorCodeResults()
        except:
            traceback.print_exc(file=self._callbacks.getStderr())
        finally:
            self._db.lock.release()
            self.colorCodeResults()

    # TODO: This method is too large. Fix that
    def runMessage(self, messageIndex):
        messageEntry = self._db.arrayOfMessages[messageIndex]
        # Clear Previous Results:
        messageEntry._roleResults = {}
        messageEntry._userRuns = {}

        messageInfo = messageEntry._requestResponse
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        reqBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        for userIndex in self._db.getActiveUserIndexes():
            userEntry = self._db.arrayOfUsers[userIndex]
            headers = requestInfo.getHeaders()
            if userEntry.isCookie():
                cookieHeader = "Cookie:"
                newheader = cookieHeader
                # getHeaders has to be called again here cuz of java references
                for header in requestInfo.getHeaders():
                    if str(header).startswith(cookieHeader):
                        newheader = str(header).strip()
                        headers.remove(header)

                # If its a valid cookie
                equals = userEntry._token.find("=")
                if equals >= 0:
                    cookieIndex = newheader.find(userEntry._token[0:equals+1])
                    # Cookie already exists and must be removed
                    if cookieIndex >= 0:
                        semicolon = newheader.find(";",cookieIndex)
                        if semicolon >=0:
                            # Remove extra whitespace
                            if newheader[semicolon+1:semicolon+2] == " ":
                                newheader = newheader.replace(newheader[cookieIndex:semicolon+2],"")
                            else:
                                newheader = newheader.replace(newheader[cookieIndex:semicolon+1],"")
                        else:
                            newheader = newheader.replace(newheader[cookieIndex:],"")
                        # Removing tailing semicolon and white space
                        newheader = newheader.rstrip("; ")
                # Handle when the only cookie is the target cookie
                if not newheader == cookieHeader:
                    newheader += ";"
                newheader += " "+userEntry._token

            # Header
            else:
                newheader = userEntry._token
                colon = newheader.find(":")
                if colon >= 0:
                    # getHeaders has to be called again here cuz of java references
                    for header in requestInfo.getHeaders():
                        if str(header).startswith(newheader[0:colon+1]):
                            headers.remove(header)

            headers.add(newheader)

            # Add static CSRF token if available
            # TODO: Kinda hacky, but for now it will add the token as long as there is some content in the post body
            # Even if its a GET request.  This screws up when original requests have no body though... oh well...
            newBody = reqBody
            if userEntry._staticcsrf and len(reqBody):
                delimeter = userEntry._staticcsrf.find("=")
                if delimeter >= 0:
                    csrfname = userEntry._staticcsrf[0:delimeter]
                    csrfvalue = userEntry._staticcsrf[delimeter+1:]
                    params = requestInfo.getParameters()
                    for param in params:
                        if str(param.getName())==csrfname:
                            # Handle CSRF Tokens in Body
                            if param.getType() == 1:
                                newBody = reqBody[0:param.getValueStart()-requestInfo.getBodyOffset()] + StringUtil.toBytes(csrfvalue) + reqBody[param.getValueEnd()-requestInfo.getBodyOffset():]
                            # Handle CSRF Tokens in Cookies (for Cookie==Body mitigation technique):
                            if param.getType() == 2:
                                # TODO: required moving above portion to a function
                                # TODO: also need to think about when cookie name != postarg name
                                print "Cookie CSRF Tokens are not currently supported"
                    if newBody == reqBody:
                        newBody = reqBody+StringUtil.toBytes("&"+userEntry._staticcsrf)



            # Construct and send a message with the new headers
            message = self._helpers.buildHttpMessage(headers, newBody)
            requestResponse = self._callbacks.makeHttpRequest(messageInfo.getHttpService(),message)
            messageEntry.addRunByUserIndex(userIndex, self._callbacks.saveBuffersToTempFiles(requestResponse))

        # Grab all active roleIndexes that should succeed
        activeSuccessRoles = [index for index in messageEntry._roles.keys() if messageEntry._roles[index] and not self._db.arrayOfRoles[index].isDeleted()]
        # Check Role Results of message
        for roleIndex in self._db.getActiveRoleIndexes():
            success = self.checkResult(messageEntry, roleIndex, activeSuccessRoles)
            messageEntry.setRoleResultByRoleIndex(roleIndex, success)
                    
    def colorCodeResults(self):
        self._messageTable.redrawTable()

    def clearColorResults(self, messageIndexArray = None):
        if not messageIndexArray:
            messageIndexes = self._db.getActiveMessageIndexes()
        else:
            messageIndexes = messageIndexArray
        for messageIndex in messageIndexes:
            messageEntry = self._db.arrayOfMessages[messageIndex]
            messageEntry._roleResults = {}
            messageEntry._userRuns = {}
        self._messageTable.redrawTable()

    def checkResult(self, messageEntry, roleIndex, activeSuccessRoles):
        for userIndex in self._db.getActiveUserIndexes():
            userEntry = self._db.arrayOfUsers[userIndex]

            ignoreUser = False
            # if user is not in this role, ignore it
            if not userEntry._roles[roleIndex]:
                ignoreUser = True
            # If user is in any other role that should succeed, then ignore it
            for index in userEntry._roles.keys():
                if not index == roleIndex and userEntry._roles[index] and index in activeSuccessRoles:
                    ignoreUser = True

            if not ignoreUser:
                shouldSucceed = roleIndex in activeSuccessRoles
                requestResponse = messageEntry._userRuns[userEntry._index]
                resp = StringUtil.fromBytes(requestResponse.getResponse())
                found = re.search(messageEntry._successRegex, resp, re.DOTALL)
                succeeds = found if shouldSucceed else not found
                if not succeeds:
                    return False
        return True

##
## DB Class that holds all configuration data
##

class MatrixDB():

    def __init__(self):
        # Holds all custom data
        # TODO: consider moving these constants to a different class
        self.STATIC_USER_TABLE_COLUMN_COUNT = 3
        self.STATIC_MESSAGE_TABLE_COLUMN_COUNT = 3

        self.lock = Lock()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0

    # Returns the index of the user, whether its new or not
    def getOrCreateUser(self, name, token=""):
        self.lock.acquire()
        userIndex = -1
        # Check if User already exits
        for i in self.getActiveUserIndexes():
            if self.arrayOfUsers[i]._name == name:
                userIndex = i
        # Add new User
        if userIndex < 0:
            userIndex = self.arrayOfUsers.size()
            self.arrayOfUsers.append(UserEntry(userIndex,
                userIndex - self.deletedUserCount,
                name, token))

            # Add all existing roles as unchecked
            for roleIndex in self.getActiveRoleIndexes():
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return userIndex

    # Returns the index of the role, whether its new or not
    def getOrCreateRole(self, role):
        self.lock.acquire()
        roleIndex = -1
        # Check if Role already exists
        for i in self.getActiveRoleIndexes():
            if self.arrayOfRoles[i]._name == role:
                roleIndex = i
        # Add new Role
        if roleIndex < 0:
            roleIndex = self.arrayOfRoles.size()
            self.arrayOfRoles.append(RoleEntry(roleIndex,
                roleIndex + self.STATIC_MESSAGE_TABLE_COLUMN_COUNT - self.deletedRoleCount,
                roleIndex + self.STATIC_USER_TABLE_COLUMN_COUNT - self.deletedRoleCount,
                role))

            # Add new role to each existing user as unchecked
            for userIndex in self.getActiveUserIndexes():
                self.arrayOfUsers[userIndex].addRoleByIndex(roleIndex)

            # Add new role to each existing message as unchecked
            for messageIndex in self.getActiveMessageIndexes():
                self.arrayOfMessages[messageIndex].addRoleByIndex(userIndex)

        self.lock.release()
        return roleIndex

    # Returns the Row of the new message
    # Unlike Users and Roles, allow duplicate messages
    def createNewMessage(self,messagebuffer,url):
        self.lock.acquire()
        messageIndex = self.arrayOfMessages.size()
        self.arrayOfMessages.add(MessageEntry(messageIndex, messageIndex - self.deletedMessageCount, messagebuffer, url))

        # Add all existing roles as unchecked
        for roleIndex in self.getActiveRoleIndexes():
            self.arrayOfMessages[messageIndex].addRoleByIndex(roleIndex)

        self.lock.release()
        return messageIndex

    def clear(self):
        self.lock.acquire()
        self.arrayOfMessages = ArrayList()
        self.arrayOfRoles = ArrayList()
        self.arrayOfUsers = ArrayList()
        self.deletedUserCount = 0
        self.deletedRoleCount = 0
        self.deletedMessageCount = 0
        self.lock.release()

    def load(self, db, callbacks, helpers):
        def loadRequestResponse(index, callbacks, helpers, host, port, protocol, requestData):
            # TODO tempRequestResont is now an array
            # because of a timing issue, where if this thread times out, it will still update temprequestresponse later on..
            # TODO also this still locks the UI until all requests suceed or time out...
            try:
                # Due to Burp Extension API, must create a original request for all messages
                self.tempRequestResponse[index] = callbacks.makeHttpRequest(helpers.buildHttpService(host, port, protocol),requestData)
            except:
                traceback.print_exc(file=callbacks.getStderr())

        self.lock.acquire()
        self.arrayOfRoles = db.arrayOfRoles
        self.arrayOfUsers = db.arrayOfUsers
        self.deletedUserCount = db.deletedUserCount
        self.deletedRoleCount = db.deletedRoleCount
        self.deletedMessageCount = db.deletedMessageCount
        self.arrayOfMessages = ArrayList()

        self.tempRequestResponse = []
        index=0
        for message in db.arrayOfMessages: 
            self.tempRequestResponse.append(None)
            t = Thread(target=loadRequestResponse, args = [index, callbacks, helpers, message._host, message._port, message._protocol, message._requestData])
            t.start()
            # TODO fix timeout here to be non-static
            t.join(2.0)
            if not t.isAlive() and self.tempRequestResponse[index] != None:
                self.arrayOfMessages.append(MessageEntry(
                    message._index,
                    message._tableRow,
                    callbacks.saveBuffersToTempFiles(self.tempRequestResponse[index]),
                    message._url, message._name, message._roles, message._successRegex, message._deleted))
            index += 1
        self.lock.release()

    

    def getSaveableObject(self):
        # TODO: might not need locks?
        self.lock.acquire()
        serializedMessages = []
        for message in self.arrayOfMessages:
            serializedMessages.append(MessageEntryData(
                message._index, 
                message._tableRow,
                message._requestResponse.getRequest(), 
                message._requestResponse.getHttpService().getHost(),
                message._requestResponse.getHttpService().getPort(),
                message._requestResponse.getHttpService().getProtocol(),
                message._url, message._name, message._roles, message._successRegex, message._deleted))
        ret = MatrixDBData(serializedMessages,self.arrayOfRoles, self.arrayOfUsers, self.deletedUserCount, self.deletedRoleCount, self.deletedMessageCount)
        self.lock.release()
        return ret

    def getActiveUserIndexes(self):
        return [x._index for x in self.arrayOfUsers if not x.isDeleted()]

    def getActiveRoleIndexes(self):
        return [x._index for x in self.arrayOfRoles if not x.isDeleted()]

    def getActiveMessageIndexes(self):
        return [x._index for x in self.arrayOfMessages if not x.isDeleted()]

    def getMessageByRow(self, row):
        for m in self.arrayOfMessages:
            if not m.isDeleted() and m.getTableRow() == row:
                return m

    def getUserByRow(self, row):
        for u in self.arrayOfUsers:
            if not u.isDeleted() and u.getTableRow() == row:
                return u

    def getRoleByMColumn(self, column):
        for r in self.arrayOfRoles:
            if not r.isDeleted() and r.getMTableColumn() == column:
                return r

    def getRoleByUColumn(self, column):
        for r in self.arrayOfRoles:
            if not r.isDeleted() and r.getUTableColumn() == column:
                return r

    def deleteUser(self,userIndex):
        self.lock.acquire()
        userEntry = self.arrayOfUsers[userIndex]
        if userEntry:
            userEntry._deleted = True
            self.deletedUserCount += 1
            if len(self.arrayOfUsers) > userIndex+1:
                for i in self.arrayOfUsers[userIndex+1:]:
                    i._tableRow -= 1
        self.lock.release()

    def deleteRole(self,roleIndex):
        self.lock.acquire()
        roleEntry = self.arrayOfRoles[roleIndex]
        if roleEntry:
            roleEntry._deleted = True
            self.deletedRoleCount += 1
            if len(self.arrayOfRoles) > roleIndex+1:
                for i in self.arrayOfRoles[roleIndex+1:]:
                    i.updateMTableColumn(i.getMTableColumn()-1)
                    i.updateUTableColumn(i.getUTableColumn()-1)
        self.lock.release()

    def deleteMessage(self,messageIndex):
        self.lock.acquire()
        messageEntry = self.arrayOfMessages[messageIndex]
        if messageEntry:
            messageEntry._deleted = True
            self.deletedMessageCount += 1
            if len(self.arrayOfMessages) > messageIndex+1:
                for i in self.arrayOfMessages[messageIndex+1:]:
                    i._tableRow -= 1
        self.lock.release()

    # TODO: If this method is unused, probably remove it?
    def getUserEntriesWithinRole(self, roleIndex):
        return [userEntry for userEntry in self.arrayOfUsers if userEntry._roles[roleIndex]]


##
## Tables and Table Models  
##
    
class UserTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        try:
            return len(self._db.getActiveUserIndexes())
        except:
            return 0

    def getColumnCount(self):
        # TODO maybe remove this try?
        try:
            return len(self._db.getActiveRoleIndexes())+self._db.STATIC_USER_TABLE_COLUMN_COUNT
        except:
            return self._db.STATIC_USER_TABLE_COLUMN_COUNT

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "User"
        elif columnIndex == 1:
            return "Session Token"
        elif columnIndex == 2:
            return "(Optional) CSRF Token"
        else:
            roleEntry = self._db.getRoleByUColumn(columnIndex)
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        userEntry = self._db.getUserByRow(rowIndex)
        if userEntry:
            if columnIndex == 0:
                return str(userEntry._name)
            elif columnIndex == 1:
                return userEntry._token
            elif columnIndex == 2:
                return userEntry._staticcsrf
            else:
                roleEntry = self._db.getRoleByUColumn(columnIndex)
                if roleEntry:
                    roleIndex = roleEntry._index
                    return roleIndex in userEntry._roles and userEntry._roles[roleIndex]
        return ""

    def addRow(self, row):
        self.fireTableRowsInserted(row,row)

    def setValueAt(self, val, row, col):
        # NOTE: testing if .locked is ok here since its a manual operation
        if self._db.lock.locked():
            return
        userEntry = self._db.getUserByRow(row)
        if userEntry:
            if col == 0:
                userEntry._name = val
            elif col == 1:
                userEntry._token = val
            elif col == 2:
                userEntry._staticcsrf = val
            else:
                roleIndex = self._db.getRoleByUColumn(col)._index
                userEntry.addRoleByIndex(roleIndex, val)

        self.fireTableCellUpdated(row,col)

    # Set checkboxes and role editable
    def isCellEditable(self, row, col):
        return True
        
    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex <= 2:
            return str
        else:
            return Boolean


class UserTable(JTable):

    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)
        return

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()
        
        # Resize
        # User Name
        self.getColumnModel().getColumn(0).setMinWidth(100);
        self.getColumnModel().getColumn(0).setMaxWidth(1000);

        # Session Token
        self.getColumnModel().getColumn(1).setMinWidth(300);
        self.getColumnModel().getColumn(1).setMaxWidth(1500);

        # CSRF Token
        self.getColumnModel().getColumn(2).setMinWidth(150);
        self.getColumnModel().getColumn(2).setMaxWidth(1500);

        self.getTableHeader().getDefaultRenderer().setHorizontalAlignment(JLabel.CENTER)


class MessageTableModel(AbstractTableModel):

    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        try:
            return len(self._db.getActiveMessageIndexes())
        except:
            return 0

    def getColumnCount(self):
        return self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT+len(self._db.getActiveRoleIndexes())

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        elif columnIndex == 1:
            return "Request Name"
        elif columnIndex == 2:
            return "Success Regex"
        else:
            roleEntry = self._db.getRoleByMColumn(columnIndex)
            if roleEntry:
                return roleEntry._name
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        messageEntry = self._db.getMessageByRow(rowIndex)
        if messageEntry:
            if columnIndex == 0:
                return str(messageEntry.getTableRow())
            elif columnIndex == 1:
                return messageEntry._name
            elif columnIndex == 2:
                return messageEntry._successRegex
            else:
                roleEntry = self._db.getRoleByMColumn(columnIndex)
                if roleEntry:
                    roleIndex = roleEntry._index
                    return roleIndex in messageEntry._roles and messageEntry._roles[roleIndex]
        return ""

    def addRow(self, row):
        self.fireTableRowsInserted(row,row)

    def setValueAt(self, val, row, col):
        # NOTE: testing if .locked is ok here since its a manual operation
        if self._db.lock.locked():
            return
        messageEntry = self._db.getMessageByRow(row)
        if col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-2:
            messageEntry._name = val
        elif col == self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-1:
            messageEntry._successRegex = val
        else:
            roleIndex = self._db.getRoleByMColumn(col)._index
            messageEntry.addRoleByIndex(roleIndex,val)
        self.fireTableCellUpdated(row,col)

    # Set checkboxes editable
    def isCellEditable(self, row, col):
        # Include regex
        if col >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT-2:
            return True
        return False

    # Create checkboxes
    def getColumnClass(self, columnIndex):
        if columnIndex < self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT:
            return str
        else:
            return Boolean



class MessageTable(JTable):

    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the message entry for the selected row
        selectedMessage = self.getModel()._db.getMessageByRow(row)
        self._extender._tabs.removeAll()

        # NOTE: testing if .locked is ok here since its a manual operation
        if self.getModel()._db.lock.locked():
            # Provide some feedback on a click
            self.redrawTable()
            return

        # Create original Request tab and set default tab to Request
        # Then Create test tabs and set the default tab to Response for easy analysis
        originalTab = self.createRequestTabs(selectedMessage._requestResponse)
        originalTab.setSelectedIndex(0)
        self._extender._tabs.addTab("Original",originalTab)
        for userIndex in selectedMessage._userRuns.keys():
            if not self.getModel()._db.arrayOfUsers[userIndex].isDeleted():
                tabname = str(self.getModel()._db.arrayOfUsers[userIndex]._name)
                self._extender._tabs.addTab(tabname,self.createRequestTabs(selectedMessage._userRuns[userIndex]))
                
        # TODO: do this on a tab change on extender._tabs: I think its needed for sending to repeater and comparer
        self._extender._currentlyDisplayedItem = selectedMessage._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
        return

    def createRequestTabs(self, requestResponse):
        requestTabs = JTabbedPane()
        requestViewer = self._extender._callbacks.createMessageEditor(self._extender, False)
        responseViewer = self._extender._callbacks.createMessageEditor(self._extender, False)
        requestTabs.addTab("Request", requestViewer.getComponent())
        requestTabs.addTab("Response", responseViewer.getComponent())
        self._extender._callbacks.customizeUiComponent(requestTabs)
        # TODO: consider adding the results when clicking the tab (lazy instantiation) since it can get slow
        requestViewer.setMessage(requestResponse.getRequest(), True)
        if requestResponse.getResponse():
            responseViewer.setMessage(requestResponse.getResponse(), False)
            requestTabs.setSelectedIndex(1)

        return requestTabs

    def redrawTable(self):
        # NOTE: this is prob ineffecient but it should catchall for changes to the table
        self.getModel().fireTableStructureChanged()
        self.getModel().fireTableDataChanged()

        # Resize
        self.getColumnModel().getColumn(0).setMinWidth(30);
        self.getColumnModel().getColumn(0).setMaxWidth(30);
        self.getColumnModel().getColumn(1).setMinWidth(300);
        self.getColumnModel().getColumn(2).setMinWidth(150);

# For color-coding checkboxes in the message table
class SuccessBooleanRenderer(JCheckBox,TableCellRenderer):

    def __init__(self, db):
        self.setOpaque(True)
        self.setHorizontalAlignment(JLabel.CENTER)
        self._db = db

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        if value:
            self.setSelected(True)
        else:
            self.setSelected(False)
        if isSelected:
            self.setForeground(table.getSelectionForeground())
            self.setBackground(table.getSelectionBackground())
        else:
            self.setForeground(table.getForeground())
            self.setBackground(table.getBackground())

        # Color based on results
        # TODO adjust to more pleasant colors
        if column >= self._db.STATIC_MESSAGE_TABLE_COLUMN_COUNT:
            messageEntry = self._db.getMessageByRow(row)
            if messageEntry:
                roleEntry = self._db.getRoleByMColumn(column)
                if roleEntry:
                    roleIndex = roleEntry._index
                    if not roleIndex in messageEntry._roleResults:
                        self.setBackground(table.getBackground())
                    else:
                        # TODO: Make a Border for the results that looks good
                        #self.setBorder(MatteBorder(0,1,1,0,Color.BLACK))
                        #self.setBorderPainted(True)
                        if messageEntry._roleResults[roleIndex]:
                            self.setBackground(Color.GREEN)
                        else:
                            self.setBackground(Color.RED)

        return self
      

##
## Classes for Messages, Roles, and Users
##

class MessageEntry:

    def __init__(self, index, tableRow, requestResponse, url, name = "", roles = {}, regex = "^HTTP/1\\.1 200 OK", deleted = False):
        self._index = index
        self._tableRow = tableRow
        self._requestResponse = requestResponse
        self._url = url
        self._name = url.getPath() if not name else name
        self._roles = roles.copy()
        self._successRegex = regex
        self._deleted = deleted
        self._userRuns = {}
        self._roleResults = {}
        return

    # Role are the index of the db Role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self,userIndex,enabled=False):
        self._roles[userIndex] = enabled;

    # Add one Run Result of user x message
    def addRunByUserIndex(self,userIndex,requestResponse):
        self._userRuns[userIndex] = requestResponse

    def setRoleResultByRoleIndex(self, roleIndex, roleResult):
        # TODO maybe make this where its calculated
        self._roleResults[roleIndex] = roleResult

    def isDeleted(self):
        return self._deleted

    def updateTableRow(self, row):
        self._tableRow = row

    def getTableRow(self):
        return self._tableRow

class UserEntry:

    def __init__(self, index, rowIndex, name, token=""):
        self._index = index
        self._name = name
        self._roles = {}
        self._deleted = False
        self._tableRow = rowIndex
        self._token = token
        self._staticcsrf = ""
        return

    # Roles are the index of the db role array and a bool for whether the checkbox is default enabled or not
    def addRoleByIndex(self, roleIndex, enabled=False):
        self._roles[roleIndex] = enabled

    def isDeleted(self):
        return self._deleted

    def updateTableRow(self, row):
        self._tableRow = row

    def getTableRow(self):
        return self._tableRow

    def isCookie(self):
        return self._token.find("=") > 0 and (self._token.find(":") == -1 or self._token.find("=") < self._token.find(":"))

class RoleEntry:

    def __init__(self,index,mTableColumnIndex,uTableColumnIndex,name):
        self._index = index
        self._name = name
        self._deleted = False
        self._mTableColumn = mTableColumnIndex
        self._uTableColumn = uTableColumnIndex
        return

    def isDeleted(self):
        return self._deleted

    def updateMTableColumn(self, column):
        self._mTableColumn = column

    def getMTableColumn(self):
        return self._mTableColumn

    def updateUTableColumn(self, column):
        self._uTableColumn = column

    def getUTableColumn(self):
        return self._uTableColumn

##
## SERIALIZABLE CLASSES
##

# Serializable DB
# Used to store Database to Disk on Save and Load
class MatrixDBData():

    def __init__(self, m, r, u, cu, cr, cm):
        
        self.arrayOfMessages = m
        self.arrayOfRoles = r
        self.arrayOfUsers = u
        self.deletedUserCount = cu
        self.deletedRoleCount = cr
        self.deletedMessageCount = cm

# Serializable MessageEntry
# Used since the Burp RequestResponse object can not be serialized
class MessageEntryData:

    def __init__(self, index, tableRow, requestData, host, port, protocol, url, name, roles, successRegex, deleted):
        self._index = index
        self._tableRow = tableRow
        self._requestData = requestData
        self._host = host
        self._port = port
        self._protocol = protocol
        self._url = url
        self._name = name
        self._roles = roles
        self._successRegex = successRegex
        self._deleted = deleted
        return
