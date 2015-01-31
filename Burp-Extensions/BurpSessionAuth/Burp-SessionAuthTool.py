# Burp SessionAuthTool Extension
# Copyright 2013 Thomas Skora <thomas@skora.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import (IBurpExtender, ITab, IScannerCheck, IScanIssue, IContextMenuFactory, IContextMenuInvocation, IParameter, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator)
from javax.swing import (JPanel, JTable, JButton, JTextField, JLabel, JScrollPane, JMenuItem)
from javax.swing.table import AbstractTableModel
from java.awt import (GridBagLayout, GridBagConstraints)
from array import array
import pickle

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IContextMenuFactory, IParameter, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Session Authentication Tool")
        self.out = callbacks.getStdout()

        # definition of suite tab
        self.tab = JPanel(GridBagLayout())
        self.tabledata = MappingTableModel(callbacks)
        self.table = JTable(self.tabledata)
        #self.table.getColumnModel().getColumn(0).setPreferredWidth(50);
        #self.table.getColumnModel().getColumn(1).setPreferredWidth(100);
        self.tablecont = JScrollPane(self.table)
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.gridx = 0
        c.gridy = 0
        c.gridheight = 6
        c.weightx = 0.3
        c.weighty = 0.5
        self.tab.add(self.tablecont, c)

        c = GridBagConstraints()
        c.weightx = 0.1
        c.anchor = GridBagConstraints.FIRST_LINE_START
        c.gridx = 1

        c.gridy = 0
        label_id = JLabel("Identifier:")
        self.tab.add(label_id, c)
        self.input_id = JTextField(20)
        self.input_id.setToolTipText("Enter the identifier which is used by the application to identifiy a particular test user account, e.g. a numerical user id or a user name.")
        c.gridy = 1
        self.tab.add(self.input_id, c)

        c.gridy = 2
        label_content = JLabel("Content:")
        self.tab.add(label_content, c)
        self.input_content = JTextField(20, actionPerformed=self.btn_add_id)
        self.input_content.setToolTipText("Enter some content which is displayed in responses of the application and shows that the current session belongs to a particular user, e.g. the full name of the user.")
        c.gridy = 3
        self.tab.add(self.input_content, c)

        self.btn_add = JButton("Add/Edit Identity", actionPerformed=self.btn_add_id)
        c.gridy = 4
        self.tab.add(self.btn_add, c)

        self.btn_del = JButton("Delete Identity", actionPerformed=self.btn_del_id)
        c.gridy = 5
        self.tab.add(self.btn_del, c)

        callbacks.customizeUiComponent(self.tab)
        callbacks.customizeUiComponent(self.table)
        callbacks.customizeUiComponent(self.tablecont)
        callbacks.customizeUiComponent(self.btn_add)
        callbacks.customizeUiComponent(self.btn_del)
        callbacks.customizeUiComponent(label_id)
        callbacks.customizeUiComponent(self.input_id)
        callbacks.addSuiteTab(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerContextMenuFactory(self)

    def btn_add_id(self, e):
        ident = self.input_id.text
        self.input_id.text = ""
        content = self.input_content.text
        self.input_content.text = ""
        self.tabledata.add_mapping(ident, content)
        self.input_id.requestFocusInWindow()

    def btn_del_id(self, e):
        rows = self.table.getSelectedRows().tolist()
        self.tabledata.del_rows(rows)

    ### ITab ###
    def getTabCaption(self):
        return("SessionAuth")

    def getUiComponent(self):
        return self.tab

    ### IContextMenuFactory ###
    def createMenuItems(self, invocation):
        menuitems = list()
        msgs = invocation.getSelectedMessages()
        if msgs != None:
            if len(msgs) == 1:              # "add as object id/as content to last id" context menu items
                bounds = invocation.getSelectionBounds()
                if bounds != None and bounds[0] != bounds[1]:
                    msg = None
                    if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST or invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
                        msg = msgs[0].getRequest().tostring()
                    if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE or invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                        msg = msgs[0].getResponse().tostring()
                    if msg != None:
                        selection = msg[bounds[0]:bounds[1]]
                        shortSelection = selection[:20]
                        if len(selection) > len(shortSelection):
                            shortSelection += "..."
                        menuitems.append(JMenuItem("Add '" + shortSelection + "' as object id", actionPerformed=self.gen_menu_add_id(selection)))
                        if self.tabledata.lastadded != None:
                            menuitems.append(JMenuItem("Add '" + shortSelection + "' as content to last added id", actionPerformed=self.gen_menu_add_content(selection)))
            if len(msgs) > 0:             # "Send to Intruder" context menu items
                requestsWithIds = list()
                for msg in msgs:
                    if isinstance(msg.getRequest(), array) and self.tabledata.containsId(msg.getRequest().tostring()):
                        requestsWithIds.append(msg)
                if len(requestsWithIds) > 0:
                    menuitems.append(JMenuItem("Send to Intruder and preconfigure id injection points", actionPerformed=self.gen_menu_send_intruder(requestsWithIds)))

        return menuitems

    def gen_menu_add_id(self, ident):
        def menu_add_id(e):
            self.tabledata.add_mapping(ident, "")
        return menu_add_id

    def gen_menu_add_content(self, content):
        def menu_add_content(e):
            self.tabledata.set_lastadded_content(content)
        return menu_add_content

    def gen_menu_send_intruder(self, requestResponses):
        def menu_send_intruder(e):
            for requestResponse in requestResponses:
                httpService = requestResponse.getHttpService()
                request = requestResponse.getRequest()
                injectionPoints = list()
                for ident in self.tabledata.getIds():
                    newInjectionPoints = findAll(request.tostring(), ident)
                    if newInjectionPoints != None:
                        injectionPoints += newInjectionPoints
                if len(injectionPoints) > 0:
                    self.callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), httpService.getProtocol() == "https", request, injectionPoints)
        return menu_send_intruder

    ### IIntruderPayloadGeneratorFactory ###
    def getGeneratorName(self):
        return "SessionAuth Identifiers"

    def createNewInstance(self, attack):
        return IdentifiersPayloadGenerator(self.tabledata)

    ### IScannerCheck ###
    def doPassiveScan(self, baseRequestResponse):
        analyzedRequest = self.helpers.analyzeRequest(baseRequestResponse)
        params = analyzedRequest.getParameters()
        ids = self.tabledata.getIds()
        issues = list()

        for param in params:
            value = param.getValue()
            for ident in ids:
                if value == ident:
                    issues.append(SessionAuthPassiveScanIssue(
                        analyzedRequest.getUrl(),
                        baseRequestResponse,
                        param,
                        ident,
                        self.tabledata.getValue(ident),
                        SessionAuthPassiveScanIssue.foundEqual,
                        self.callbacks
                        ))
                elif value.find(ident) >= 0:
                    issues.append(SessionAuthPassiveScanIssue(
                        analyzedRequest.getUrl(),
                        baseRequestResponse,
                        param,
                        ident,
                        self.tabledata.getValue(ident),
                        SessionAuthPassiveScanIssue.foundInside,
                        self.callbacks
                        ))
        if len(issues) > 0:
            return issues
        else:
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        ids = self.tabledata.getIds()
        if len(ids) <= 1:                 # active check only possible if multiple ids were given
            return None
        baseVal = insertionPoint.getBaseValue()
        url = baseRequestResponse.getUrl()

        idFound = list()
        for ident in ids:                 # find all identifiers in base value
            if baseVal.find(ident) >= 0:
                idFound.append(ident)
        if len(idFound) == 0:             # no given identifier found, nothing to do
            return None

        baseResponse = baseRequestResponse.getResponse().tostring()
        baseResponseBody = baseResponse[self.helpers.analyzeResponse(baseResponse).getBodyOffset():]
        issues = list()
        scannedCombos = list()
        for replaceId in idFound:         # scanner checks: replace found id by other given ids
            for scanId in ids:
                if replaceId == scanId or set([replaceId, scanId]) in scannedCombos:
                    continue
                scannedCombos.append(set([replaceId, scanId]))

                scanPayload = baseVal.replace(replaceId, scanId)
                scanRequest = insertionPoint.buildRequest(scanPayload)
                scanRequestResponse = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), scanRequest)
                scanResponse = scanRequestResponse.getResponse().tostring()
                scanResponseBody = scanResponse[self.helpers.analyzeResponse(scanResponse).getBodyOffset():]

                if baseResponseBody == scanResponseBody:   # response hasn't changed - no issue
                    continue

                # Analyze responses
                replaceValue = self.tabledata.getValue(replaceId)
                scanValue = self.tabledata.getValue(scanId)
                # naming convention:
                # first word: base || scan (response)
                # second word: Replace || Scan (value)
                if replaceValue != "":
                    baseReplaceValueCount = len(baseResponseBody.split(replaceValue)) - 1
                    scanReplaceValueCount = len(scanResponseBody.split(replaceValue)) - 1
                else:
                    baseReplaceValueCount = 0
                    scanReplaceValueCount = 0

                if scanValue != "":
                    baseScanValueCount = len(baseResponseBody.split(scanValue)) - 1
                    scanScanValueCount = len(scanResponseBody.split(scanValue)) - 1
                else:
                    baseScanValueCount = 0
                    scanScanValueCount = 0

                if scanScanValueCount == 0:
                    # Scan identifier content value doesn't appears, but responses differ
                    issueCase = SessionAuthActiveScanIssue.caseScanValueNotFound
                elif baseReplaceValueCount > 0 and baseScanValueCount == 0 and scanReplaceValueCount == 0 and scanScanValueCount == baseReplaceValueCount:
                    # Scan identifier replaces all occurrences of the original identifier in the response
                    issueCase = SessionAuthActiveScanIssue.caseScanValueAppearsExactly
                elif baseReplaceValueCount > 0 and baseScanValueCount == 0 and scanReplaceValueCount == 0 and scanScanValueCount > 0:
                    # Scan identfiers value appears, replaced ids value disappears
                    issueCase = SessionAuthActiveScanIssue.caseScanValueAppearsFuzzy
                elif baseReplaceValueCount > scanReplaceValueCount and baseScanValueCount < scanScanValueCount:
                    # Occurence count of replaced id value decreases, scan id value increases
                    issueCase = SessionAuthActiveScanIssue.caseDecreaseIncrease
                elif baseScanValueCount < scanScanValueCount:
                    # Occurence count of scan id value increases
                    issueCase = SessionAuthActiveScanIssue.caseScanValueIncrease
                else:
                    # Remainingg cases
                    issueCase = SessionAuthActiveScanIssue.caseOther

                issues.append(SessionAuthActiveScanIssue(
                    url,
                    baseRequestResponse,
                    insertionPoint,
                    scanPayload,
                    scanRequestResponse,
                    replaceId,
                    replaceValue,
                    scanId,
                    scanValue,
                    issueCase,
                    self.callbacks
                    ))

        if len(issues) > 0:
            return issues
        else:
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return 1
        else:
            return 0


class SessionAuthPassiveScanIssue(IScanIssue):
    foundEqual = 1                        # parameter value equals identifier
    foundInside = 2                       # identifier was found inside parameter value

    def __init__(self, url, httpmsgs, param, ident, value, foundtype, callbacks):
        self.callbacks = callbacks
        self.service = httpmsgs.getHttpService()
        self.findingurl = url
        requestMatch = [array('i', [param.getValueStart(), param.getValueEnd()])]
        responseMatches = findAll(httpmsgs.getResponse().tostring(), value)
        self.httpmsgs = [callbacks.applyMarkers(httpmsgs, requestMatch, responseMatches)]
        if responseMatches:
            self.foundInResponse = True
        else:
            self.foundInResponse = False
        self.param = param
        self.ident = ident
        self.value = value
        self.foundtype = foundtype
        if self.foundInResponse:
            self.issueSeverity = "Low"
        else:
            self.issueSeverity = "Information"

    def __eq__(self, other):
        return self.param.getType() == other.param.getType() and self.param.getName() == other.param.getName() and self.param.getValue() == other.param.getValue()

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "SessionAuthPassiveScanIssue(" + self.getUrl() + "," + self.param.getType() + "," + self.param.getName + "," + self.param.getValue() + ")\n"

    def getUrl(self):
        return self.findingurl

    def getIssueName(self):
        return "Object Identifier found in Parameter Value"

    def getIssueType(self):
        return 1

    def getSeverity(self):
        return self.issueSeverity

    def getConfidence(self):
        if self.foundtype == self.foundEqual:
            return "Certain"
        elif self.foundtype == self.foundInside:
            return "Tentative"

    def getIssueDetail(self):
        msg = "The " + getParamTypeStr(self) + " <b>" + self.param.getName() + "</b> contains the user identifier <b>" + self.ident + "</b>."
        if self.foundInResponse:
            msg += "\nThe value <b>" + self.value + "</b> associated with the identifier was found in the request. The request is \
            probably suitable for active scan detection of privilege escalation vulnerabilities."
        return msg

    def getRemediationDetail(self):
        return "A web application should generally perform access control checks to prevent privilege escalation vulnerabilities. The checks must not trust any \
        data which is sent by the client because it is potentially manipulated. There must not be a static URL which allows to access a protected resource."

    def getIssueBackground(self):
        return "User identifiers submitted in requests are potential targets for parameter tampering attacks. An attacker could try to impersonate other users by \
        replacement of his own user identifier by the id from a different user. This issue was reported because the user identifier previously entered was found in \
        the request."

    def getRemediationBackground(self):
        return "The reaction to request manipulation and access attempts should be analyzed manually. This scan issue just gives you a pointer for potential interesting \
        requests. It is important to understand if the replacement of an object identifier in the request gives an unprivileged user access to data he shouldn't be able \
        to access."

    def getHttpMessages(self):
        return self.httpmsgs

    def getHttpService(self):
        return self.service


class SessionAuthActiveScanIssue(IScanIssue):
    caseOther = 0
    caseScanValueNotFound = 1
    caseScanValueAppearsExactly = 2
    caseScanValueAppearsFuzzy = 3
    caseDecreaseIncrease = 4
    caseScanValueIncrease = 5

    def __init__(self, url, baseRequestResponse, insertionPoint, scanPayload, scanRequestResponse, replaceId, replaceValue, scanId, scanValue, issueCase, callbacks):
        self.callbacks = callbacks
        self.service = baseRequestResponse.getHttpService()
        self.findingUrl = url
        self.insertionPoint = insertionPoint
        self.scanPayload = scanPayload
        baseResponseMatches = findAll(baseRequestResponse.getResponse().tostring(), replaceValue)
        self.baseRequestResponse = callbacks.applyMarkers(baseRequestResponse, None, baseResponseMatches)
        scanPayloadOffsets = insertionPoint.getPayloadOffsets(scanPayload)
        scanRequestMatch = None
        if scanPayloadOffsets != None:
            scanRequestMatch = [array('i', scanPayloadOffsets)]
        scanResponseMatches = findAll(scanRequestResponse.getResponse().tostring(), scanValue)
        self.scanRequestResponse = callbacks.applyMarkers(scanRequestResponse, scanRequestMatch, scanResponseMatches)
        self.replaceId = replaceId
        self.replaceValue = replaceValue
        self.scanId = scanId
        self.scanValue = scanValue
        self.issueCase = issueCase

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        if self.issueCase in [self.caseScanValueAppearsExactly, self.caseScanValueAppearsFuzzy, self.caseDecreaseIncrease, self.caseScanValueIncrease]:
            return "Potential Privilege Escalation Vulnerability"
        else:
            return "Replacement of Identifier causes different Responses"

    def getIssueType(self):
        if self.issueCase in [self.caseScanValueAppearsExactly, self.caseScanValueAppearsFuzzy, self.caseDecreaseIncrease, self.caseScanValueIncrease]:
            return 2
        else:
            return 3

    def getSeverity(self):
        if self.issueCase in [self.caseScanValueAppearsExactly, self.caseScanValueAppearsFuzzy, self.caseDecreaseIncrease, self.caseScanValueIncrease]:
            return "High"
        else:
            return "Information"

    def getConfidence(self):
        if self.issueCase == self.caseScanValueAppearsExactly:
            return "Certain"
        elif self.issueCase in [self.caseScanValueAppearsFuzzy, self.caseDecreaseIncrease]:
            return "Firm"
        else:
            return "Tentative"

    def getIssueDetail(self):
        msg = "<p>The replaced identifier was <b>" + self.replaceId + "</b> and replaced by <b>" + self.scanId + "</b> in the response. \
        The response was watched for decreasing occurrences of the content value <b>" + self.replaceValue + "</b> and increasing \
        occurrences of <b>" + self.scanValue + "</b>."
        if self.issueCase in [self.caseOther, self.caseScanValueNotFound]:
            msg += "<p>The replacement of the identifier has caused a different response, but the occurence of the content value never changed \
            or the content value of the replacement identifier even doesn't appeared. The differences should be verified manually.</p>"
        elif self.issueCase == self.caseScanValueAppearsExactly:
            msg += "<p>The content value associated with the replaced identifier disappeared completely. Instead the content value of \
            the replacement identifier appeared with the same count. This is a quite strong indication of a possible privilege escalation \
            vulnerability.</p>"
        elif self.issueCase == self.caseScanValueAppearsFuzzy:
            msg += "<p>The content value associated with the replaced identifier disappeared completely. Instead the content value of \
            the replacement identifier appeared with a different count. This is an indication of a possible privilege escalation \
            vulnerability.</p>"
        elif self.issueCase == self.caseDecreaseIncrease:
            msg += "<p>The appearance count of the content value associated with the replaced identifier decreased, while the appearance count of \
            the replacement identifier increased. This is an indication of a possible privilege escalation vulnerability.</p>"
        elif self.issueCase == self.caseDecreaseIncrease:
            msg += "<p>The appearance count of the content value associated with the replaced identifier decreased, while the appearance count of \
            the replacement identifier increased. This is an indication of a possible privilege escalation vulnerability.</p>"
        elif self.issueCase == self.caseScanValueIncrease:
            msg += "<p>The appearance appearance count of the replacement identifier increased. This is an weak indication of a possible privilege \
            escalation vulnerability.</p>"

        return msg

    def getRemediationDetail(self):
        return "A web application should generally perform access control checks to prevent privilege escalation vulnerabilities. The checks must not trust any \
        data which is sent by the client because it is potentially manipulated. There must not be a static URL which allows to access a protected resource."

    def getIssueBackground(self):
        msg = "The given request/response pair was automatically scanned for privilege escalation vulnerabilities by replacement \
        of identifiers in the request and comparing the resulting responses. This issue was reported "
        if self.issueCase in [self.caseScanValueAppearsExactly, self.caseScanValueAppearsFuzzy, self.caseDecreaseIncrease, self.caseScanValueIncrease]:
            msg += "because the occurrence count of the content values associated with the changed identifiers have changed (see issue details)."
        else:
            msg += "for informational purposes because the responses differ. There is no direct indication for a privilege escalation issue."
        return msg

    def getRemediationBackground(self):
        return "The reaction to request manipulation and access attempts should be analyzed manually. This scan issue just gives you a pointer for potential interesting \
        requests. It is important to understand if the replacement of an object identifier in the request gives an unprivileged user access to data he shouldn't be able \
        to access."

    def getHttpMessages(self):
        return [self.baseRequestResponse, self.scanRequestResponse]

    def getHttpService(self):
        return self.service


class IdentifiersPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, source):
        self.ids = source.getIds()
        self.reset()

    def reset(self):
        self.workIds = list(self.ids)
        self.workIds.reverse()

    def hasMorePayloads(self):
        return len(self.workIds) > 0

    def getNextPayload(self, baseValue):
        try:
            return self.workIds.pop()
        except IndexError:
            return


class MappingTableModel(AbstractTableModel):
    def __init__(self, callbacks):
        AbstractTableModel.__init__(self)
        self.columnnames = ["User/Object Identifier", "Content"]
        self.mappings = dict()
        self.idorder = list()
        self.lastadded = None
        self.callbacks = callbacks
        self.loadMapping()

    def getColumnCount(self):
        return len(self.columnnames)

    def getRowCount(self):
        return len(self.mappings)

    def getColumnName(self, col):
        return self.columnnames[col]

    def getValueAt(self, row, col):
        if col == 0:
            return self.idorder[row]
        else:
            return self.mappings[self.idorder[row]]

    def getColumnClass(self, idx):
        return str

    def isCellEditable(self, row, col):
       if col < 1:
           return False
       else:
           return True

    def add_mapping(self, ident, content):
        if ident not in self.mappings:
            self.idorder.append(ident)
        self.mappings[ident] = content
        self.lastadded = ident
        self.fireTableDataChanged()
        self.saveMapping()

    def set_lastadded_content(self, content):
        self.mappings[self.lastadded] = content
        self.fireTableDataChanged()

    def del_rows(self, rows):
        rows.sort()
        deleted = 0
        for row in rows:
            delkey = self.idorder[row - deleted]
            del self.mappings[delkey]
            if delkey == self.lastadded:
                self.lastadded = None
            if row - deleted > 0:
                self.idorder = self.idorder[:row - deleted] + self.idorder[row + 1 - deleted:]
            else:
                self.idorder = self.idorder[1:]
            self.fireTableRowsDeleted(row - deleted, row - deleted)
            deleted = deleted + 1
        self.saveMapping()

    def setValueAt(self, val, row, col):
        if col == 1:
            self.mappings[self.idorder[row]] = val
            self.fireTableCellUpdated(row, col)
        self.saveMapping()

    def getIds(self):
        return self.idorder

    def getValue(self, ident):
        return self.mappings[ident]

    def containsId(self, msg):
        for ident in self.idorder:
            if msg.find(ident) >= 0:
                return True
        return False

    def saveMapping(self):
        self.callbacks.saveExtensionSetting("mappings", pickle.dumps(self.mappings))
        self.callbacks.saveExtensionSetting("idorder", pickle.dumps(self.idorder))
        self.callbacks.saveExtensionSetting("lastadded", pickle.dumps(self.lastadded))

    def loadMapping(self):
        storedMappings = self.callbacks.loadExtensionSetting("mappings")
        if isinstance(storedMappings, str):
            try:
                self.mappings = pickle.loads(storedMappings) or dict()
            except:
                self.mappings = dict()

        storedIdorder = self.callbacks.loadExtensionSetting("idorder")
        if isinstance(storedIdorder, str):
            try:
                self.idorder = pickle.loads(storedIdorder) or list()
            except:
                self.idorder = list()

        storedLastAdded = self.callbacks.loadExtensionSetting("lastadded")
        if isinstance(storedLastAdded, str):
            try:
                self.lastadded = pickle.loads(storedLastAdded)
            except:
                self.lastadded = None

### Global Functions ###

# Find all occurrences of a string in a string
# Input: two strings
# Output: list of integer arrays (suitable as burp markers)
def findAll(searchIn, searchVal):
    if searchVal == None or len(searchVal) == 0:
        return None
    found = list()
    length = len(searchVal)
    continueSearch = True
    offset = 0
    while continueSearch:
        pos = searchIn.find(searchVal)
        if pos >= 0:
            found.append(array('i', [pos + offset, pos + length + offset]))
            searchIn = searchIn[pos + length:]
            offset = offset + pos + length
        else:
            continueSearch = False
    if len(found) > 0:
        return found
    else:
        return None

def getParamTypeStr(scanIssue):
    paramtype = scanIssue.param.getType()
    if paramtype == IParameter.PARAM_URL:
        return "URL parameter"
    elif paramtype == IParameter.PARAM_BODY:
        return "body parameter"
    elif paramtype == IParameter.PARAM_COOKIE:
        return "cookie"
    elif paramtype == IParameter.PARAM_XML:
        return "XML parameter"
    elif paramtype == IParameter.PARAM_XML_ATTR:
        return "XML attribute parameter"
    elif paramtype == IParameter.PARAM_MULTIPART_ATTR:
        return "multipart attribute parameter"
    elif paramtype == IParameter.PARAM_JSON:
        return "JSON parameter"
    else:
        return "parameter"
