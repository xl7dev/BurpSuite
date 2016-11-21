#!/usr/bin/python
# coding: utf-8

#
# Yara scanner plugin for Burpsuite
# Copyright 2016, Polito, Inc. All Rights Reserved.
#

__author__ = 'Ian'

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import ITab
from burp import IMessageEditorController
from java.io import PrintWriter
from java.lang import Runnable
from java.lang import System
from java.lang import Thread
from java.util import ArrayList
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt.event import ActionListener
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextField
from javax.swing.table import AbstractTableModel
from threading import Lock
import os
import subprocess

# Global variables
yara_path = None
yara_rules = None
stdout = None


class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, ActionListener,
                   AbstractTableModel, Runnable):

    #
    # Implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # Initialize the global stdout stream
        global stdout

        # Keep a reference to our callbacks object
        self._callbacks = callbacks

        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Burpsuite Yara Scanner")

        # Create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        # main split pane
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        splitpane.setLeftComponent(scrollPane)

        # Options panel
        optionsPanel = JPanel()
        optionsPanel.setLayout(GridBagLayout())
        constraints = GridBagConstraints()

        yara_exe_label = JLabel("Yara Executable Location:")
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 0
        constraints.gridy = 0
        optionsPanel.add(yara_exe_label, constraints)

        self._yara_exe_txtField = JTextField(25)
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 1
        constraints.gridy = 0
        optionsPanel.add(self._yara_exe_txtField, constraints)

        yara_rules_label = JLabel("Yara Rules File:")
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 0
        constraints.gridy = 1
        optionsPanel.add(yara_rules_label, constraints)

        self._yara_rules_txtField = JTextField(25)
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 1
        constraints.gridy = 1
        optionsPanel.add(self._yara_rules_txtField, constraints)

        self._yara_clear_button = JButton("Clear Yara Results Table")
        self._yara_clear_button.addActionListener(self)
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 1
        constraints.gridy = 2
        optionsPanel.add(self._yara_clear_button, constraints)

        # Tabs with request/response viewers
        viewerTabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        viewerTabs.addTab("Request", self._requestViewer.getComponent())
        viewerTabs.addTab("Response", self._responseViewer.getComponent())
        splitpane.setRightComponent(viewerTabs)

        # Tabs for the Yara output and the Options
        self._mainTabs = JTabbedPane()
        self._mainTabs.addTab("Yara Output", splitpane)
        self._mainTabs.addTab("Options", optionsPanel)

        # customize our UI components
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(viewerTabs)
        callbacks.customizeUiComponent(self._mainTabs)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # add ourselves as a context menu factory
        callbacks.registerContextMenuFactory(self)

        # Custom Menu Item
        self.menuItem = JMenuItem("Scan with Yara")
        self.menuItem.addActionListener(self)

        # obtain our output stream
        stdout = PrintWriter(callbacks.getStdout(), True)

        # Print a startup notification
        stdout.println("Burpsuite Yara scanner initialized.")

    #
    # Implement ITab
    #
    def getTabCaption(self):
        return "Yara"

    def getUiComponent(self):
        return self._mainTabs

    #
    # Implement IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE:
            self.requestResponses = invocation.getSelectedMessages()
            return [self.menuItem]
        else:
            self.requestResponses = None
        return None

    #
    # Implement Action
    #
    def actionPerformed(self, actionEvent):
        global yara_rules
        global yara_path

        if actionEvent.getSource() is self.menuItem:
            yara_path = self._yara_exe_txtField.getText()
            yara_rules = self._yara_rules_txtField.getText()
            t = Thread(self)
            t.start()
        elif actionEvent.getSource() is self._yara_clear_button:
            # Delete the LogEntry objects from the log
            row = self._log.size()
            self._lock.acquire()
            self._log.clear()

            # Update the Table
            self.fireTableRowsDeleted(0, row)

            # Clear data regarding any selected LogEntry objects from the request / response viewers
            self._requestViewer.setMessage([], True)
            self._responseViewer.setMessage([], False)
            self._currentlyDisplayedItem = None
            self._lock.release()
        else:
            stdout.println("Unknown Event Received.")

    #
    # Implement Runnable
    #
    def run(self):
        self.yaraScan()

    #
    # Extend AbstractTableModel
    #
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Rule Name"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._ruleName
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # Implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    #
    # Implement the Yara scanning logic
    #
    def yaraScan(self):
        # If stdout has not yet been initialized, punt.
        if stdout is None:
            return

        # If the location of the yara executable and rules files are NULL, punt.
        if yara_rules is None or yara_path is None or len(yara_rules) == 0 or len(yara_path) == 0:
            JOptionPane.showMessageDialog(None, "Error: Please specify the path to the yara executable and rules file in"
                                                "the options tab.")
            return

        # If iRequestResponses is None, punt.
        if self.requestResponses is None:
            JOptionPane.showMessageDialog(None, "Error: No Request/Responses were selected.")
            return
        else:
            stdout.println("Processing %d item(s)." % len(self.requestResponses))

        # Get the OS temp folder
        os_name = System.getProperty("os.name").lower()

        temp_folder = None
        if "linux" in os_name:
            temp_folder = "/tmp"
        elif "windows" in os_name:
            temp_folder = os.environ.get("TEMP")
            if temp_folder is None:
                temp_folder = os.environ.get("TMP")

        if temp_folder is None:
            stdout.println("Error: Could not determine TEMP folder location.")
            return

        # Keep track of the number of matches.
        matchCount = 0

        # Process the site map selected messages
        for idx, iRequestResponse in enumerate(self.requestResponses):
            # Process the request
            request = iRequestResponse.getRequest()
            if request is not None:
                if len(request) > 0:
                    try:
                        # Yara does not support scanning from stdin so we will need to create a temp file and scan it
                        req_filename = os.path.join(temp_folder, "req_" + str(idx) + ".tmp")
                        req_file = open(req_filename, "wb")
                        req_file.write(request)
                        req_file.close()
                        yara_req_output = subprocess.check_output([yara_path, yara_rules, req_filename])
                        if yara_req_output is not None and len(yara_req_output) > 0:
                            ruleName = (yara_req_output.split())[0]
                            self._lock.acquire()
                            row = self._log.size()
                            # TODO: Don't add duplicate items to the table
                            self._log.add(LogEntry(ruleName, iRequestResponse, self._helpers.analyzeRequest(iRequestResponse).getUrl()))
                            self.fireTableRowsInserted(row, row)
                            self._lock.release()
                            matchCount += 1
                    except Exception as e:
                        JOptionPane.showMessageDialog(None, "Error running Yara. Please check your configuration and rules.")
                        return
                    finally:
                        # Remove the temp file
                        if req_file is not None:
                            req_file.close()
                        os.remove(req_filename)

            # Process the response
            response = iRequestResponse.getResponse()
            if response is not None:
                if len(response) > 0:
                    try:
                        # Yara does not support scanning from stdin so we will need to create a temp file and scan it
                        resp_filename = os.path.join(temp_folder, "resp_" + str(idx) + ".tmp")
                        resp_file = open(resp_filename, "wb")
                        resp_file.write(response)
                        resp_file.close()
                        yara_resp_output = subprocess.check_output([yara_path, yara_rules, resp_filename])
                        if yara_resp_output is not None and len(yara_resp_output) > 0:
                            ruleName = (yara_resp_output.split())[0]
                            self._lock.acquire()
                            row = self._log.size()
                            # TODO: Don't add duplicate items to the table
                            self._log.add(LogEntry(ruleName, iRequestResponse, self._helpers.analyzeRequest(iRequestResponse).getUrl()))
                            self.fireTableRowsInserted(row, row)
                            self._lock.release()
                            matchCount += 1
                    except Exception as e:
                        JOptionPane.showMessageDialog(None, "Error running Yara. Please check your configuration and rules.")
                        return
                    finally:
                        # Remove the temp file
                        if resp_file is not None:
                            resp_file.close()
                        os.remove(resp_filename)

        # Print a completion notification
        JOptionPane.showMessageDialog(None, "Yara scanning complete. %d rule(s) matched." % matchCount)


class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)
        return

class LogEntry:
    def __init__(self, ruleName, requestResponse, url):
        self._ruleName = ruleName
        self._requestResponse = requestResponse
        self._url = url
        return
