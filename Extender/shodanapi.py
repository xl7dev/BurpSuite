#!/usr/bin/env python

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from burp import IContextMenuFactory
from burp import IContextMenuInvocation

from javax.swing import JMenuItem

import socket
import json
import urllib2
import socket
import threading

class BurpExtender(IBurpExtender,IContextMenuFactory):

    def	registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Shodan Scan")
        self.callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self,invocation):
        menu_list = []
        menu_list.append(JMenuItem("Scan with Shodan",None,actionPerformed= lambda x, inv=invocation:self.startThreaded(self.start_scan,inv)))
        return menu_list

    def startThreaded(self,func,*args):
        th = threading.Thread(target=func,args=args)
        th.start()

    def start_scan(self,invocation):
        http_traffic = invocation.getSelectedMessages()
        if len(http_traffic) !=0:
                service = http_traffic[0].getHttpService()
                hostname = service.getHost()
                ip = socket.gethostbyname(hostname)
                req = urllib2.Request("https://api.shodan.io/shodan/host/"+ip+"?key=1lgyO39gi4FOQqI7Y2TYndvNUJNRGjYe")
                response = json.loads(urllib2.urlopen(req).read())
                print "This report is last updated on  %s" % str(response['last_update'])
                print "IP - %s" %str(response['ip_str'])
                print "ISP - %s" %str(response['isp'])
                print "City - %s" %str(response['city'])
                print "Possible Vulns - %s" %str(response['vulns'])
                print "Open Ports -  %s" % str(response['ports'])
