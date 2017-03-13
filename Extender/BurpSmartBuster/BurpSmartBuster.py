# -*- coding: utf-8 -*-
'''
Created on 2015-02-22

BurpSmartBuster
@author: @pathetiq
@version: 0.2
@summary: This is a Burp Suite extension which discover content with a smart touch. A bit like “DirBuster” and “Burp Discover Content”,
          but smarter and being integrated into Burp Suite this plugin looks at words in pages, the domain name, the current directories and filename
          to help you find hidden files, directories and information you usually don't with a static dictionary file that brute force its way on the web server.

@bug: URL with variable, no file, no extension or weird variable separate by ; :, etc. breaks the directories/files listing
@todo: technology detection and scanning, community files, add 404 detection in output, threads speeds and adjustments
@todo: Add results to an issue. add tested files somewhere, add found file to sitemap.

'''
#sys imports
import sys

#Find the jython path where our prerequisites packages are installed
import site
for site in site.getsitepackages():
    sys.path.append(site)
#Examples of paths if needed
#sys.path.append("/home/USERNAME/.local/lib/python2.7/site-packages/")
#sys.path.append("/usr/local/lib/python2.7/site-packages")
##sys.path.append("/usr/lib/python2.7/dist-packages/")
#sys.path.append("/home/USERNAME/Documents/Apps/TextBlob")
#sys.path.append("/home/USERNAME/Documents/Apps/nltk")

#burp imports
from burp import IBurpExtender
from burp import IScanIssue
from burp import IScannerCheck
from burp import IScannerInsertionPoint
from burp import IHttpListener
from burp import IBurpExtenderCallbacks

#utils imports
from array import array
from java.io import PrintWriter
from java.net import URL
import os
import ConfigParser
import json
import logging
from tld import get_tld
import hashlib
import random

#spidering
from bs4 import BeautifulSoup
import Queue

#Parse HTML comments
from bs4 import Comment
import re
from urlparse import urlparse

#requester
import requests
import csv
from collections import deque
import threading

#text tokenization & natural language lib
locals()
#TODO: REVALIDATE the following : file /usr/local/lib/python2.7/dist-packages/nltk/internals.py line 902 has been change to remove os.getgroups() to compile in Burp...Jhython?
#http://textminingonline.com/getting-started-with-textblob
from textblob import TextBlob


'''----------------------------------------------------------------------------------------------------------------------------------------
BurpSmartBuster Logging object and config
----------------------------------------------------------------------------------------------------------------------------------------'''
class Logger():

    LOG_FILENAME = 'BSB.log'
    DEFAULT_LEVEL = logging.INFO

    def __init__(self,name=LOG_FILENAME,level=DEFAULT_LEVEL):

        #define configs
        self._default_level=level
        self._name = name
        print "Log file is: " + name

        logging.basicConfig(filename=self._name+".log",
                            level=self._default_level,
                            format="%(asctime)s - [%(levelname)s] [%(threadName)s] (%(funcName)s:%(lineno)d) %(message)s",
                            )

        self._logger = logging.getLogger(name)
        return

    def getLogger(self):
        return self._logger


'''----------------------------------------------------------------------------------------------------------------------------------------
BurpSmartBuster main class (BurpExtender)
----------------------------------------------------------------------------------------------------------------------------------------'''
class BurpExtender(IBurpExtender, IScanIssue, IScannerCheck, IScannerInsertionPoint,IHttpListener, IBurpExtenderCallbacks):

    # definitions
    EXTENSION_NAME = "BurpSmartBuster"
    AUTHOR = "@pathetiq"

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # define stdout writer
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        print(self.EXTENSION_NAME + ' by ' + self.AUTHOR)
        print('================================')
        print('This extension will create new requests for ALL "in scope" HTTP request made through Burp. Make sure to filter scope items')
        print('For help or any information see the github page or contact the author on twitter.')

        # set our extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)

        #set default config file name and values
        self._configFile = "bsb.ini"
        self._jsonFile = "data.json"
        self._configNumberOfTests_Path = 5
        self._configNumberOfTests_Files = 5
        self._configNumberOfTests_Extensions = 5
        self._configNumberOfTests_Directories = 5
        self._configSpider_RecursiveDirs = 5
        self._configSpider_NumberOfPages = 5
        self._configSmart_Local = False
        self._configSmart_Smart = True
        self._configSmart_File = False
        self._configSmart_Spider = False
        self._configInScope_only = True
        self._trailingSlash = True
        self._verbose = True
        self._ignoreFileType = ["gif","jpg","png","css","js","ico","woff"]

        #Get a logger object for logging into file
        loggerTemp = Logger(self.EXTENSION_NAME,logging.DEBUG)
        self._logger= loggerTemp.getLogger()

        #get the config file, will overwrite default config if the ini file is different
        self.getSmartConfiguration()

        #words gather on the page from the spidering
        self._words = {}
        self._mergedWords = {}

        #robots.txt list
        self._robots = {}
        self._robotsScanned = {}

        #sitemap.xml list
        self._sitemap = {}

        #url in comments
        self._urlsInComment = {}

        #domain names to query current url/path/files for hidden items
        self._smartDomain = {}

        #sitemap and robots scanned once
        self._siteRobotScanned = {}

        #Load our BSB json data
        jsonfile = open(self._jsonFile)
        self._parsed_json = json.load(jsonfile)
        jsonfile.close()

        #define the request object to use each time we need to call a URL
        self._requestor = Requestor(self._logger)

        #Variable to define if unique data has already been grabbed
        self._smartRequestData = {}
        self._smartRequestPath = {}
        self._smartRequestFiles = {}
        #number of time the spider have run
        self._spiderRan = {} #Array of domain. If domain exist. Spider did ran!

        return

    '''
    Extension Unloaded
    '''
    def extensionUnloaded(self):
        self._logger.info("Extension was unloaded")
        return

    '''
    VERBOSE FUNCTION
    Display each URL tested
    '''
    def verbose(self,text):
        #Is verbose on or off from config file?
        if self._verbose:
            print "[VERBOSE]: "+text
        return

    '''
    MAIN FUNCTION / WHERE EVERYTHING STARTS

    For every request which isn't created from the Extender(this might have to be change)
    The request is analyse and related to the config options new request are create to test if
    specific files/paths/directories exists.
    '''
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo): #IHttpRequestResponse message info


        #TODO: not from repeater and intruder --> set in ini file too! --> and toolFlag != self._callbacks.TOOL_EXTENDER

        #This is required to not LOOP Forever as our plugin generate requests!
        if toolFlag == self._callbacks.TOOL_PROXY and toolFlag != self._callbacks.TOOL_EXTENDER:

            #Get an Urldata object to use later
            data = self.getURLdata(messageInfo,messageIsRequest)

            #VERIFICATION: if URL is in scope we do scan
            if not self._callbacks.isInScope(data.getUrl()):
                #self._callbacks.includeInScope(url)
                self._logger.info("URL not in scope: " + data.getUrl().toString())
                return

            if messageIsRequest:
                self._logger.debug("Entering: processHttpMessage() REQUEST")
                self._logger.debug("Request from domain: "+data.getDomain())

                #REJECT specific extension on request
                if data.getFileExt() in self._ignoreFileType:
                    self._logger.info("FILETYPE IGNORED: " + data.getUrl().toString())
                    return

                ###############################################
                # Decide which mode to use based on ini config
                ###############################################

                #from browsed file only
                if self._configSmart_Smart:
                    self._logger.info("SMARTREQUEST FOR: "+data.getUrl().toString())
                    self._logger.debug("Executing: smartRequest()")
                    thread = threading.Thread(
                        target=self.smartRequest,
                        name="Thread-smartRequest",
                        args=[data],
                    )
                    thread.start()
                    thread.join()

                #wordlist adjust with the domain name
                elif self._configSmart_Local:
                    self._logger.debug("Executing: localRequest()")
                    self.localRequest(data)

                #your own wordlist, no smart here
                elif self._configSmart_File:
                    self._logger.debug("Executing: fileRequest()")
                    self.fileRequest(data)

                #spidered items only. Like smart but it browse for you.
                elif self._configSmart_Spider:
                    self._logger.debug("Executing: spiderRequest()")
                    self.spiderRequest(data)

            else: #if response
                self._logger.debug("Entering: processHttpMessage() RESPONSE")

                ###############################################
                # Decide which mode to use based on ini config
                ###############################################
                #VERIFICATION: if URL is in scope we do scan
                #if not self._callbacks.isInScope(data.getUrl()):
                #    #self._callbacks.includeInScope(url)
                #    self._logger.info("URL %s not in scope: " % data.getUrl())
                #    return

                #from browsed file only
                #TODO: sniff JS and CSS file for URLS
                #if self._configSmart_Smart:
                self._logger.debug("Executing: getUrlInComments()")
                thread = threading.Thread(
                    target=self.getUrlInComments,
                    name="Thread-getUrlInComments",
                    args=[data],
                )
                thread.start()
                thread.join()
        return

    '''----------------------------------------------------------------------------------------------------------
    BurpSmartBuster main class (BurpExtender)
    Only spidering to gather the more page and test those
    ----------------------------------------------------------------------------------------------------------'''
    def spiderRequest(self, data):
        return

    '''----------------------------------------------------------------------------------------------------------
    Use BSB files on all visited page
    ----------------------------------------------------------------------------------------------------------'''
    def localRequest(self, data):
        return

    '''----------------------------------------------------------------------------------------------------------
    Use user supply file on all visited page
    ----------------------------------------------------------------------------------------------------------'''
    def fileRequest(self, data):
        return

    #
    # TODO: ADD A FULL feature VS Smart. Remove others!
    #


    '''----------------------------------------------------------------------------------------------------------
    Use the logic, based on the BSB files and data from the website
    This is where all the magic happens.

    We want to :
    - Call some file extension for the file we browsed to
        -TODO:  Get a huge list
            - Extension
            - User file, windows, linux, osx
    - Call some path when browsing a new path (even when it is a file)
        - default path list
    - Call some files when browsing a new path
        - user files windows, osx, linux
        - backup list
        - autosave list
        - svn, git list
        - CMS
        - Web server, etc.
    - Get robots.txt and sitemap data
    - Brute force up to 2 or 3 letters of files names and path on all found path which is not cms/git/etc.

    - Future version: Parse HTML comments for path


    - If they exist, we add them to XXX?
    - If new path exists, let's go recursive (new class?)
    - If file exists: add to sitemap + verbose + log

    @param data: UrlData object containing all information about the URL
    ----------------------------------------------------------------------------------------------------------'''
    def smartRequest(self,data):

        #Current request variables
        domain = data.getDomain()
        url = data.getUrl()

        ##################### FETCH DATA ###############################
        # Gather smart data once before sending requests
        ################################################################
        self._logger.debug("Has the Data been gathered for? : "+ str(url))
        if domain not in self._smartRequestData:
            try:
                self._smartRequestData[domain] = True
                self._logger.debug("no")
                self._logger.info("Fetching data for: "+ domain)

                print "getting data for:" + str(url)
                self.getSmartData(data)

            except Exception as e:
                print "exception:"+ e
                self._smartRequestData[domain] = False
                return False
        else:
            self._logger.debug("yes")

        # Execution of request with the received data:
        # - spider
        # - sitemap
        # - robots
        # - current directories
        # - commentsInUrl
        # json data:
        # - extension files
        # - common basic cms files
        # - common server files
        # - common user files
        # - common test files
        # - common repositories files
        # -
        # -
        '''
        For the current directories (path)
        - Test a path/file for a category of path/files
            - If a tested path/files exist (200/401/403/500) scan other files + - add to sitemap and LOG + add issues?
            - If not skip it
            - go 3 deep max and retest all

        TODO future version:
        Pseudo algo:
        Si le present url est un fichier:
        - Si c'Est un fichier php... tester phps extension.
        - si c'Est un fichier asmx, tester les wsdl

        Si c'Est un path:
        - si ca inclus un path dans sharepoint, tester les sharepoints
        - si ca inclus un fichier de wordpress ou drupal, tester quelques fichiers cms
            - Si on trouve un répertoire de type X, effectuer une recherche sur les fichiers de type X dans le repertoire trouvé
        '''





        #Current request data
        baseUrl = data.getBaseUrl()
        path = data.getPath()
        filename = data.getFilename()
        extension = data.getFileExt()
        print "CURRENT FILE: " + baseUrl + "," + filename + "," + extension
        #data.json sections: extensions, fileprefix, filesuffix, files, directories

        #test local file
        #if current url is a file: test extentions + intelligent details
        #AND we test current file with prefix and suffix

        #testing directories
        #if current URL have some directories test them out
        #Test them with FILES and DIRECTORIES. Including the current directory (last in path)

        #with the smart data test robots path and files
        #test N url from sitemap
        #in current paths test files and path using domainname and domain without the tld
        #with filename generated + extensions and path/filenamegenerated
        '''
        print "EXTENSIONS"
        for extension in self._parsed_json["extensions"]:
            print extension["name"]
        print "SUFFIX PREFIX"
        for prefix in self._parsed_json["fileprefix"]:
            print prefix["name"]
        for suffix in self._parsed_json["filesuffix"]:
            print suffix["name"]

        print "FILES"
        for files in self._parsed_json["files"]:
            print files["name"]
        '''

        print "DIRECTORIES"

        #Directories data information
        directories = data.getDirectories()
        directory = "/"
        slash = "" #force slash or not var

        #get options foir trailing slash. By default it's ON
        if self._trailingSlash:
            slash = "/"

        ##################### EXECUTE DATA.json REQUESTS ###################
        # Build Request to be execute based on our data.json
        # and getSmartData results
        ################################################################

        #TODO: important put tested directories and files in a dictionnary or array
        #TODO: important put tested directories and files in a dictionnary or array
        #TODO: important put tested directories and files in a dictionnary or array
        #TODO: important put tested directories and files in a dictionnary or array

        ################
        #Scan the root directory!
        ################
        print "DIR: "+str(directories)

        if not directories:
            directories = ["/"]

        #TODO: Add recursive directory when a directory is found. Number of recursive directory is in ini file
        #TODO: replace print with requestor object that add the url to the queue in a thread, no need to wait for join
        # response will be dealed in requestor
        for dir in directories:
            print "TESTING: " + dir
            if dir == "/":
                directory = "/"
            else:
                directory = directory+dir+"/" #test all directories: / /a/ /a/b/ /a/b/c/ ...

            #call our directories inside all request directires
            for dir2 in self._parsed_json["directories"]:
                self.verbose("RequestDir for: "+baseUrl+directory+dir2["name"]+slash)
                self._requestor.addRequest(baseUrl+directory+dir2["name"]+slash,data)

            # call directories based on domain information: url/a/b/c/smartDomain , url/a/b/smartDomain/, etc.
            #print "SMARTDOMAIN"+self._smartDomain
            for dir2 in self._smartDomain[domain]:
                self.verbose("RequestSmartDomain for: " + baseUrl + directory + dir2)
                self._requestor.addRequest(baseUrl + directory + dir2,data)

                #in each directory call smartDomain.extensions
                for ext in self._parsed_json["extensions"]:
                    self.verbose("RequestSmartDomain.ext for: " + baseUrl + directory + dir2 + ext["name"])
                    self._requestor.addRequest(baseUrl + directory + dir2 + ext["name"],data)

            #call our files in all directories
            #print "parsed json"+self._parsed_json["files"]
            for files in self._parsed_json["files"]:
                self.verbose("RequestFile for: "+baseUrl+directory+files["name"])
                self._requestor.addRequest(baseUrl+directory+files["name"],data)


        ################
        #If URL is a file, let's try to add some extension to the file
        ################
        if extension:

            #replace current file extension for our extension
            tempFilenameUrl = baseUrl+directory+filename
            tempFilenameUrl1 = baseUrl+directory+filename+"."+extension
            for ext in self._parsed_json["extensions"]:
                self.verbose("RequestExt for: "+ tempFilenameUrl+ext["name"])
                self.verbose("RequestFileExt for: "+ tempFilenameUrl1+ext["name"])
                self._requestor.addRequest(tempFilenameUrl+ext["name"],data)
                self._requestor.addRequest(tempFilenameUrl1+ext["name"],data)

            #add a prefix to current file
            tempFilenameUrl = baseUrl+directory
            for prefix in self._parsed_json["fileprefix"]:
                tempFilenameUrl1 = tempFilenameUrl+prefix["name"]+filename+"."+extension
                self.verbose("RequestPrefix for: "+tempFilenameUrl1)
                self._requestor.addRequest(tempFilenameUrl1,data)

            #add suffix to current file
            tempFilenameUrl = baseUrl+directory
            for suffix in self._parsed_json["filesuffix"]:
                tempFilenameUrl1 = tempFilenameUrl+filename+suffix["name"]+"."+extension
                self.verbose("RequestSuffix for: "+tempFilenameUrl1)
                self._requestor.addRequest(tempFilenameUrl1,data)



        #make sure we have some data
        #print "DATA RECEIVED"
        #print self._words[domain]
        #print self._mergedWords ##need to call the emrge function if needed
        #print self._robots[domain]
        #print str(len(self._sitemap[domain]))
        #print str(self._urlsInComment[domain])



        ##################### EXECUTE SMART REQUESTS ###################
        # Build Request to be execute based on our data.json
        # and getSmartData results
        ################################################################

        #list of smart directories
        smartDirectories = {}

        #list of smart files (add our extension to it)
        smartfiles = {}

        ################
        #Request N pages from sitemap
        ################
        if domain not in self._siteRobotScanned: #Do it once
            self._siteRobotScanned[domain] = True #done for this domain

            tmpSiteMap = []
            for i in range(0,self._configSpider_NumberOfPages): #get N number of pages from ini config
                tmpSiteMap.append(self._sitemap[domain][i])

            #Requests files and directories from robots.txt
            tmpRobots = []
            for line in self._robots[domain]:

                #in case robots.txt use ending wildcard we remove it
                if line.endswith("*"):
                    line = line[:-1]
                #TODO: Test if directory or file is not 404 ??
                tmpRobots.append(baseUrl+line)

            ################
            # requests all value for N sitemap url
            ################
            for link in tmpSiteMap:

                if link.endswith("/"): #scan directories and files

                    for dir2 in self._parsed_json["directories"]:
                        self.verbose("RequestSiteMap dir/file for: " + link + dir2["name"] + slash)
                        self._requestor.addRequest(link + dir2["name"] + slash,data)

                    for files in self._parsed_json["files"]:
                        self.verbose("RequestSiteMap dir/file for: " + link + files["name"])
                        self._requestor.addRequest(link + files["name"],data)

                else:  #scan extensions and suffix/prefix
                    # call our files in all directories
                    for ext in self._parsed_json["extensions"]:
                        self.verbose("RequestSitemap file/ext/ext for: " + link + ext["name"])
                        self._requestor.addRequest(link + ext["name"],data)

                        #Get the file extension of the current sitemap url to replace the extension
                        tmpUrl = urlparse(link)
                        if len(tmpUrl.path.split(".")[-1:]) > 1:
                            newUrl = ".".join(tmpUrl.path.split(".")[:-1])+ext["name"]
                            self.verbose("RequestSiteMap file/ext for: " + newUrl)
                            self._requestor.addRequest(newUrl,data)

            ################
            #requests all values for robots path
            ################
            for link in tmpRobots:
                tmpUrl = baseUrl + link
                if link.endswith("/"):  # scan directories and files
                    for dir2 in self._parsed_json["directories"]:
                        self.verbose("RequestRobots dir/file for: " + tmpUrl + dir2["name"] + slash)
                        self._requestor.addRequest(tmpUrl + dir2["name"] + slash,data)

                    for files in self._parsed_json["files"]:
                        self.verbose("RequestRobots dir/file for: " + tmpUrl + files["name"])
                        self._requestor.addRequest(tmpUrl + files["name"],data)
                else:
                    for ext in self._parsed_json["extensions"]:
                        self.verbose("RequestRobots file/ext/ext for: " + tmpUrl + ext["name"])
                        self._requestor.addRequest(tmpUrl + ext["name"],data)

                        #Get the file extension of the current sitemap url to replace the extension
                        tmpUrl1 = urlparse(link)
                        if len(tmpUrl1.path.split(".")[-1:]) > 1:
                            newUrl = ".".join(tmpUrl1.path.split(".")[:-1])+ext["name"]
                            self.verbose("RequestRobots file/ext for: " + newUrl)
                            self._requestor.addRequest(newUrl,data)


        #TODO :  path and words/merge words

        ################
        #Request from words
        ################
        #print self._words


        #TODO: loop over: sitemap (done), robots (done), words/mergedwords(fixed for textblob required), bruteforce(later)  Maybe comments data?
        # - add the data to our stack to request and parse by the Requestor object
        # - Get current query path and files & Filter out static object from the request (images,etc.)
        #filter out: gif,jpg,png,css,ico


    '''----------------------------------------------------------------------------------------------------------
    Get the data for smartRequest(), it will fills our list of words which will be our smart logic data to create
    multiple new HTTP requests. This data should be gather once.
    ----------------------------------------------------------------------------------------------------------'''
    #TODO: split some of this works in different functions
    def getSmartData(self, data):

        ################################################################
        # Get the url and its data to create the new smart requests
        ################################################################
        urlString = str(data.getUrl()) #cast to cast to stop the TYPEerror on URL()
        domain = data.getDomain()
        netloc = data.getNetloc()
        directories = data.getDirectories()
        lastDirectory = data.getLastDirectory()
        params = data.getParams()
        fileExt = data.getFileExt()
        completeUrl = data.getCompleteURL()
        baseUrl = data.getBaseUrl()

        #Java URL to be used with Burp API
        url = URL(urlString)
        self._logger.debug("Current URLString: "+urlString)
        ######################### SPIDER EXECUTION #####################
        # Get some words from the web page: do it once!
        # Note: This step could be threaded using Queue.Queue but there is
        # little advantage as we need to wait to get all the value anyway
        ################################################################

        self._logger.debug("Has the Spider ran for? : "+ domain)
        if domain not in self._spiderRan: #doing it once
            self._spiderRan[domain] = True
            self._logger.debug("No")

            #self._mergedWords[domain] = {}
            #self._words[domain] = {}

            #Start URL, number of page to spider through, request class object to use

            spider = Spider(data, self._configSpider_NumberOfPages, self._requestor,self._logger)
            spider.runSpidering()

            #Get words from the spidering
            self._words[domain] = spider.getWords()
            #Get merged words
            #spider.mergeWords()
            #self._mergedWords[domain] = spider.getMergedWords()

            self._logger.debug("Length of Words: "+ str(len(self._words[domain])))
            #self._logger.debug("Length of MergedWords: "+ str(len(self._mergedWords[domain])))
            self._logger.info("SPIDER DONE")
        else:
            self._logger.debug("Yes")

        ################################################################
        # Get robots.txt (once)
        # Retrieve unique path and files from the robots.txt
        ################################################################
        if domain not in self._robots: #do it once
            print " robot "

            #get the file
            queueRobot = Queue.Queue(1)
            self._logger.info("robot")
            thread = threading.Thread(
                target=self._requestor.runRequest,
                name="Thread-Robots",
                args=[baseUrl+"/robots.txt", queueRobot],
            )
            thread.start()
            thread.join()
            response = queueRobot.get()

            #Parse the file for disallow lines
            robotList = []
            for item in response.content.split('\n'):
                if item:
                    i = item.split(':')
                    if i[0].lower() == "disallow" and i[1] not in robotList:
                        robotList.append(i[1])

            #add to domain list
            self._robots[domain] = robotList

            self._logger.debug("ROBOT LIST for : " + domain + ":")
            for item in self._robots[domain]:
                self._logger.debug(item)

            self._logger.info("ROBOTS DONE")

        else:
            print "no robot"
            self._logger.debug("Robots.txt already checked for: " + baseUrl)

        ################################################################
        # Get sitemap.xml (once)
        # test those url for all files/extensions if not in local deque yet
        ################################################################
        if domain not in self._sitemap:
            print " sitemap "
            queueSitemap = Queue.Queue(1)
            thread = threading.Thread(
                target=self._requestor.runRequest,
                name="Thread-Sitemap",
                args=[baseUrl+"/sitemap.xml", queueSitemap],
            )
            thread.start()
            thread.join()

            response = queueSitemap.get()
            soup = BeautifulSoup(response.content, "html.parser")

            #Parse the XML TODO: for N instance related to .ini config
            sitemapList = []
            for url in soup.findAll("loc"):
                sitemapList.append(url.text)

            self._sitemap[domain] = sitemapList

            self._logger.debug("Sitemap.xml nbr of items: "+str(len(self._sitemap[domain])))

            self._logger.info("SITEMAP DONE")
        else:
            print "no sitemap"

        ################################################################
        # Get domain name relative values
        # test those names for directory, files with extension
        ################################################################
        print "smartDomain"
        tmpDomValue = []

        if domain == "localhost":
            tmpDomValue.append(domain)
        else:
            tld = get_tld(urlString, as_object=True)
            tmpDomValue.append(tld.domain)
            tmpDomValue.append(tld.tld)

            if tld.subdomain:
                tmpDomValue.append("".join(tld.subdomain+"." + tld.tld))


        self._smartDomain[domain] = tmpDomValue

        ######################## BRUTE FORCE DATA ######################
        # 1, 2 or 3 letters brute force of current directory
        # Has the current directory been test already? No: do it
        #brute force function or object?
        ################################################################
        #TODO: Later version
        #charset = "abcdefghijklmnopqrstuvwxyz0123456789_-"
        #for a in itertools.product(charset,repeat=2):
        #    sub="".join(a)


        return True


    '''----------------------------------------------------------------------------------------------------------
    Get the information inside response for smartRequest()
    It will look for URL and email domain inside HTML comments

    @todo: Optimize the IFs in the comment for loop!
    ----------------------------------------------------------------------------------------------------------'''
    def getUrlInComments(self,data):

        ################### CURRENT DIRECTORIES/FILES ##################
        # Get current directory(ies)
        # validate if tested already
        # If not deal with: test directories and files at currentPath
        # New class object?
        ################################################################
        responseData = data.getResponseData()

        #TODO: Parse HTML files for comments for Path and file

        #if you have a response
        if responseData:
            soup = BeautifulSoup(responseData, "html.parser")
            comments=soup.find_all(string=lambda text:isinstance(text,Comment))
            regUrl = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
            regEmail = r"[\w\.-]+@[\w\.-]+"
            urlsInComments = []
            emailsInComments= []
            urlsInComment = []
            emailsInComment = []

            for comment in comments:
                #get urls
                urlsComments = re.findall(regUrl,comment)
                #parse url, does the domain the same as our current domain?
                if urlsComments:
                    for url in urlsComments[0]:
                        if url:
                            #Get URLs
                            tempData = urlparse(url)
                            domainInUrlTemp = '{uri.netloc}'.format(uri=tempData).split('.')
                            domainInUrl = ".".join(domainInUrlTemp)

                            #TODO: url will need to be verify if in scope when we call it : keep the URL path/file for scan
                            urlsInComment = re.findall(regUrl,comment)
                            urlsInComments.append(urlsInComment)

                    #get emails
                    emailsInComment = re.findall(regEmail, comment)
                    emailsInComments.append(emailsInComment)
            self._logger.debug("url in comments and email in comments:")

            #get list only
            if urlsInComments and urlsInComments[0]:
                if type(urlsInComment[0]) is tuple:
                    self._urlsInComment[data.getDomain] = urlsInComment[0]
            #TODO: use email in another version?
            if emailsInComments and emailsInComments[0]:
                if type(emailsInComments[0]) is tuple:
                    emailsInComments = emailsInComments[0]

            self._logger.debug(urlsInComments)
            self._logger.debug(emailsInComments)

            self._logger.info("COMMENTS DONE")


            #TODO: finish these function to gather the information from the data.json
        '''
    Function which is accessing smart list of Path to look into by the smart request function
    '''
    def getSmartListPath(self):
        return

    '''
    Function which is accessing smart list of file extension to look into by the smart request function
    '''
    def getSmartListExt(self):
        return

    '''
    Function which is accessing smart list of directories to look into by the smart request function
    '''
    def getSmartDirectories(self):
        return

    '''
    Function which is accessing smart list of files to look into by the smart request function
    '''
    def getSmartFiles(self):
        return

    '''
    Function to get configurations of our SmartBuster plugin
    '''
    def getSmartConfiguration(self):
        #Verify is file exist
        if not os.path.exists(self._configFile):
            #if not create the file
            config = self.setSmartConfiguration()
        else:
            #get the config file, newly created or not
            config = ConfigParser.ConfigParser()
            config.read(self._configFile)

            #get config values
            self._configNumberOfTests_Path = int(config.get('NumberOfTests','Paths'))
            self._configNumberOfTests_Files = int(config.get('NumberOfTests','Files'))
            self._configNumberOfTests_Extensions = int(config.get('NumberOfTests','Extensions'))
            self._configNumberOfTests_Directories = int(config.get('NumberOfTests','Directories'))
            self._configSpider_RecursiveDirs = int(config.get('Spider','RecursiveDirs'))
            self._configSpider_NumberOfPages = int(config.get('Spider','NumberOfPages'))
            self._configSmart_Local = config.get('Smart','Local')
            self._configSmart_Smart = config.get('Smart','Smart')
            self._configSmart_File = config.get('Smart','File')
            self._configSmart_Spider = config.get('Smart','Spider')
            self._verbose = config.get('Smart', 'Verbose')
            self._configInScope_only = config.get('InScope','ScopeOnly')
            self._trailingSlash = config.get('Technical','TrailingSlash')
            self._ignoreFileType = config.get('Ignore','FileType').split(",")

        #DEBUG: printing options
        #dictionary = {}
        #for section in config.sections():
        #    dictionary[section] = {}
        #    self._logger.debug("section: "+ str(section))
        #    for option in config.options(section):
        #        self._logger.debug("Options: " + str(config.get(section, option)))

        return

    '''
    Function to set configurations of our SmartBuster plugin if none are found in the current directory
    '''
    def setSmartConfiguration(self):
        config = ConfigParser.ConfigParser()

        #set config with default values
        config.add_section('NumberOfTests')
        config.set('NumberOfTests','Paths',self._configNumberOfTests_Path)
        config.set('NumberOfTests','Files',self._configNumberOfTests_Files)
        config.set('NumberOfTests','Extensions',self._configNumberOfTests_Extensions)
        config.set('NumberOfTests','Directories',self._configNumberOfTests_Directories)
        config.add_section('Spider')
        config.set('Spider','RecursiveDirs',self._configSpider_RecursiveDirs)
        config.set('Spider','NumberOfPages',self._configSpider_NumberOfPages)
        config.add_section('Smart')
        config.set('Smart','Local',self._configSmart_Local)
        config.set('Smart','Smart',self._configSmart_Smart)
        config.set('Smart','File',self._configSmart_File)
        config.set('Smart','Spider',self._configSmart_Spider)
        config.set('Smart', 'Verbose', self._verbose)
        config.add_section('InScope')
        config.set('InScope','ScopeOnly',self._configInScope_only)
        config.add_section('Technical')
        config.set('Technical','TrailingSlash',self._trailingSlash)
        config.add_section('Ignore')
        config.set('Ignore','FileType',",".join(self._ignoreFileType))

        #write config to file
        with open(self._configFile, 'w') as configfile:
            config.write(configfile)

        return config

    '''
    This functions split all informations of the URL for further use in the smartRequest function
    @param messageInfo: last request executed with all its information
    '''
    def getURLdata(self,messageInfo,messageIsRequest):


        analyzedRequest = self._helpers.analyzeRequest(messageInfo)
        url = analyzedRequest.getUrl()
        self._logger.debug(url)

        parsed = urlparse(url.toString())

        '''
        print 'scheme  :', parsed.scheme
        print 'netloc  :', parsed.netloc
        print 'path    :', parsed.path
        print 'params  :', parsed.params
        print 'query   :', parsed.query
        print 'fragment:', parsed.fragment
        print 'username:', parsed.username
        print 'password:', parsed.password
        print 'hostname:', parsed.hostname, '(netloc in lower case)'
        print 'port    :', parsed.port
        '''


        #Is there any parameters?
        params = analyzedRequest.getParameters()

        for p in params:
            self._logger.debug("Query var: "+p.getName())
            self._logger.debug("Query value: "+p.getValue())

        #getURL, needs to be a string before parsing it with urlparse
        completeURL = url.toString()
        self._logger.debug("Complete URL: "+completeURL)

        #URL sans port/dir/params
        baseURL = messageInfo.getHttpService().toString()
        self._logger.debug("Base URL: "+baseURL)


        #Get path including directories and file extension
        path = urlparse(completeURL).path.encode("utf-8")
        filename = path.split('/')[-1:].pop().split('.')[:1].pop()
        fileExt = path.split('.')[1:]
        fileExt = "".join(fileExt)
        directories = path.split('/')[1:-1]
        directory = "/".join(directories)
        if len(fileExt) > 0:
            self._logger.debug("Directories: "+str(directories)[1:-1])
            self._logger.debug("Directory: "+directory)
            self._logger.debug("File Extension: "+fileExt)
            self._logger.debug("URL Path: "+path)
            self._logger.debug("Filename: "+filename)
        else:
            self._logger.debug("No file Extension, directory is: "+path)

        #Get domain and netloc
        netloc = parsed.netloc.encode("utf-8")
        domain = netloc.split(':')[0]

        self._logger.debug("Domain/: "+domain)

        '''
        print "Complete URL: "+completeURL
        print "Domain: "+domain
        print "Netloc: "+ netloc
        print "Query value: "+p.getValue()
        print "Query var: "+p.getName()
        print "Directories: "+str(directories)[1:-1]
        print "Directories2: "+str(directories)
        print "Directory: "+directory
        print "File Extension: "+fileExt
        print "URL Path: "+path
        print "Filename: "+filename
        print "Base URL: "+baseURL
        '''

        responseData = ""
        if not messageIsRequest: #when it's a response, get the response data
            content = messageInfo.getResponse()
            response = self._helpers.analyzeResponse(content)
            responseData = self._helpers.bytesToString(content[response.getBodyOffset():])

            #data = UrlData("",headers,"","","","","","",responseData,self._logger)

        data = UrlData(url,domain,netloc,directories,params,filename,fileExt,baseURL,completeURL,path,responseData,self._logger)
        return data

    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    def doPassiveScan(self, baseRequestResponse):
        pass

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass


'''
Multithreaded class to execute queries out of the Queue.Queue

Also get the response and validate the 404 type
'''
class RequestorWorker(threading.Thread):

    def __init__(self, threadID, name, queue, responseQueue, logger, requestor):

        #Sahred Queue between Thread Workers
        self._id = threadID
        self._name = name
        self._queue = queue #request queue received from the Requestor
        self._threadLock = threading.Lock()
        self._alive = True
        threading.Thread.__init__(self)
        self.daemon = True
        self._responseQueue = responseQueue
        self._logger = logger
        self._requestor = requestor

        self._acceptedCode = (200,400,401,403,500)

        #TODO: Set a randomizer of user-agent and add the option in .ini file
        self._headers = {
            'User-Agent': 'Mozilla/5.0'
        }

        return

    def run(self):
        while(self._alive):
            #waiting for queue
            #print "Waiting for queue: "+self._name
            url = self._queue.get()
            # Get domain and netloc
            #parsed = urlparse(url)
            #netloc = parsed.netloc.encode("utf-8")
            #domain = netloc.split(':')[0]

            #request the data, etc. see todo below

            #print "TASK RECEIVED: " + url + " From: " + self._name

            #TODO: add http protocol/service in data

            self._logger.debug(self._name+" requesting(URL): " + url)
            self._logger.info(self._name+" requesting(URL): " + url)
            #print "[Requesting] " + url
            response = requests.get(url, headers=self._headers, allow_redirects=False)

            #TODO: if title contains 404, page not found
            #TODO: if body contain 404, page not found



            if response.status_code in self._acceptedCode:
                print "[URL EXISTS](" +str(response.status_code)+ ") "+ url


                #TODO: issue = SmartBusterIssue()
                #might need to parse the url into data for the issue?
                #issue=ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), httpmsgs, ISSUE_NAME, ISSUE_DETAIL, SEVERITY, CONFIDENCE, REMEDIATION_DETAIL, ISSUE_BACKGROUND, REMEDIATION_BACKGROUND)
                #self._callbacks.addScanIssue(issue)

                #for further use if needed
                #self._responseQueue.put(response)
        #return



        '''
        TODO:
        - add the request to the class queue
            - verify if the URL is already in sitemap
            - If not do it
        - Parse the queue
        - Send a request
        - Parse the response
        - Get the response code
            - 200, 401, 403 --> add to sitemap (403 might be false positive, can't know for sure)
            - 302 (redirect) --> parse the redirect URL (in scope ok, in sitemap stop, not in site map  add to queue : 200+window.location or JS isn't catch yet
            - 500: add to log file
            - 404, remove from queue
            - Log each result, verbose it too
        '''





'''----------------------------------------------------------------------------------------------------------------------------------------
Class to hold the Request data

- Using Requests API we use a Queue to append HTTP requests to be executed.
- If the requests return a 200/401/403/500 we add them to the sitemap and add them to our list of URL/Dir/file found
- Can save data found to csv
----------------------------------------------------------------------------------------------------------------------------------------'''
class Requestor():
    '''
    Initialize

    '''
    def __init__(self,logger):

        #Queue to hold URL to request
        #Each item will be a URL string str(URL)
        self._requestQueue = Queue.Queue(0)
        self._logger = logger
        self._error404 = {}

        #Queue to hold URL and their response code
        #Each item will be a list (url,code)
        self._responseQueue = deque()

         #TODO: Set a randomizer of user-agent and add the option in .ini file
        self._headers = {
            'User-Agent': 'Mozilla/5.0'
        }

        self._logger.debug("Requestor object created")

        #TODO: Set a number of thread in config ini file
        #TODO: Launch N Thread Workers

        threads = [] #list containing threads

        #1 thread needed for infofestival. Don't know how to split the pages between workers
        for i in range(0,40):
            t = RequestorWorker(i,"RequestorWorker-"+str(i),self._requestQueue,self._responseQueue, logger, self)
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        #for t in threads:
        #    t.join()

        return

    '''
    Checks for the 404 page of a specific domain

    @param filename: Save the Queued data to the filename
    '''
    def _define404(self,data):

        domain = data.getDomain()

        #only do once per domain
        if domain not in self._error404:
            self._error404[domain] = True
            errorQueue = Queue.Queue(0)
            code = 404

            #get a 404 page
            m = hashlib.md5()
            m.update(str(random.random()))

            url = data.getBaseUrl()+"/"+m.hexdigest()
            print url
            self.runRequest(url,errorQueue)
            response = errorQueue.get()

            #if website use standard 404 error, everything is good
            if response.status_code == 404:
                return

            #if website used a 30x code
            if 310 - response.status_code < 11 and 310 - response.status_code > 0:
                code = 300

            #if website use a 200
            if response.status_code == 200:

                soup = BeautifulSoup(response.content, "html.parser")

                if soup.findAll(text=re.compile("page not found")):
                    code = "page not found"
                elif soup.findAll(text=re.compile("404")):
                    code = "404"

                ################################
                #TODO: more use case to add
                ################################

            #define which code is refer to a 404
            self._error404[domain] = code

        return

    '''
    Return type of 404 for requested domain

    @param domain: domain to fetch error 404 type
    '''
    def getError404(self,domain):
        return self._error404[domain]

    '''
    Save to CSV

    @param filename: Save the Queued data to the filename
    '''
    def saveToCSV(self,filename):
        writer = csv.writer(open(filename+'.csv', 'a', buffering=0))

        for item in self._responseQueue:
            writer.writerow([item])

        return

    '''
    Add a request to the queue to be execute by a thread worker (RequestorWorker)

    @param url: the URL to get a response from
    '''
    def addRequest(self,url,data):

        #get the 404 details for the current domain
        #print "ADDING: "+ url

        #type404 = self._define404(data)
        self._requestQueue.put(url) ##see if we can put the type404 inside the queue along with the url
        return


    '''
    Run a NON DELAYED (no thread workers) request and save the url:response code to the response deque class variable

    @param url: the URL to request and get a response
    @param responseQueue: thread safe queue to send the response back to the spider or other objects
    '''
    def runRequest(self,url,responseQueue):

        #TODO: After thread is done, in thread read the _requestQeue object

        self._logger.debug("runRequest(URL): "+url)
        self._logger.info("EXECUTING REQUEST FOR: "+url)
        response = requests.get(url,  headers=self._headers, allow_redirects=False)
        responseQueue.put(response)

        #TODO: Get code
        #TODO: add page to SiteMap if not there already?


        self._logger.debug("runRequest done  for: "+url)

        return

    #TODO randomizedUserAgent
    def randomizedUserAgent(self):
        return




'''----------------------------------------------------------------------------------------------------------------------------------------
Class to hold the Spidering data

- Based on: http://www.netinstructions.com/how-to-make-a-web-crawler-in-under-50-lines-of-python-code/
  Uses BeautifulSoup, require to download/install it.
----------------------------------------------------------------------------------------------------------------------------------------'''
class Spider():

    '''
    Initialize

    @param startUrl: the URL to start the spidering

    '''
    def __init__(self, data, maxPages, requestObj, logger):
        self._data = data
        self._words = []
        self._mergedWords = []
        self._maxPages = int(maxPages)
        self._requestor = requestObj
        self._queue = Queue.Queue(self._maxPages)
        self._domain = data.getDomain()
        self._logger = logger
        self._logger.debug("Spider object created")

    '''
    Run the spidering

    @return: list of all words found
    @todo: use TextBlob for other language, right now mostly only english based words will be categorized correctly.
    '''
    def runSpidering(self):

        urlString = str(self._data.getUrl())
        url = URL(urlString)

        print "Spider, URL: " + urlString
        #Get the words from the URL, starting with the startUrl
        link_list = [urlString]

        #Counter
        pagesVisited = 0

        self._logger.debug("Max pages to visit: " + str(self._maxPages))

        while int(pagesVisited) < int(self._maxPages):
            self._logger.debug("Nbr Page Visited: " + str(pagesVisited) + " / " + str(self._maxPages))
            self._logger.debug("Visiting: " + link_list[pagesVisited])
            visitingUrl = link_list[pagesVisited]
            pagesVisited = pagesVisited+1
            print "Visiting URL: "+visitingUrl
            try:
                #??? Fix the url retrieve.
                #If it starts with / we add the domain to it
                if self._domain not in visitingUrl:
                    if visitingUrl.startswith("/"):
                        visitingUrl = visitingUrl[1:]
                        #TODO: startswith /#

                    link_list[pagesVisited] = self._data.getCompleteURL() + visitingUrl
                    visitingUrl = link_list[pagesVisited]

                #send an asynchronus HTTP request and wait for the response
                thread = threading.Thread(
                                target=self._requestor.runRequest,
                                name="Thread-Spider",
                                args=[visitingUrl, self._queue],
                                )
                thread.start()
                thread.join()
                response = self._queue.get()
                self._logger.debug("Response received from: "+visitingUrl)

                #Get the soup
                soup = BeautifulSoup(response.content, "html.parser")

                #Get the visible text
                [s.extract() for s in soup(['style', 'script', '[document]', 'head', 'title'])]
                visible_texts = soup.getText()#.encode('utf-8').strip()
                #Get the text blob
                blob = TextBlob(visible_texts)

                #Get the words : TODO: add the 1000 value in the bsb.ini?
                if len(blob.words) <= 1000: #merging 2 words and up to 1000  (cpu intensivity)
                    for words,tag in blob.tags:
                        #Get only noun and numbers
                        if tag.startswith("NN") or tag == "CD":
                            self._words.append(words)

                self._logger.debug("Size of WORDS: " + str(len(self._words)))

                #Get the links for next pages or stop
                aSoup = soup.findAll("a")
                if len(aSoup) > 0:
                    for i in aSoup:
                        #Do not use previous page, index or anchors
                        if not i['href'].startswith("#") and not i['href'] == "/" and not i['href'] in i and not i['href'].startswith("/#") and not i['href'].startswith("//"):
                            link_list.append(i['href'])
                else:
                    self._logger.debug("No words on: "+visitingUrl)
                    break

            except KeyError:
                self._logger.error("SpiderError: KeyError")
                pass
            except requests.exceptions.RequestException as e:
                self._logger.error("SpiderError: "+e.reason)
                pass

        return self._words

    '''
    Merge the obtained words from the spidering

    @return: List of all words mixed with each others
    '''
    def mergeWords(self):
        if len(self._words) > 1:

            #original list of words that we want to mix
            listOriginal = self._words

            #merging all words together
            for words in listOriginal:
                for wordsToMerge in listOriginal:
                    self._mergedWords.append(words+wordsToMerge)

            return True
        else:
            return False


    '''
    @return: List of all words mixed with each others
    Note: The return words needs to be convert to utf-8
    '''
    def getMergedWords(self):
         return self._mergedWords

    '''
    @return: List of all words
    Note: The return words needs to be convert to utf-8
    '''
    def getWords(self):
         return self._words




'''----------------------------------------------------------------------------------------------------------------------------------------
Class to hold the URL data in separated parts
----------------------------------------------------------------------------------------------------------------------------------------'''
class UrlData():

    def __init__(self,url,domain,netloc,directories,params,filename, fileExt,baseURL,completeURL,path,responseData,logger):
        self._url = url
        self._domain = domain
        self._netloc = netloc
        self._directories = directories
        self._params = params
        self._fileExt = fileExt
        self._baseURL = baseURL
        self._completeURL = completeURL
        self._responseData = responseData
        self._logger = logger
        self._path = path
        self._filename = filename

        self._logger.debug("UrlData object created")
        return

    def getPath(self):
        return self._path

    def getFilename(self):
        return self._filename

    def getResponseHeaders(self):
        if not self._url:
            return self._domain

    def getResponseData(self):
        return self._responseData

    def getBaseUrl(self):
        return self._baseURL

    def getCompleteURL(self):
        return self._completeURL

    def getUrl(self):
        return self._url

    def getDomain(self):
        return self._domain

    def getNetloc(self):
        return self._netloc

    def getDirectories(self):
        return self._directories

    def getLastDirectory(self):
        if len(self._directories) > 0:
            return self._directories[len(self._directories)-1]
        else:
            return ""

    def getParams(self):
        return self._params

    def getFileExt(self):
        return self._fileExt
'--------------------------------------------------------------------'



'''--------------------------------------------------------------------
Class to hold the Issues found
@TODO: see for Sitemap instead of issue or WITh issues
--------------------------------------------------------------------'''
class SmartBusterIssue(IScanIssue):
  '''This is our custom IScanIssue class implementation.'''
  def __init__(self, httpService, url, httpMessages, issueName, issueDetail, severity, confidence, remediationDetail, issueBackground, remediationBackground):
      self._issueName = issueName
      self._httpService = httpService
      self._url = url
      self._httpMessages = httpMessages
      self._issueDetail = issueDetail
      self._severity = severity
      self._confidence = confidence
      self._remediationDetail = remediationDetail
      self._issueBackground = issueBackground
      self._remediationBackground = remediationBackground


  def getConfidence(self):
      return self._confidence

  def getHttpMessages(self):
      return self._httpMessages
      #return None

  def getHttpService(self):
      return self._httpService

  def getIssueBackground(self):
      return self._issueBackground

  def getIssueDetail(self):
      return self._issueDetail

  def getIssueName(self):
      return self._issueName

  def getIssueType(self):
      return 0

  def getRemediationBackground(self):
      return self._remediationBackground

  def getRemediationDetail(self):
      return self._remediationDetail

  def getSeverity(self):
      return self._severity

  def getUrl(self):
      return self._url

  def getHost(self):
      return 'localhost'

  def getPort(self):
      return int(80)
