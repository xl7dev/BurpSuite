Burp Suite Heartbleed Bug Extension
=======================

This extension adds a new tab to Burp's Suite main UI and tests a server against the Heartbleed Bug, in case the server is vulnerable, data in server's memory will be dumped and viewed.

The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet. SSL/TLS provides communication security and privacy over the Internet for applications such as web, email, instant messaging (IM) and some virtual private networks (VPNs). The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the vulnerable versions of the OpenSSL software. This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. This allows attackers to eavesdrop on communications, steal data directly from the services and users and to impersonate services and users. [taken from heartbleed.com]

Requirement:

    Jython 2.7 or above

Installation:

    Donwload Heartbleed.jar and add it in burp's Extender tab
    Configure your burp suite to use Jython under Extender/Options/Python environment


Tested on:
   
    Burp Suite Professional v1.6beta2
    Ubuntu 12.04 LTS
    Windows 7 Enterprise

More info is available at:

    http://forum.portswigger.net/thread/1197/burp-suite-heartbleed-extension
