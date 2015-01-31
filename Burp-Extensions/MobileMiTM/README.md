MobileMiTM
==========

Burp Extension for BurpSuite pro that includes a custom DNS, non-HTTP proxy, and autolearn

Features:

1. DNS -  Thes feature makes it easier to use invisible proxies with mobile devices. Set a DNS responding IP Address
   and start the DNS listener. (Must run burp as root). Now set the mobile device's DNS to the same IP address that
   is running BURPSuite. Create invisible listeners for the identified Ports or enable AutoLearn.

2. AutoLearn - AutoLearn starts a service that looks for connections to the host machine. If the Port is not already 
   open then it will automatically create an invisible proxy listener in BURP Suite. This is useful for mobile apps 
   that don't use common port. Say for instance the app sends HTTPS over port 4443 instead of the normal 443. AutoLearn
   will pick up on this and save you trouble running TCPDump trying to figure out why its not communicating with the 
   server.

3. Non-HTTP Proxy - This extension also incluses a proxy that will allow you to intercept, tamper, and view previous 
   requests not using the HTTP protocol. It currently supports just asyncronous raw sockets and SSL sockets. (SSH 
   comming soon)


For more information visit the Wiki Page: https://github.com/summitt/MobileMiTM/wiki

Requirements:
Must have libpcap installed on *nix machines and winpcap on Windows machines.


Run on Linux and OSX

sudo java -classpath .:MiTMExtender.jar:suite.jar burp.StartBurp

Run on Windows

java -classpath .;MiTMExtender.jar;suite.jar burp.StartBurp


