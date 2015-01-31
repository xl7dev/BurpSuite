POST2JSON
=========

* Author: geoff.jones@cyberis.co.uk
* Copyright: Cyberis Limited 2013
* License: GPLv3 (See LICENSE)

Burp Suite Extension to convert a POST request to a JSON message, moving any present .NET request verification token ('__RequestVerificationToken') to the HTTP request header.

Installation
============
In recent versions of Burp, all you need to do is open the 'Extender' tab within Burp, click 'Add' and select POST2JSONBurpExtender.jar.

Download the latest version here - https://github.com/cyberisltd/POST2JSON/blob/master/dist/POST2JSONBurpExtender.jar?raw=true

Usage
=====
If you have a POST request within an editor window, right clicking will now present a new menu item 'POST2JSON'.

Selecting the option will change the request to a correctly formatted JSON message, moving any present .NET '__RequestVerificationToken' to the HTTP request header.

Burp's history will be updated to reflect the editing request. To 'revert' the request method change, Ctrl-z will get you back to the orginal request (prior to 'Forward'ing of course).

Issues
======
Kindly report all issues via https://github.com/cyberisltd/POST2JSON/issues
