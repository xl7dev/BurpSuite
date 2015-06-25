Burp MultiDEC Extension
January 2013
Austin Lane<alane@trustwave.com>
http://www.trustwave.com

INTRODUCTION
============

Burp MultiDEC Extension is a plugin for Burp Suite that adds a tabbed 
encoder/decoder. The tool aims to implement the same Decoder functionality in 
a new tabbed interface.

Features:
o Convert between ASCII text, HTML and URL encoding, Base64, as well as 
Decimal, Binary, Hex, and Octal numbers.
o Multi-tabbed interface allows multiple conversions to be maintained.

REQUIREMENTS
============

Burp Suite Pro 1.5.0.1+

BUILDING FROM SOURCE
====================

1. Drop Burp Suite Pro JAR in ./lib
2. ant clean; ant compile; ant jar;

USAGE
=====

In Burp Suite navigate to the Extender tab. 
Select "Add".
Leave Extension Type as "Java" and choose "Select file…".
Navigate to the included "BurpMultiDECExtension.jar" file or your JAR compiled 
from source, then click "Open".
Click "Next" to load the plugin. 

Within the Notes tab, there are two options:
o Encode: Encode text in the input window to one of the selected formats.
o Decode: Decode text in the input window from the selected format to plaintext
or decimal numbers.

COPYRIGHT
=========

Burp MultiDEC Extension - A plugin for Burp Suite that adds a tabbed 
encoder/decoder window.
Austin Lane
Copyright (C) 2013 Trustwave
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
