## Yara-Scanner

### Introduction
Yara-Scanner is a Python-based extension that integrates a Yara scanner into Burp Suite. Yara-Scanner allows you perform on-demand Yara scans of websites within the Burp interface, based on custom Yara rules that you write or obtain. Example use cases include scanning spidered sites for obfuscated Javascript or any other specific string patterns of interest present in any part of a request or response. It has been tested with Yara 3.4 in Burp Suite Free and Pro versions 1.6.3x on Windows 7 and 10, and Kali 2.0.

### Prerequisite: Jython
If you have not already added a Jython standalone JAR file to Burp:

1. Download the latest version (2.7) of the Jython standalone JAR file from: http://www.jython.org/downloads.html
2. In Burp, go to the Extender tab, then Options
3. Under Python Environment, click Select file... next to the field for Location of Jython standalone JAR file
4. Select your downloaded jython-standalone-2.7.0.jar file and click Open

### Prerequisite: Yara
1. Install or download the latest version of the standalone Yara binary (3.4) for your OS. Instructions at:  https://github.com/plusvic/yara/releases/tag/v3.4.0. 

### How to Install
1. Download yaraburp.py
3. In Burp, go to the Extender tab, then Extensions
3. Click Add
4. Under Extension details, set Extension type to Python
5. Click Select file...  next to the Extension file (.py) field 
6. Select your downloaded copy of yaraburp.py and click Open, then Next
7. In the Load Burp Extension window, after a few seconds the Output box should display "Burpsuite Yara scanner initialized", indicating that it was successfully loaded. A Yara tab will appear in Burp and Yara Scanner is now ready to use. Click Close.
8. Ensure that the Loaded option box is now checked for Burpsuite Yara Scanner 

### How to Use
1. Click the Yara tab in Burp, then Options
2. Enter the full path of your Yara Executable Location
  * Windows example: C:\Users\User\Downloads\Yara\yara32.exe
  * Linux example: /usr/bin/yara
3. Enter your Yara Rules File path 
  * Windows example: C:\Users\User\Downloads\Yara\rules.yar
  * Linux example: /user/Downloads/rules.yar
  * Among other Yara rule examples, a sample rule file for obfuscated JS detection can be downloaded from this repository, though you are encouraged to write and test your own Yara rules.
4. Visit your target site(s) using Burp as an interception proxy and your browser of choice to populate Burp's Site map
5. In Burp's Target tab, in the Site map, select the site(s) you want to scan with Yara then right-click on them and select Scan with Yara
 *  IMPORTANT NOTE: if you select a domain in the site map without expanding it, and select "Scan with Yara", it won't scan everything under that site. For some reason the Burp API does not include everything underneath that domain. You have to expand and select all of the sub-items in the tree structure under that domain and THEN select "Scan with Yara" to get everything.
6. After the Yara scan has successfully completed, a "Yara scanning complete. x rule(s) matched." message will appear. Click OK.
7. Click on the Yara tab and select Yara Output to view the rule hits; the Rule Name and URL will be listed for each hit.

### Possible Roadmap
* Add active scanning with Yara
* Add persistent settings
* Allow for multiple rule files, instead of requiring all rules to be within a single file
* DONE Add compatibility with Linux
* DONE Add threading for Yara to improve performance
* DONE Add "Clear Yara Results Table" button in Options
