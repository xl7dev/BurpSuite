# PT-Manager
Penetration Test Vulnerabilities Manager is an extension for Burp Suite, written in Jython, was developed by Barak Tawily in order to ease application security people manage vulnerabilities
 
 
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/general.png)
# Installation 
1.         Download Burp Suite (obviously): http://portswigger.net/burp/download.html
2.         Download Jython standalone JAR (version >= 2.7): http://www.jython.org/downloads.html
3.         Open Burp -> Extender -> Options -> Python Environment -> Select File -> Choose the Jython standalone JAR
4.         Install PT Manager from the BApp Store or follow these steps:
5.         Download the PTManager.py file (and XlsxWriter-0.7.3 if you would like to generate an xlsx report).
6.         Open Burp -> Extender -> Extensions -> Add -> Choose PTManager.py file.
7.         See the PT Manager tab and manage your vulnerabilities and project easily :)
 
# User Guide - How to use?
After installation, the PT Manager tab will be added to Burp.
 
Project Settings Tab:
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/project_settings.png)
 
1.         Open the Project Settings tab (PT Manager -> Project Settings) and create a new project, make sure you are creating it under the encrypted partition.
2.         "Details" text area can be used in order to save any details about the project such as URLs, credentials, contact details, or any other comments.
3.         Generate report section can be used in order to generate project report in HTML, XLSX, DOCX, TXT.
4.         import and export buttons can be used in order to send other people reports and allows them import it in the extension.
5.         "Open project directory" - will open your project directory, as you would expect ? :)
 
 
Vulnerability Tab:
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/vulnerability.png)
 
1. Open the Vulnerability tab and create a new vulnerability.
2. "Color:" combobox can be used in order to change a specific vulnerability’s background color. it can be used to let you know if the vulnerability was verified (set it green) or if it is false positive (so set it to red or just remove the vulnerability)
3. "Add SS from clipboard" button will copy a captured image that and save it on your clipboard. It is also possible to add it manually by pasting the jpg file into the vulnerability folder.
4. It is possible to right-click the selected preview image in order to copy the file into the clipboard in case you would like to get a specific image
5. request and response tab will include the requset and response of the vulnerable requset. it is possible to attach specific requests and responses to a vulnerability by right-clicking the request/response from anywhere in Burp then clicking on "Send to PT Manager" 
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/send%20to.png)
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/select.png)
![alt tag](https://raw.githubusercontent.com/Quitten/PT-Manager/master/images/request.png)
 
