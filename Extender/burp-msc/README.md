#Burp-msc
A little burp extension that allows you to export selected
requests/responses as an MSC (Message Sequence Chart)

##Requirements (Needy, I know)
  * Burpsuite v1.6+ (free or pro)
  * jython (tested on 2.5.3)
  * mscgen
  * sphinxcontrib-mscgen (in progess)

##How to install
Asssuming you have linked the jython.jar file to your BurpSuite session, you
only need to pull the repository and import the extension.

##How to use
In BurpSuite, go to the Proxy->HTTP history tab. Select the messages you would
like to export then right-click and select "Export to MSC".  A dialogue box
will appear asking for a path to save the mscgen outoput. From there you can
simply run mscgen on the output to generate your PNG. 
