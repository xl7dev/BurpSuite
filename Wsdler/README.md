Wsdler
======

WSDL Parser extension for Burp

How to Run

java -classpath Wsdler.jar;burp.jar burp.StartBurp

Blog detailng how to use the Wsdler Plugin:

https://www.netspi.com/blog/entryid/57/hacking-web-services-with-burp

How To Compile
==============

I used IntelliJ to compile this plugin. However, Eclipse should work too. 

1. Clone the repo and open the folder as a project in Intellij/Eclipse
2. Maven is used to retrieve dependencies. So import the pom.xml into Maven. For Intellij, this should happen automatically. You can see the dependencies by clicking the vertically aligned Maven Projects tab on the right side of the window.
3. You should now be able to compile the plugin. Make sure that when you are building, a jar file gets created. In Intellij, select File > Project Structure > Artifacts > Plus Sign > Jar > From modules with dependencies > OK and check the Build on make checkbox. That should be it. Again, the process should be similar in Eclipse.
