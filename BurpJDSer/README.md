BurpJDSer
=========

BurpJDSer is a Burp plugin that will deserialze/serialize Java request and response to and from XML with the use of Xtream library (http://xstream.codehaus.org/)

========= Usage =========
#1 Find and download client *.jar files
- Burp: view HTML response for embedded jar files
- Alternatively, look through browser's cache

#2(Optional) Search for sensitive information
- Use JD-GUI to open jar file. File --> Save all sources to a location
- What to search: hardcoded password, SQL string, SSN, Credit card, etc.

#3 Start Burp plugin
java -classpath burp.jar;burpjdser.jar;xstream-1.4.2.jar;[client_jar] burp.StartBurp 
*** Note: in case there're multiple jars, copy them all into a folder and use this to start Burp:
java -classpath burp.jar;burpjdser.jar;xstream-1.4.2.jar;"[Absolute path to jars folder]"/* burp.StartBurp 

#4 Inspect serialized Java traffic
- Serialized Java request/response will be automatically converted to XML. Decoded XML should be in "Edited Request" and "Original Response" tabs.
- Fuzz the request using Repeater/Intruder. Request will be automatically serialized back to binary format and response will be deserialized in XML format

#5: Bypass client-side authorization:
Sometimes the client rely on server for authorization check. In case you may want to modify the serialized response to bypass it:
- Inspect proxy response for possible authorization check
- Modify potentially abusive parameters to bypass client-side restrictions