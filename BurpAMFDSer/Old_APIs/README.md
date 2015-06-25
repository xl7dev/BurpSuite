BurpAMFDSer
============
BurpAMFDSer is a Burp plugin that will deserialze/serialize AMF request and response to and from XML with the use of Xtream library (http://xstream.codehaus.org/)
BurpAMFDSer also utilizes  part of Kenneth Hill's Jmeter source code for custom AMF deserialization (https://github.com/steeltomato/jmeter-amf)

========= Usage =========
#1 Start Burp plugin
java -classpath burp.jar;burpamfdser.jar;xstream-1.4.2.jar burp.StartBurp 

#2 Inspect serialized AMF traffic
- Serialized AMF request/response will be automatically converted to XML. Decoded XML should be in "Edited Request" and "Original Response" tabs.
- Fuzz the request using Repeater/Intruder. Request will be automatically serialized back to binary format and response will be deserialized in XML format

#3 Bypass client-side authorization:
Sometimes the client rely on server for authorization check. In case you may want to modify the serialized response to bypass it:
- Inspect proxy response for possible authorization check
- Modify potentially abusive parameters to bypass client-side restrictions