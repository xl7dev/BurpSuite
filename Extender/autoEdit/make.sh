#!/bin/bash
rm burp/BurpExtender*.class
rm burp/ParamM.class
javac -Xlint:unchecked burp/BurpExtender.java
jar -cfv autoEdit.jar burp/BurpExtender* burp/ParamM*
