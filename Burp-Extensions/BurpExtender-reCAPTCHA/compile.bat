del BurpExtender.class
del BurpExtender.jar
javac.exe BurpExtender.java
jar.exe -cf BurpExtender.jar BurpExtender.class
java -Xmx512m -classpath "*" burp.StartBurp "admin" "password"