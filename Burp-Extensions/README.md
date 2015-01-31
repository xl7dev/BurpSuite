Burp Suite Extensions Collection
===============

A collection of extensions for the new Burp Suite API (v1.5+) using Submodules for easy collection and updating. If you want to add a new module to the collection just send a Pull request or create an Issue. If you want your collection removed create an Issue. 

Thanks to Mubix for inspiration (https://github.com/mubix/tools) :)

The following command should pull down the latest versions.

git pull --recurse-submodules && git submodule update --init --recursive

Included:

BurpJDSer-ng
===============
Deserializes java objects and encode them in XML using the Xtream library.

BurpAuthzPlugin
===============
Test for authorization flaws

Wsdler
===============
Parses WSDL and creates SOAP requests for web services.