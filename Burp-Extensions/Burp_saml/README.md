Burp Extension - SAML Message editor
====================================

Author: Chris Smith, Insomnia Security

Email: chris.smith@insomniasec.com

This extension provides a simple method for viewing and altering any SAML
requests or responses that have been captured by Burp.

Limitations:
* This has been tested against an OpenSAML SP and IDP which may differ from
  other SAML implementations.

* No support for artifacts

* Attempts to detect compressed requests/responses and only compress if
  detected at first.
