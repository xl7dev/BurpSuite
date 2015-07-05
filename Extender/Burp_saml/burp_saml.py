# Copyright (c) 2013, Chris Smith, Insomnia Security
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the Insomnia Security nor the names of its contributors
#   may be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
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
"""

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab

import re
import urllib
import xml.dom.minidom
import zlib

saml_parameter_names = ['SAMLResponse', 'SAMLRequest']

# This is disabled by default because of a bug in Jython.
# minidom on cPython does not expand entities, whereas Jython's implementation
# does. This exposes the user to XXE-type issues when dealing with a server
# that is untrusted.
#
# If you know what you are doing, you can re-enable this.
config_pretty_print = False


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        """Implements Burp's Extension API

        Saves useful references to objects that burp exposes that can leverage
        its functionality from the extension code
        """
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        self.callbacks.setExtensionName("SAML input editor")
        self.callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        """Implements Burp's API for creating message editors"""
        return SAMLInputTab(self, controller, editable)


class SAMLMessage(object):
    """Class representing a SAML message

    Stores the message, information about the message and provides
    functionality for retrieving it in different formats.

    Easier to use Python functionality for encoding/decoding due to
    the Java/Python bridge sucking a bit, especially with string/bytearray
    conversion.
    """
    def __init__(self, encoded_msg=None):
        self.raw_message = None
        self.compression = False

        if encoded_msg:
            self.set_encoded_message(encoded_msg)

    def get_encoded_message(self):
        """Retrieves the message in encoded form"""
        if self.compression:
            message = zlib.compress(self.raw_message)[2:-4]
        else:
            message = self.raw_message

        base64_encoded = message.encode('base64')
        url_encoded = urllib.quote(base64_encoded)

        return url_encoded

    def set_encoded_message(self, encoded_msg):
        """Sets the message from an encoded message"""
        url_decoded = urllib.unquote(encoded_msg)
        base64_decoded = url_decoded.decode('base64')

        self.detect_compression(base64_decoded)
        if self.compression:
            self.raw_message = zlib.decompress(base64_decoded, -15)
        else:
            self.raw_message = base64_decoded

    def get_pretty_message(self):
        """Retrieve the message formatted for human eyes"""
        if config_pretty_print:
            xml_dom = xml.dom.minidom.parseString(self.raw_message, resolve_entities=False)
            return xml_dom.toprettyxml(indent='\t')
        else:
            return self.raw_message

    def set_pretty_message(self, pretty_msg):
        """Sets the message from pretty-formatted XML"""
        self.raw_message = re.sub(r"\t|\n", "", pretty_msg)

    def detect_compression(self, message):
        """Check if a message is using compression or not"""
        try:
            zlib.decompress(message, -15)
            self.compression = True
        except zlib.error:
            self.compression = False


class SAMLInputTab(IMessageEditorTab):
    """Implements Burp's API for implementing an editor tab for a HTTP message"""

    def __init__(self, extender, controller, editable):
        # self.extender is our only access back to burp
        self.extender = extender

        # A master "editable" boolean burp sends to instruct if can be edited
        # e.g. proxy history messages = not editable
        self.editable = editable

        # Create the text input box
        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)

        # These variables will specify the parameter we are working with
        # when a message is discovered in the request.
        self.parameter_name = None
        self.parameter_type = None

        # This is the SAML message we will be working with
        self.saml_message = None

        # HTTP message for us to paste our SAML content back into
        self.current_message = None

    def getTabCaption(self):
        return "SAML"

    def isEnabled(self, content, isRequest):
        """Analyses the HTTP message for any SAML content

        If found, a SAML message is created and information about the
        parameter is saved
        """
        for parameter_name in saml_parameter_names:
            parameter = self.extender.helpers.getRequestParameter(content, parameter_name)

            if parameter is not None:
                self.parameter_name = parameter_name
                self.parameter_type = parameter.getType()
                self.saml_message = SAMLMessage(parameter.getValue())

                return True

        return False

    def setMessage(self, content, isRequest):
        """Called by Burp to display content in editor pane

        'content' is the entire HTTP message so use Burp's helpers to find
        the parts that are interesting to us.
        """
        if content is None:
            self.txtInput.setText(None)
            self.txtInput.setEditable(False)
        else:
            self.txtInput.setText(
                self.extender.helpers.stringToBytes(
                    self.saml_message.get_pretty_message()))

        self.current_message = content

    def getMessage(self):
        """Called by Burp to get the HTTP message after editing"""
        if self.txtInput.isTextModified():
            # Update the message with the new content from the editor
            self.saml_message.set_pretty_message(
                self.extender.helpers.bytesToString(self.txtInput.getText()))

            # Create a new request parameter from the message
            new_parameter = self.extender.helpers.buildParameter(
                self.parameter_name, self.saml_message.get_encoded_message(),
                self.parameter_type)

            # Return the orig HTTP message with the updated parameter
            return self.extender.helpers.updateParameter(self.current_message,
                                                         new_parameter)
        else:
            # Nothing changed, return the current http message
            return self.current_message

    # These functions required to implement the rest of the burp API
    def getUiComponent(self):
        return self.txtInput.getComponent()

    def isModified(self):
        return self.txtInput.isTextModified()

    def getSelectedData(self):
        return self.txtInput.getSelectedText()
