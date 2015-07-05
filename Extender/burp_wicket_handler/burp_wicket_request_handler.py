# Used as part of Burps Session Handling
# Record a Macro which just gets the page you want to submit
# this should give correct wicket:interface in the body e.g:
#
# GET /site/blah HTTP/1.1
#
# Add a new Rule in Options/Sessions
# Set the scope (e.g. Repeater/Scanner/Intruder)
# Add the Macro to the rule and tick 'After running the macro, invoke a Burp extension action handler'
# Select the WicketRequestHandler
#
# For items such as the Scanner/Intruder we are probably limited to 1 thread.
#
# May be possible to do a recursive grep with Intruder which would be quicker? How do we get this
# in the correct place?
# 
# TODO: Instead of recording a Macro to gather the interface create a request
# ourselves based on the request wicket:interface parameter?
#

from burp import IBurpExtender
from burp import ISessionHandlingAction
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # set our extension name
        callbacks.setExtensionName("WicketRequestHandler")

        callbacks.registerSessionHandlingAction(self)
        
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._helper = callbacks.getHelpers()

        return

    #
    # implement ISessionHandlingAction
    #
    # This method is used by Burp to obtain the name of the session handling
    # action. This will be displayed as an option within the session handling
    # rule editor when the user selects to execute an extension-provided
    # action.
    #
    # @return The name of the action.
    def getActionName(self):
        return "UpdateWicketInterface"

    #
    # implement ISessionHandlingAction
    #
    #
    # This method is invoked when the session handling action should be
    # executed. This may happen as an action in its own right, or as a
    # sub-action following execution of a macro.
    #
    # @param IHttpRequestResponse currentRequest The base request that is currently being processed.
    # The action can query this object to obtain details about the base
    # request. It can issue additional requests of its own if necessary, and
    # can use the setter methods on this object to update the base request.
    # @param IHttpRequestResponse[] macroItems If the action is invoked following execution of a
    # macro, this parameter contains the result of executing the macro.
    # Otherwise, it is
    # <code>null</code>. Actions can use the details of the macro items to
    # perform custom analysis of the macro to derive values of non-standard
    # session handling tokens, etc.
    #
    def performAction(self, currentRequest, macroItems):      
        if macroItems is None:
            self._stdout.println("No macro defined!")
            return

        if currentRequest is None:
            self._stdout.println("No current request!")
            return

        request_info = self._helper.analyzeRequest(currentRequest.getRequest())
        request_params = request_info.getParameters()
        if request_params is None:
            self._stdout.println("No request params to update")
            return

        wicket_interface = None
        identifier = None
        for p in request_params:
            if p.getName() == "wicket:interface":
                wicket_interface = p
            elif "_hf_0" in p.getName():
                identifier = p

        updated_request = currentRequest.getRequest()
        # Remove the identifier if it exists
        if identifier is not None:
            updated_request = self._helper.removeParameter(updated_request, identifier)
            
        # Wicket Interface needs updating
        if wicket_interface is not None:
            for m in macroItems:
                m_response = m.getResponse()
                if m_response is None:
                    self._stderr.println("No Macro Response!")
                    continue
                else:
                    m_response_info = self._helper.analyzeResponse(m_response)
                    m_response_body = self._helper.bytesToString(m_response[m_response_info.getBodyOffset():])
                    re_interface = re.compile(r"(action=\"\?wicket:interface=)([\w:]+)(\")")
                    re_identifier = re.compile(r"(\w)+_hf_0")
                    result = re_interface.search(m_response_body)
                    iresult = re_identifier.search(m_response_body)
                    if result is None:
                        self._stderr.println("No interface found in macro response!")
                    else:
                        wi_value = result.group(2)
                        wicket_interface = self._helper.buildParameter(
                            wicket_interface.getName(),
                            wi_value,
                            wicket_interface.getType())

                        self._stdout.println("Found wicket interface: %s" % wi_value)
                        updated_request = self._helper.updateParameter(updated_request, wicket_interface)
                    if  iresult is None:
                        self._stderr.println("No identifier found in macro response!")
                    else:
                        i_name = iresult.group(0)
                        identifier = self._helper.buildParameter(
                            i_name,
                            "",
                            p.getType())
                        
                        updated_request = self._helper.addParameter(updated_request, identifier)
                        self._stdout.println("Found identifier: %s" % i_name)
                           
        #self._stdout.println(self._helper.bytesToString(updated_request))
        currentRequest.setRequest(updated_request)
