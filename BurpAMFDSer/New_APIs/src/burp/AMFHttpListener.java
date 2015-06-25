package burp;
import burp.*;

public class AMFHttpListener implements IHttpListener {

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			if (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER || toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) {
				byte[] currentMsg = messageInfo.getRequest();
				byte[] serializedMsg = AMFUtilities.serializeProxyItem(currentMsg);
				messageInfo.setRequest(serializedMsg);
			}
		}
	}
}