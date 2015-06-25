import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

public class BurpExtender implements IBurpExtender {
	public static IBurpExtenderCallbacks mCallbacks;

	public BurpExtender() {
	}

	public byte[] processProxyMessage(int messageReference, boolean messageIsRequest, String remoteHost, int remotePort, boolean serviceIsHttps,
			String httpMethod, String url, String resourceType, String statusCode, String responseContentType, byte[] message, int[] action) {
		try {
			if (messageIsRequest) {
				if (!"POST".equals(httpMethod))
					return message;
				byte[] deserReq = Utilities.deserializeProxyItem(message);
				if (deserReq == null) {
					action[0] = ACTION_DONT_INTERCEPT;
					return message;
				}
				return deserReq;
			} else {
				String resp = new String(message);
				if (resp.contains(Utilities.X_BURP_INITDESERIALIZED)) {
					action[0] = ACTION_FOLLOW_RULES_AND_REHOOK;
					return resp.replaceAll(Utilities.X_BURP_INITDESERIALIZED, Utilities.X_BURP_DESERIALIZED).getBytes();
				}
				if (resp.contains(Utilities.X_BURP_DESERIALIZED)) {
					byte[] serResp = Utilities.serializeProxyItem(message);
					return serResp;
				}
				return message;
			}
		} catch (Exception e) {
			Utilities.print(e.getMessage());
			return message;
		}
	}

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;
	}

	public void setCommandLineArgs(String[] args) {
	}

	public void processHttpMessage(String toolName, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

		try {
			if (messageIsRequest) {
				byte[] request = messageInfo.getRequest();
				String requestStr = new String(request);
				if (requestStr.contains(Utilities.X_BURP_DESERIALIZED) || requestStr.contains(Utilities.X_BURP_INITDESERIALIZED)) {
					byte[] xml = Utilities.serializeProxyItem(request);
					messageInfo.setRequest(xml == null ? request : xml);
				}
			} else {
					byte[] xml = Utilities.initDeserializeProxyItem(messageInfo.getResponse());
					messageInfo.setResponse(xml == null ? messageInfo.getResponse() : xml);
				}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void newScanIssue(IScanIssue issue) {
	}

	public void applicationClosing() {

	}

}
