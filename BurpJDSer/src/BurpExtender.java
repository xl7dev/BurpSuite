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
				return deserReq;
			} else {
				String resp = new String(message);
				if (resp.contains(Utilities.X_BURP_INITDESERIALIZED)) {
					action[0] = ACTION_FOLLOW_RULES_AND_REHOOK;
					return resp.replaceAll(Utilities.X_BURP_INITDESERIALIZED, Utilities.X_BURP_DESERIALIZED).getBytes();
				}
				if (resp.contains(Utilities.X_BURP_DESERIALIZED)) {
					return Utilities.serializeProxyItem(message);
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
			String url = messageInfo.getUrl().getPath();
			String lowerCaseToolName = toolName.toLowerCase();
			if ("scanner".equals(lowerCaseToolName) && messageIsRequest)
				Utilities.print(messageInfo.getRequest());
			if ("repeater".equals(lowerCaseToolName) || "intruder".equals(lowerCaseToolName) || "scanner".equals(lowerCaseToolName)) {
				if (messageIsRequest) {
					byte[] xml = Utilities.serializeProxyItem(messageInfo.getRequest());
					messageInfo.setRequest(xml);
				} else {
					byte[] xml = Utilities.deserializeProxyItem(messageInfo.getResponse());
					messageInfo.setResponse(xml);
				}
			} else if ("proxy".equals(lowerCaseToolName)) {
				if (messageIsRequest) {
					byte[] byteReq = messageInfo.getRequest();
					try {
						byte[] modReq = Utilities.serializeProxyItem(byteReq);
						messageInfo.setRequest(modReq);
					} catch (Exception e) {
						Utilities.print(e.getMessage());
					}
				} else {
					byte[] byteResp = messageInfo.getResponse();
					try {
						byte[] modResp = Utilities.initDeserializeProxyItem(byteResp);
						messageInfo.setResponse(modResp);
					} catch (Exception e) {
						Utilities.print(e.getMessage());
					}
				}
			}

		} catch (Exception e) {
			try {
				Utilities.print(">>>>>Tool: " + toolName + " URL: " + messageInfo.getUrl().getPath() + " . Reason: " + e.getMessage());
			} catch (Exception e1) {
				e1.printStackTrace();
			}

		}
	}

	public void newScanIssue(IScanIssue issue) {
	}

	public void applicationClosing() {

	}

}
