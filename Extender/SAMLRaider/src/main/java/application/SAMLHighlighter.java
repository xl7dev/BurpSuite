package application;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class SAMLHighlighter implements IHttpListener{
	
	private SamlTabController samlTabController;
	
	public void setSamlTabController(SamlTabController samlTabController) {
		this.samlTabController = samlTabController;
	}
	
	@Override
	public void processHttpMessage(int toolFlag , boolean isRequest, IHttpRequestResponse requestResponse) {
		if (toolFlag  == IBurpExtenderCallbacks.TOOL_PROXY) {
			if (isRequest) {
				final byte[] requestBytes = requestResponse.getRequest();
				if(samlTabController.isEnabled(requestBytes, isRequest)){
					highlightRequestResponse(requestResponse);
				}
			}
		}
	}
	
	private void highlightRequestResponse(IHttpRequestResponse requestResponse) {
		requestResponse.setHighlight("blue");
	}

}
