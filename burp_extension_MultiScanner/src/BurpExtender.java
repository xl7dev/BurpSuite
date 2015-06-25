package burp;

import java.io.PrintWriter;

//This is the class that is the entry point
//It registers the new menu item
public class BurpExtender implements IBurpExtender
{
    @SuppressWarnings("deprecation")
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
    	
    	stdout.println("Multi Scanner loaded.");
    	
    	callbacks.registerMenuItem("Extension: Multi Scanner", new MultiScannerMenuItem(callbacks));
    }
}

@SuppressWarnings("deprecation")
//This class implements the menu item and defines its clicked method
class MultiScannerMenuItem implements IMenuItemHandler
{
	IBurpExtenderCallbacks callbacks;
	ITextEditor myTextEditor;
	
	public MultiScannerMenuItem(IBurpExtenderCallbacks callbacksSent)
	{
		callbacks = callbacksSent;
	}
	
	//What happens when you initiate the Multi Scanner
	public void menuItemClicked(String caption, IHttpRequestResponse[] messageInfo)
	{
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println(new String(caption+"\nWe will make requests with the following user agents to check"
				+ "if the target website's mobile versions serve different responses.\nThe first UA is our"
				+ "baseline UA to compare against."));
        
     // write a message to the Burp alerts tab
        //callbacks.issueAlert("Hello alerts");

		
		String userAgentsList = "";
		System.out.println(caption+" clicked");
		
		// A list of all the user agents we use
		//This list can be augmented if we need
		//to impersonate more devices
		String userAgents [] = 
			{
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:16.0) Gecko/20100101 Firefox/16.0",
				"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
				"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
				"Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
				"Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; SAMSUNG; SGH-i917)",
				"Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)",
				"Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+"
			};
		
		//A data structure to save all the response lengths
		//This is shown to the viewer
		//It is also used to compare the responses
		long [][] responseLength = new long[messageInfo.length][userAgents.length];
		for(int i=0; i<messageInfo.length; i++)
		{
			for(int j=0; j<userAgents.length;j++)
			{
				responseLength[i][j]=0;
			}
		}
		
		
		//To set the list which we will use in UI component
		for(int i=0; i<userAgents.length;i++)
		{
			userAgentsList = userAgentsList.concat((i+1)+": "+userAgents[i]+"\n");
		}
				
		stdout.println(userAgentsList);
		
		//We will create request string and make http requests
		
		for(int curMsg=0; curMsg<messageInfo.length; curMsg++)
		{	
			IHttpRequestResponse mess = messageInfo[curMsg];
			IHttpService infoReq = mess.getHttpService();
			
			//Printing for debugging
			System.out.println(infoReq.getHost());
			System.out.println(infoReq.getPort());
			System.out.println(infoReq.getProtocol());
			
			int port = infoReq.getPort();
			String host = infoReq.getHost();
			boolean ssl = infoReq.getProtocol() == "https"?true: false;
			
			stdout.println("Making requests to target "+ host + "\n");
			
			for(int i=0; i<userAgents.length;i++)
			{	
					//Construct http request
					//For each target
					//For each user agent
					String httpRequestString = "GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: "+userAgents[i]+"\r\n\r\n";
					byte[] httpResponse = callbacks.makeHttpRequest(host, port, ssl, httpRequestString.getBytes());
					stdout.println(userAgents[i]);
					stdout.println("Response Length: ");
					stdout.println(httpResponse.length + "\n");
					responseLength[curMsg][i]=httpResponse.length;
			}
		}
		
		boolean isDiff = false, first = true;
		//Compare Responses
		for(int i=0; i<messageInfo.length; i++)
		{
			for(int j=0; j<userAgents.length;j++)
			{
				if(responseLength[i][j] !=  responseLength[i][0] && first)
				{
					//Mark that scan will have to be done
					stdout.println("Target "+messageInfo[i].getHttpService().getHost()+" has"
							+ " different versions."
							+ "\nSending to active scan.");
					isDiff = true;
					first = false;
				}
			}
			if(isDiff)
			{
				isDiff = false; //reset
				
				callbacks.issueAlert("Target: "+ messageInfo[i].getHttpService().getHost()+""
						+ "difering versions found. Scanning.");
				
				String httpRequestString = "";
				
				IHttpRequestResponse mess = messageInfo[i];
				IHttpService infoReq = mess.getHttpService();
				int port = infoReq.getPort();
				String host = infoReq.getHost();
				
				boolean ssl = infoReq.getProtocol() == "https"?true: false;
				
				for(int j=0; j<userAgents.length;j++)
				{
					//Construct http request
					//For each target
					//For each user agent
					httpRequestString = "GET / HTTP/1.1\r\nHost: "+host+"\r\n"
							+ "User-Agent: "+userAgents[j]+"\r\n\r\n";
					//Call active scan 
					callbacks.doActiveScan(host, port, ssl, httpRequestString.getBytes());
				}
			}
			else
			{
				//If the marking indicated scan is not needed
				callbacks.issueAlert("No differing versions found for "+ messageInfo[i].getHttpService().getHost()+""
						+ ". Not scanning.");
			}
			
			first = true;
		}
		
	}
}
