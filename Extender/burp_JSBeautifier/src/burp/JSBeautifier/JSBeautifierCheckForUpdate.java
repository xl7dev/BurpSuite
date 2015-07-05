package burp.JSBeautifier;

import java.io.PrintWriter;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

// Usage: 
// JSBeautifierCheckForUpdate testme = new burp.JSBeautifier.JSBeautifierCheckForUpdate(mCallbacks);
// testme.updateStatus
public class JSBeautifierCheckForUpdate {
	
	private static final String strChangeLogURL = "https://raw.githubusercontent.com/irsdl/BurpSuiteJSBeautifier/master/jsbeautifier/CHANGELOG";
	private final burp.IBurpExtenderCallbacks mCallbacks;
	private final PrintWriter stdout;
	private final PrintWriter stderr;
	public int updateStatus = -1;
	public String updateMessage = "";
	
	public JSBeautifierCheckForUpdate(IBurpExtenderCallbacks mCallbacks) {
		this.mCallbacks = mCallbacks;		
		IExtensionHelpers helper = mCallbacks.getHelpers();
		 stdout = new PrintWriter(mCallbacks.getStdout(), true);
	     stderr = new PrintWriter(mCallbacks.getStderr(), true);
	     Double currenVersion = BeautifierPreferences.getVersion();
	     Double latestVersion = 0.0;
		try{
			URL changeLogURL = new URL(strChangeLogURL);
			byte[] request = helper.buildHttpRequest(changeLogURL);
			byte[] response = mCallbacks.makeHttpRequest(changeLogURL.getHost(), 443, true, request);
			
			if(response != null){
				// splitting the message to retrieve the header and the body
				String strFullMessage = new String(response,"UTF-8");
				if(strFullMessage.contains("\r\n\r\n")){
					String strBody = strFullMessage.split("\r\n\r\n",2)[1];
					Pattern MY_PATTERN = Pattern.compile("(?im)^[\\s]*v[\\s]*(\\d+(\\.*\\d*){0,1})$"); 
					
					Matcher m = MY_PATTERN.matcher(strBody);
					
					if (m.find()) {
						latestVersion = Double.parseDouble(m.group(1));
						
						if (latestVersion > currenVersion){
							updateStatus = 1; // update is available
						}else if (latestVersion.equals(currenVersion)){
							updateStatus = 0; // no update is available
						}else{
							updateStatus = 2; // Future version!
						}
					}
				}
					
			}
		}catch(Exception e){
			stderr.println(e.getMessage());
		}
		
		switch(updateStatus){
		case -1:
			updateMessage = "Check for update failed: Could not get proper response from "+strChangeLogURL.toString();
			stderr.println(updateMessage);
			break;
		case 0:
			updateMessage = "This version is up to date.";
			stdout.println(updateMessage);
			break;
		case 1:
			updateMessage = "Version "+latestVersion.toString()+" is available via GitHub: "+BeautifierPreferences.getProjectLink();
			stdout.println(updateMessage);
			break;
		case 2:
			updateMessage = "This version is more up to date!";
			stdout.println(updateMessage);
			break;
		}
		
	}
	

}
