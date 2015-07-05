package burp.JSBeautifier;


import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.SequenceInputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import org.mozilla.javascript.*;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.JSBeautifier.UnicodeBOMInputStream.BOM;
import burp.customGUI.ViewHighlightedTextForm;

public class JSBeautifierFunctions {
	private boolean isAutomatic = false; // Automatic or Manual ?
	private final burp.IBurpExtenderCallbacks mCallbacks;
	private final PrintWriter stdout;
	private final PrintWriter stderr;
	private String encoding = "UTF-8";
	private static String beautifierJS = "";
	private int msgType = -1;
	private static ScriptableObject sharedScope;
	private final static Pattern patternCDATA = Pattern.compile("(?i)^[\\s\\/\\*]*\\<\\!\\[CDATA\\["); // Fix Possible <![CDATA[ bugs!
	
	// application common messages
	private enum messageList {
		msgNullMessage("Text should not be Null."),
		msgEmptyMessage("Text does not have the required encoding to be beautified, or it is empty."),
		msgReadOnlyMessage("Text is ReadOnly. A new window will be opened shortly."),
		msgRequestHasBeenIssued("It is not possible to beautify this request, please send it to repeater."),
		msgFatalMessage("Fatal Error :(\nPlease review the console for the error.");
		private String strMessage;
		
		private messageList(String msg) {
			strMessage = msg;
		}

		public String getMessage() {
			return strMessage;
		}
	}

	// constructor
	public JSBeautifierFunctions(IBurpExtenderCallbacks mCallbacks) {
		super();
		this.msgType = -1;
		this.mCallbacks = mCallbacks;
		// obtain our output stream
        stdout = new PrintWriter(mCallbacks.getStdout(), true);
        stderr = new PrintWriter(mCallbacks.getStderr(), true);
	}

	
	// This function should be called in order to beautify a message
	public void beautifyIt(IHttpRequestResponse[] messageInfo, boolean isAuto,int msgType)
	{
		this.isAutomatic = isAuto;
		this.msgType = msgType;
		String[] requestHeaderAndBody = {"",""};
		String[] responsetHeaderAndBody ={"",""};
		String finalRequestHeaderAndBody = "";
		String finalResponsetHeaderAndBody = "";
		int messageState = 0;
		byte[] request;
		byte[] response;
		try {

			// This is not in-use anymore!
			
			if(msgType==-1){
				if(!requestHeaderAndBody[1].equals("") && !responsetHeaderAndBody[1].equals("") && !isNormalPostMessage(requestHeaderAndBody[1]) && !isAutomatic){
					String[] options = {"Only on response", "Only on request", "On both", "Cancel"};
					int n = askConfirmMessage("Please choose an option:", "Response and Request are available, do you want to run beautifier?",options);
					switch(n){
					case 0:
						msgType = 2; // It is a response
						break;
					case 1:
						msgType = 1; // It is a request
						break;
					case 2:
						msgType = 3; // It is both!
						break;
					case 3:
						msgType=0; // Cancel! Then Exit!
						break;
					}
				}else if(requestHeaderAndBody[1].equals("") && responsetHeaderAndBody[1].equals("")){
					msgType=0; // Nothing to be beautified!
				}else{
					msgType = (!responsetHeaderAndBody[1].equals("")) ? 2 : 1; // 1= request, 2= response -> I need to check the response first!
					if(msgType==1 && (isNormalPostMessage(requestHeaderAndBody[1]) || msgType==1 && isAutomatic)){
						// It is a normal POST message and should not be beautified
						msgType= 0;
					}
				}
			}
			
			
			switch(msgType){
				case 3:
					// Implementing the message type
					request = messageInfo[0].getRequest();
					response = messageInfo[0].getResponse(); 
					// create array of Header and Body for Request and Response
					requestHeaderAndBody = getHeaderAndBody(request);
					responsetHeaderAndBody = getHeaderAndBody(response);
					break;
				case 2:
					response = messageInfo[0].getResponse(); 
					responsetHeaderAndBody = getHeaderAndBody(response);
					break;
				case 1:
					request = messageInfo[0].getRequest();
					requestHeaderAndBody = getHeaderAndBody(request);
					break;
			}

			// Check the response content-type to be a valid text
			if(msgType==2 || msgType==3){
				
				if(!isValidContentType(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// Content-Type is not valid, we need to ask the user for confirmation
					int n = 1;
					if(!isAutomatic){
						String[] options = {"Yes, please continue ","No, please do not beautify the response"};
						n = askConfirmMessage("Please choose an option:", "Response content-type has not been recognised, do you still want to run beautifier?",options);
					}
					if(n==1){
						//No has been selected
						if(msgType==2){
							msgType = 0;  // stop beautifying the response
							return; // Exit
						}else{
							msgType = 1; // only beautify the request
						}
					}
				}
			}

			switch(msgType){
			case 3:
			case 2:// It is a response
				if(msgType==3){
					// Request & Response
					if(BeautifierPreferences.isBeautifyHeadersInManualMode()){
						requestHeaderAndBody[0] = deCompress(requestHeaderAndBody[0]);
					}
					requestHeaderAndBody[1] = deCompress(requestHeaderAndBody[1]);
					requestHeaderAndBody[0] = requestHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\t\\d]+$", "Content-Length: "+requestHeaderAndBody[1].length());
				}
				
				if(isUnprotectedCSSFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1])){
					// If it is a CSS file, it needs to have a <STYLE> tag in its body, otherwise it will be corrupted
					responsetHeaderAndBody[1] = "<STYLE my/beautifier>"+responsetHeaderAndBody[1]+"</STYLE my/beautifier>";
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<STYLE my/beautifier>", "");
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("</STYLE my/beautifier>", "");
				}else if(isHtmlXmlFile(responsetHeaderAndBody[0],responsetHeaderAndBody[1]) || isDotNetPipeDelimitedResponse(responsetHeaderAndBody[1])){
					// If it is a HTML or XML file, it should be started with a valid tag
					responsetHeaderAndBody[1] = "<my beautifier unique thing />"+responsetHeaderAndBody[1];
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replace("<my beautifier unique thing />", "");
					
					// Fix possible <![CDATA[ bugs!
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replaceAll("(?im)[\\s]*\\<\\ \\!\\[CDATA\\[", "<![CDATA[");
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replaceAll("(?im)\\/\\/[\\s]+<\\!\\[CDATA\\[", "//<![CDATA[");
					// Fix possible free space on top (<?xml or <!doctype and so on)
					responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replaceAll("(?i)^[\\s]+", "");
					
					// Fix other problems of .Net Pipe-delimited response
					if(isDotNetPipeDelimitedResponse(responsetHeaderAndBody[1]))
					{
						responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replaceAll("(?i)\\\\[\\s]+\"[\\s]*:", "\\\\\":");
						responsetHeaderAndBody[1] = responsetHeaderAndBody[1].replaceAll("(?i)\\\\[\\s]+\"[\\s]*,", "\\\\\",");
					}
					
				}else{
					responsetHeaderAndBody[1] = deCompress(responsetHeaderAndBody[1]);
				}
				
				if(BeautifierPreferences.isBeautifyHeadersInManualMode()){
					responsetHeaderAndBody[0] = deCompress(responsetHeaderAndBody[0]);
				}
				responsetHeaderAndBody[0] = responsetHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\t\\d]+$", "Content-Length: "+responsetHeaderAndBody[1].length()+4); // 4 additional characters are "\r\n\r\n" which will be added later
				break;
			case 1: // It is a request
				requestHeaderAndBody[1] = deCompress(requestHeaderAndBody[1]);
				if(BeautifierPreferences.isBeautifyHeadersInManualMode()){
					requestHeaderAndBody[0] = deCompress(requestHeaderAndBody[0]);
				}
				
				requestHeaderAndBody[0] = requestHeaderAndBody[0].replaceAll("(?im)^content\\-length:[\\ \\t\\d]+$", "Content-Length: "+requestHeaderAndBody[1].length());				
				break;
			case 0:
				// Nothing is there! Nothing to be beautified!
				showMessage(messageList.msgEmptyMessage.getMessage());
				return;
			}



			// Create the final/beautified text for Request and Response - They would be empty if they are not available
			finalRequestHeaderAndBody = requestHeaderAndBody[0]+"\r\n\r\n"+requestHeaderAndBody[1];
			finalResponsetHeaderAndBody = responsetHeaderAndBody[0]+"\r\n\r\n"+responsetHeaderAndBody[1];

			
			if (msgType==1){
				messageInfo[0].setRequest(finalRequestHeaderAndBody.getBytes(encoding));
				messageState = 1;
			}else if (msgType==2){
				messageInfo[0].setResponse(finalResponsetHeaderAndBody.getBytes(encoding));
				messageState = 1;
			}else{
				messageInfo[0].setRequest(finalRequestHeaderAndBody.getBytes(encoding));
				messageState = 1;
				messageInfo[0].setResponse(finalResponsetHeaderAndBody.getBytes(encoding));
				messageState = 2;
			}

		}catch (Exception e) {
			if(e.getMessage().equalsIgnoreCase("Item is read-only") && !isAutomatic)
			{
				// Read only item - we need to open a new message box
				showMessage(messageList.msgReadOnlyMessage.getMessage());

				ViewHighlightedTextForm showMsgForm = new ViewHighlightedTextForm();

				if (msgType==1){
					showMsgForm.showForm(BeautifierPreferences.getAppInfo(), finalRequestHeaderAndBody, "text/html", 600, 450);
				}else if (msgType==2){
					showMsgForm.showForm(BeautifierPreferences.getAppInfo(), finalResponsetHeaderAndBody, "text/html", 600, 450);
				}else{
					if(messageState==0)
						showMsgForm.showForm(BeautifierPreferences.getAppInfo(), finalRequestHeaderAndBody, "text/html", 600, 450);
					showMsgForm.showForm(BeautifierPreferences.getAppInfo(), finalResponsetHeaderAndBody, "text/html", 600, 450);
				}

			}else if(e.getMessage().equalsIgnoreCase("Request has already been issued") && !isAutomatic){
				//showMessage(messageList.msgRequestHasBeenIssued.getMessage());
				// It seems it can change the request anyway! so we ignore this error for now!
			}else{
				// Not catched error
				showMessage(messageList.msgFatalMessage.getMessage());
				if(BeautifierPreferences.isDebugMode())
					e.printStackTrace(stderr);
			}

		}
	}

	// Running the beautifier javascript on the text
	private String deCompress(String strInput){
		if(strInput==null)
			return "";
		if(strInput.equals(""))
			return "";

		String[] testBOMInput = splitBOMCharacter(strInput); // Find any BOM to remove it
		boolean hasBOM = !testBOMInput[0].equals(""); // Does it have BOM?
		// Removing BOM from the input
		if(hasBOM){
			strInput = testBOMInput[1];
		}

		String finalResult = "";
		try {
			// Set version to JavaScript1.2 so that we get object-literal style
			// printing instead of "[object Object]"
			// http://jsbeautifier.org/beautify.js
			// Javascripts from "http://jsbeautifier.org/" has been mixed in 1 line - March 2012

			// Loading the JavaScript
			if(beautifierJS.equals("")){			
				//beautifierJS ="";
				String[] fileList = {"beautify-css.js","beautify-html.js","beautify.js","javascriptobfuscator_unpacker.js","myobfuscate_unpacker.js","p_a_c_k_e_r_unpacker.js","urlencode_unpacker.js","inlineJS.js"};
				try{

					String encoding = "UTF-8"; /* You need to know the right character encoding. */

					InputStream[] fileStreams = new InputStream[fileList.length];
					for (int i=0;i<fileStreams.length;i++){
						fileStreams[i] = getClass().getResourceAsStream("/"+fileList[i]);

					}

					Enumeration<InputStream> streams = 
							Collections.enumeration(Arrays.asList(fileStreams));
					Reader r = new InputStreamReader(new SequenceInputStream(streams), encoding);
					char[] buf = new char[2048];
					StringBuilder str = new StringBuilder();
					while (true) {
						int n = r.read(buf);
						if (n < 0)
							break;
						str.append(buf, 0, n);
					}
					r.close();
					beautifierJS = str.toString();
					if (BeautifierPreferences.isDebugMode())
						stdout.println("Javascript files have been loaded successfully.");
				}catch(IOException errIO){
					stderr.println("Error: IO error. Please check the required files: " + fileList.toString());
					if (BeautifierPreferences.isDebugMode())
						errIO.printStackTrace(stderr);
					stderr.println("Unable to load the JavaScript files.");
				}
			}
			
			// this is just a try to store this object in memory to increase performance after the first run
			
			Context cx= Context.enter();
			cx.setOptimizationLevel(-1);
			cx.setLanguageVersion(Context.VERSION_DEFAULT);
			if(sharedScope==null){
				// Initialize the standard objects (Object, Function, etc.)
				// This must be done before scripts can be executed.
				sharedScope = cx.initStandardObjects(null, true);
				// defining "global" will fix the bug in which we could not have access to beautifier main functions
				cx.evaluateString(sharedScope, "var global = {};"+beautifierJS,"myBeautifier", 1, null);
			}

			// Add settings to beautifier
			String beautifierSettingVars = "var indent_size = %d;";
			beautifierSettingVars+="var indent_char = '%s';";
			beautifierSettingVars+="var max_preserve_newlines = %d;";
			beautifierSettingVars+="var preserve_newlines = %b;";
			beautifierSettingVars+="var keep_array_indentation = %b;";
			beautifierSettingVars+="var break_chained_methods = %b;";
			beautifierSettingVars+="var space_after_anon_function = %b;";
			beautifierSettingVars+="var indent_scripts = '%s';";
			beautifierSettingVars+="var brace_style = '%s';";
			beautifierSettingVars+="var space_before_conditional = %b;";
			beautifierSettingVars+="var detect_packers = %b;";
			beautifierSettingVars+="var unescape_strings = %b;";
			beautifierSettingVars+="var wrap_line_length = %d;";
			
			beautifierSettingVars = String.format(beautifierSettingVars,BeautifierPreferences.getIndent_size(),BeautifierPreferences.getIndent_char(),BeautifierPreferences.getMax_preserve_newlines(),BeautifierPreferences.isPreserve_newlines(),
					BeautifierPreferences.isKeep_array_indentation(),BeautifierPreferences.isBreak_chained_methods(),BeautifierPreferences.isSpace_after_anon_function(),BeautifierPreferences.getIndent_scripts(),
					BeautifierPreferences.getBrace_style(),BeautifierPreferences.isSpace_before_conditional(),BeautifierPreferences.isDetect_packers(),BeautifierPreferences.isUnescape_strings(),
					BeautifierPreferences.getWrap_line_length());
			
			cx.evaluateString(sharedScope, beautifierSettingVars, "beautifierSettingVars", 1, null);

			// Now we can evaluate a script. Let's create a new object
			// using the object literal notation

			Object fObj = sharedScope.get("beautify", sharedScope);
			
			if (!(fObj instanceof Function)) {
				stderr.println("beautify is undefined or not a function.");
			} else {
				Object functionArgs[] = { strInput };
				Function f = (Function)fObj;
				Object result1 = f.call(cx, sharedScope, sharedScope, functionArgs);
				finalResult = Context.toString(result1);
//				if(BeautifierPreferences.isDebugMode())
//					stdout.println("Result after beautifying= \r\n"+finalResult);
			}

		} catch (Exception e) {
			if(BeautifierPreferences.isDebugMode())
				e.printStackTrace(stderr);
		}finally {
			Context.exit();
		}

		// Adding BOM to the result
		if(hasBOM){
			finalResult = testBOMInput[0]+finalResult;
		}
		return finalResult;
	}

	// Show a message to the user
	public void showMessage(String strMsg){
		//mCallbacks.issueAlert(strMsg);
		if(!isAutomatic || BeautifierPreferences.isDebugMode())
		{
			JOptionPane.showMessageDialog(null, strMsg);
		}
		stdout.println(strMsg);
	}

	// Common method to ask a multiple question
	public Integer askConfirmMessage(String strTitle, String strQuestion, String[] msgOptions){
		Object[] options = msgOptions;
		int n = 0;
		n = JOptionPane.showOptionDialog(null,
				strQuestion,
				strTitle,
				JOptionPane.YES_NO_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				null,
				options,
				options[0]);
		return n;
	}

	// Split header and body of a request or response
	private String[] getHeaderAndBody(byte[] fullMessage) throws UnsupportedEncodingException{
		String[] result = {"",""};
		String strFullMessage = "";
		if(fullMessage != null){
			// splitting the message to retrieve the header and the body
			strFullMessage = new String(fullMessage,encoding);
			if(strFullMessage.contains("\r\n\r\n"))
				result = strFullMessage.split("\r\n\r\n",2);
		}
		return result;
	}

	// Read the Content-Type value from the header
	private String findHeaderContentType(String strHeader){
		String contentType="";
		if(!strHeader.equals("")){
			Pattern MY_PATTERN = Pattern.compile("(?im)^content-type:([\\ \\w\\/\\-\\_\\,]*)"); // just in case, it also includes ",_ " 
			Matcher m = MY_PATTERN.matcher(strHeader);
			if (m.find()) {
				contentType = m.group(1);
			}
		}
		return contentType;
	}

	// Check to see if it is a Pipe-delimited .Net Ajax response
	private boolean isDotNetPipeDelimitedResponse(String strBody){
		boolean result = false;
		if(strBody.split("|").length > 3 && !strBody.trim().startsWith("<")){
			result = true; // It seems it is a DotNet delimited response /:)
		}
		
		return result;
	}
	// Check to see if it is a CSS file to protect it from being corrupted
	private boolean isUnprotectedCSSFile(String strHeader, String strBody){
		boolean result = false;
		// Check if it is a CSS file to prevent from being checked as a JS file
		if(!strHeader.equals("") && !strBody.equals("")){
			if(findHeaderContentType(strHeader).toLowerCase().contains("css")){
				String startwithStyleTagRegex = "(?i)^[\\s]*\\<style[\\s\\\\/>]+";
				if(!strBody.matches(startwithStyleTagRegex)){
					result = true; // It does not start with any <style tag
				}
			}
		}
		return result;
	}

	// Check to see if it is a HTML or XML file
	private boolean isHtmlXmlFile(String strHeader, String strBody){
		boolean result = false;
		// Check if it is a CSS file to prevent from being checked as a JS file
		if(!strHeader.equals("") && !strBody.equals("") && !patternCDATA.matcher(strBody).find()){
			if(findHeaderContentType(strHeader).toLowerCase().contains("html") || findHeaderContentType(strHeader).toLowerCase().contains("xml")){
				result = true;
			}
		}
		return result;
	}

	// Check for Byte Order Mark (BOM) character ~ http://www.unicode.org/faq/utf_bom.html#BOM
	// split the text to two sections: [0]=BOM Character,[1]=Text without BOM character
	private String[] splitBOMCharacter(String strInput){
		String[] strResult = {"",""};
		if (strInput == null)
			return strResult;

		if(!strInput.equals("")){
			final byte[] byteInput = strInput.getBytes();
			if(byteInput.length>4){
				if ((byteInput[0] == (byte)0xFF) &&
						(byteInput[1] == (byte)0xFE) &&
						(byteInput[2] == (byte)0x00) &&
						(byteInput[3] == (byte)0x00))
				{
					strResult[0] = new String(BOM.UTF_32_LE.bytes);


				}
				else if ((byteInput[0] == (byte)0x00) &&
						(byteInput[1] == (byte)0x00) &&
						(byteInput[2] == (byte)0xFE) &&
						(byteInput[3] == (byte)0xFF))
				{
					strResult[0]  = new String(BOM.UTF_32_BE.bytes);

				} else				if ((byteInput[0] == (byte)0xEF) &&
						(byteInput[1] == (byte)0xBB) &&
						(byteInput[2] == (byte)0xBF))
				{
					strResult[0]  = new String(BOM.UTF_8.bytes);

				}else if ((byteInput[0] == (byte)0xFF) &&
						(byteInput[1] == (byte)0xFE))
				{
					strResult[0]  = new String(BOM.UTF_16_LE.bytes);

				}
				else			if ((byteInput[0] == (byte)0xFE) &&
						(byteInput[1] == (byte)0xFF))
				{
					strResult[0]  = new String(BOM.UTF_16_BE.bytes);

				}else{

					strResult[0]  = "";
				}
				strResult[1] = strInput.substring(strResult[0].length());
			}else{
				strResult[1] = strInput; // this text is not important for us!
			}
		}
		return strResult;
	}

	// Check the content type of the response message to be in text-format 
	private boolean isValidContentType(String strHeader, String strBody){
		boolean result = false;
		if(!strHeader.equals("")){

			// 1- Check for a URL/Link usually for ajax queries, we do not want to beautify it if it only contains a URL (normal or relative)		
			// Fixed provided by augustd at codemagi.com - https://code.google.com/p/burp-suite-beautifier-extension/issues/detail?id=2 
			try {
			    URL dummy_url = new java.net.URL(strBody);
			    return false; // We do not want to beautify it if it only contains a URL (normal or relative)
			} catch (MalformedURLException me) {
			    //not a URL
			}
			// 2- Check for the Content-Type value  now!
			String contentType= findHeaderContentType(strHeader);
			if(BeautifierPreferences.isDebugMode())
				stdout.println(contentType);
			// We are only interested in the following types
			// main beautifier function cannot work with a CSS file without having a STYLE tag - a fix needs to be added later
			String[] validTypes = {"text","html","xml","javascript","vml","svg","json","ajax","css"}; 
			for(String item : validTypes){
				if (contentType.toLowerCase().contains(item.toLowerCase())){
					result = true;
					break;
				}
			}
		}
		return result;
	}

	// Check the body of the request to not be a normal POST request
	private boolean isNormalPostMessage(String strBody){
		boolean result = false;
		if(!strBody.equals("")){
			// We are only interested when there is a valid pair
			if((strBody.startsWith("{") && strBody.endsWith("}"))||(strBody.startsWith("<") && strBody.endsWith(">"))||(strBody.startsWith("[") && strBody.endsWith("]"))||(strBody.startsWith("(") && strBody.endsWith(")"))){
				// It seems valid to be beautified as it is not a normal POST message
				result = false;
			}else{
				// It is a normal POST message? even multipart/form-data? 
				result = true;
			}
		}
		return result;
	}
}
