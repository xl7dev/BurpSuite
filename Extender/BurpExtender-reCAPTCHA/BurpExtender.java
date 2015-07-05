/**
 * BurpExtender - Transparent reCAPTCHA proxy.
 * -------------------------------------------
 *
 * This module for Burp 1.4 and above intercepts HTTP requests
 * and detects the presense of reCAPTCHA. When reCAPTCHA is found
 * the CAPTCHA is validated passed to a CAPTCHA solving farm where
 * its solved. The solution in the form of  challenge/response 
 * string is then inserted into the Burp HTTP response.
 *
 * The Extension works well when the stock standard reCAPTCHA API
 * has been used. When it hasn't you'll need to do some tinkering
 * in order to get modificiation of the HTTP response to work 
 * correctly. The site http://www.google.com/recaptcha/learnmore 
 * works well with this plugin as do the stock examples that ship
 * with reCAPTCHA.
 *
 * Im not a Java Programmer - as a result this code may not be 
 * that great.
 *
 * @author Phil 01/01/2012
 * @url http://www.idontplaydarts.com 
 *
 **/

import java.net.URL;
import java.util.*;
import java.util.regex.*;
import java.io.*;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class BurpExtender
{
	public static final int API_TIMEOUT    = 180; // Maximum time to wait for the API to respond.
	public static final int API_MAX_ERRORS = 10; // Maximum, reCAPTCHAs to request per HTTP response.
	
	// Credentials for the reCAPTCHA API	
	public static String API_USERNAME = new String(""); 						
	public static String API_PASSWORD = new String(""); 	
		
    public burp.IBurpExtenderCallbacks mCallbacks;
	
	public String CAPTCHAID = new String("");	// Saves the last known CAPTCHA ID
	
	public void setCommandLineArgs(String[] args) 
	{
		try {
			if (args.length == 2) {		
				API_USERNAME = java.net.URLEncoder.encode(args[0], "ISO-8859-1");
				API_PASSWORD = java.net.URLEncoder.encode(args[1], "ISO-8859-1");
				for (String argument : args) {
					System.out.println("Invoked with " + argument);
				}
			}
        } 
		catch (Exception e)
        {
            e.printStackTrace();
        }		
	}	
	
    public void processHttpMessage(
            String toolName,
			boolean messageIsRequest,
			IHttpRequestResponse messageInfo)
    {
		if ((API_USERNAME == "") || (API_PASSWORD == "")) {
			mCallbacks.issueAlert("You must specify the DeathByCaptcha API credentials on the command line!\n");
		}
	
        if (!messageIsRequest)
        {
            try
            {
				// Extract the HTTP response from Burp
			
				String message 		= new String(messageInfo.getResponse());
				String reCAPTCHAKey = new String("");
				
				// Check for the reCAPTCHA script - if its not using the stock standard API
				// you'll need to modify these lines.
				
	            // Pattern pattern = Pattern.compile("www.google.com/recaptcha/api/noscript\\?k=(.+?)\"");
				
				Pattern pattern = Pattern.compile("<script.+?src=.+?\\?k=(6[a-zA-Z0-9\\-_]{39})");
				Matcher matcher = pattern.matcher(message);
				
				// If the script and the site key (k) are found:
				if (matcher.find()) {
		
					// Now contains the site key
					reCAPTCHAKey = matcher.group(1);				

					String cryptoKey = new String("");
					int	decodeAttempts = 0;
					
					// Decode the CAPTCHA and get the challenge_field back
					while((decodeAttempts < 3) && ((cryptoKey == null) || (cryptoKey.equals("")))) {
						cryptoKey = extractCaptcha(reCAPTCHAKey);
						decodeAttempts++;
					}
					
					if (decodeAttempts >= 3) {
						mCallbacks.issueAlert("CAPTCHA decoding failed 3 times in a row\n");
					} else {					
						// Replace the script tags with the challenge_field tags
						message = message.replaceAll("<script.+?src=.+?\\?k=(6[a-zA-Z0-9\\-_]{39}).*?>.*?</script>", "<input type=\"text\" name=\"recaptcha_challenge_field\" value=\"" +  cryptoKey + "\"><input type=\"text\" name=\"recaptcha_response_field\" value=\"manual_challenge\">");
						
						// Remove the content length - cant be bothered to update it.
						message = message.replaceAll("Content-Length:.+?\r\n", "");
																 
						// Set the HTTP response.
						messageInfo.setResponse(message.getBytes());		
					}
	
				}
				
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        
    }
	
	/**
	 * Takes a JPEG reCAPTCHA byte array and  passes it to DeathByCaptcha.com 
	 * for solving.
	 *
	 **/
	public String deathByCaptcha(byte[] image) {

		// Construct the HTTP POST header	
		String header = new String("POST /api/captcha HTTP/1.1\r\n"+
		"Host: api.deathbycaptcha.com\r\n"+
		"User-Agent: Burp Intruder - idontplaydarts.com\r\n"+
		"Content-Type: multipart/form-data; boundary=---------------------------41184676334\r\n");
				
		// Body - Constructing the multipart post for DeathByCaptcha
		String body = new String("-----------------------------41184676334\r\n" +
		"Content-Disposition: form-data; name=\"username\"\r\n\r\n" +
		API_USERNAME + "\r\n" +
		"-----------------------------41184676334\r\n" +
		"Content-Disposition: form-data; name=\"password\"\r\n\r\n" +
		API_PASSWORD + "\r\n" +
		"-----------------------------41184676334\r\n" +
		"Content-Disposition: form-data; name=\"captchafile\"; filename=\"burpImage.jpeg\"\r\n" +
		"Content-Type: image/jpeg\r\n\r\n" );
		
		// Update the content-length header
		String APIStringCall = header + "Content-length: " + (body.getBytes().length + image.length) + "\r\n\r\n" + body;
													
		byte[] APICall = new byte[APIStringCall.getBytes().length + image.length];
		
		// Export the String as a byte array for the Burp httpRequest method
		System.arraycopy(APIStringCall.getBytes(), 0, APICall, 0, APIStringCall.getBytes().length);
		System.arraycopy(image, 0, APICall, APIStringCall.getBytes().length, image.length);
	
		try {
		
			System.out.println("Making DeathByCaptcha call..");
		
			byte[] APIResponse = mCallbacks.makeHttpRequest("api.deathbycaptcha.com", 80, false, APICall);

			String APIStringResponse = new String(APIResponse);		
			
			if (APIStringResponse.indexOf("HTTP/1.1 303") > -1) {
			
				String captcha = new String();
				String text    = new String();
			
				System.out.println("Uploaded ok.");
				
					// Extract response, solution + captcha key
				
					Pattern pattern = Pattern.compile("captcha=(.+?)&text=(.*?)&");
					Matcher matcher = pattern.matcher(APIStringResponse);	
					
					if (matcher.find()) {
						text 	= matcher.group(2);
						captcha = matcher.group(1);			
					
						CAPTCHAID = captcha;
						System.out.println("Instant response => Text: '" + text + "' Captcha: " + captcha);						
							
						// If the captcha wasnt solved straight away then poll.
							
						String APIPollCall = new String("GET /api/captcha/" + captcha + " HTTP/1.1\r\nHost: api.deathbycaptcha.com\r\n\r\n");
							
						int i = 0;
							
						while (("".equals(text)) && (i < API_TIMEOUT)) {
							Thread.sleep(2000);
							byte[] APIPollResponse = mCallbacks.makeHttpRequest("api.deathbycaptcha.com", 80, false, APIPollCall.getBytes());
							String APIPollString = new String(APIPollResponse);
							//System.out.println(APIPollString);
							matcher = pattern.matcher(APIPollString);	
							if (matcher.find()) {
								text 	= matcher.group(2);
								captcha = matcher.group(1);		
								System.out.println("response  " + i + " => Text: " + text + " Captcha: " + captcha);																
							}
							i = i + 2;
						}
							
						if (i >= API_TIMEOUT) {
							mCallbacks.issueAlert("CAPTCHA " + CAPTCHAID + " timed out\n");
							CAPTCHAID = "";
							return "";
						}

						return text;
						
					}
					
				
			
			} else {
				
				mCallbacks.issueAlert("API responded with an unexpected status.\n");

				System.out.println("Somethings wrong with the API response.\n");
				System.out.println(APIStringResponse);
			
			}
		
		}
        catch (Exception e)
        {
			e.printStackTrace();
        }				
	
		return "";
	
	}
	
	public String extractCaptcha(String reCAPTCHAKey) {
			
			String HTTPHeaders = new String("GET /recaptcha/api/noscript?k=" + reCAPTCHAKey + " HTTP/1.1\r\nHost:www.google.com\r\n\r\n");
			
			byte[] HTTPHeaderBytes = HTTPHeaders.getBytes();
			
            try
            {			
			
				String IFrameResponse 	= new String(mCallbacks.makeHttpRequest("www.google.com", 80, false, HTTPHeaderBytes));
				String captchaImage	  	= new String();
				String captchaChallenge = new String();
				
				System.out.println("Got IFrame Response");
				
				// System.out.println(IFrameResponse);
			
				// Extract this
				// http://www.google.com/recaptcha/api/image?c=03AHJ_Vusuk8NPFGOHTJA2HQAX2kJTZ4kh2qMONMLmQrfgb3ixpbNcBinna7PjBSr1AM270g_7aeNIzyiOte5Rxd0rw-cGRiYujoT3Mv1aAgaIxFoZWapoFjRxGJwpdTLXza2FZLGlSdvaFxKlja3e-HP1jvyPTEdI_w

				Pattern pattern = Pattern.compile("image\\?c=(.+?)\"");
				Matcher matcher = pattern.matcher(IFrameResponse);					
				
				if (matcher.find()) {
				
					captchaImage = matcher.group(1);					
					System.out.println("Extracted CAPTCHA image: http://www.google.com/recaptcha/api/image?c=" + captchaImage);
						
					pattern = Pattern.compile(" id=\"recaptcha_challenge_field\" value=\"(.+?)\"");
					matcher = pattern.matcher(IFrameResponse);					
					
					if (matcher.find()) {
						captchaChallenge = matcher.group(1);
						System.out.println("Extracted challenge: " + captchaChallenge);	
						
					}
				
				}
				
				// Important parts extracted. Request the image.
				
				if ((captchaImage != "") && (captchaChallenge != "")) {
				
					String solution = new String();
				
					System.out.println("Requesting reCAPTCHA image...");
										
					HTTPHeaders = "GET /recaptcha/api/image?c=" + captchaImage + " HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
					HTTPHeaderBytes = HTTPHeaders.getBytes();
					
					byte[] reCAPTCHAImage = getResponseBody(mCallbacks.makeHttpRequest("www.google.com", 80, false, HTTPHeaderBytes));

					if (reCAPTCHAImage != null) {
						System.out.println("" + reCAPTCHAImage.length + " Bytes recieved.\n");
																			
						// Extracted CAPTCHA image - decode it 					
						solution = deathByCaptcha(reCAPTCHAImage);
					
					}		
					
					// Post to reCAPTCHA
					
					System.out.println("Captcha Decoded as: " + solution);
					
					if (!solution.equals("")) {
					
						String HTTPPostHeaders = new String("POST /recaptcha/api/noscript?k=" + reCAPTCHAKey + " HTTP/1.1\r\nHost:www.google.com\r\nContent-Type: application/x-www-form-urlencoded\r\n");
						String PostData = new String("recaptcha_challenge_field=" + captchaChallenge + "&recaptcha_response_field=" + solution + "&submit=I%27m+a+human");
						
						String reCAPTCHAResponse =  new String(HTTPPostHeaders + "Content-Length: " + PostData.length()  + "\r\n\r\n" + PostData);
						
						// Post to reCAPTCHA and see what the response was..
						
						byte[] reCAPTCHAReply = getResponseBody(mCallbacks.makeHttpRequest("www.google.com", 80, false, reCAPTCHAResponse.getBytes()));
			
						String reply = new String(reCAPTCHAReply);
						
					//	System.out.println(reply);
						
						if (reply.indexOf("Your answer was correct.") > -1) {
							
							System.out.println("Correct! Awesome ;)");
										
							pattern = Pattern.compile("<textarea.+?>(.+?)<");
							matcher = pattern.matcher(reply);												
							
							// Look for the token
							
							if (matcher.find()) {
							
								String securityCode = matcher.group(1);					
								System.out.println("Crypto Key: " + securityCode);
								return securityCode;
							
							}
							
						} else {
						
							// TODO: Report incorrect captcha
							if (!CAPTCHAID.equals("")) {
							
								String HTTPReportHead = new String("POST /api/captcha/" + CAPTCHAID + "/report HTTP/1.1\r\nHost: api.deathbycaptcha.com\r\n");
								String HTTPReportBody = new String("username=" + API_USERNAME + "&password=" + API_PASSWORD);
							
								String HTTPReport = new String();
								
								HTTPReport = HTTPReportHead + "Content-length: " + HTTPReportBody.length()  + "\r\n\r\n" + HTTPReportBody;
							
								byte[] reportResponse = mCallbacks.makeHttpRequest("api.deathbycaptcha.com", 80, false, HTTPReport.getBytes());
								
								String rResponse = new String(reportResponse);
								
								System.out.println("CATPCAH " + CAPTCHAID + " was incorrect :(" + rResponse);
								
								mCallbacks.issueAlert("CAPTCHA " + CAPTCHAID + " was reported as incorrect.\n");

							}
							
							return null;							
						
						}
						
					}
																						
				} else {
						
					mCallbacks.issueAlert("Error obtaining Google Image\n");
			
				}				
			
			}
            catch (Exception e)
            {
                e.printStackTrace();
            }
			
			return null;
			
	}
	
	// Works out the location of the response body in a HTTP Response.
	
	public byte[] getResponseBody(byte[] data) {
	
		for (int i = 0; i < data.length-4; i++) {
			if ((data[i] == 13) && (data[i+1] == 10) && (data[i+2] == 13) && (data[i+3] == 10)) {
				byte[] body = new byte[data.length-i-4];
				System.arraycopy(data, i+4, body, 0, data.length-i-4);
				return body;
			}
		}
		
		return null;
	}	
	
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        mCallbacks = callbacks;
    }
}
