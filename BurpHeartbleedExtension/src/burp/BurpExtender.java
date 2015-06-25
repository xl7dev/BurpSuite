package burp;

/**
 * Heartbleed extension for burp suite.
 * @author Ashkan Jahanbakhsh
 *
 */

public class BurpExtender{
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		callbacks.registerMenuItem("Heartbleed this!", new HeartBleed(callbacks));
	}	
}