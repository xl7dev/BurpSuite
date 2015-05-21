package burp;

import java.io.PrintWriter;

import burp.xxser.bin.BurpCallbacks;
import burp.xxser.bin.ContextMenuShow;

public class BurpExtender implements IBurpExtender {
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
			
			BurpCallbacks.setBacks(callbacks);
			BurpCallbacks.getBacks().registerContextMenuFactory(new ContextMenuShow());
			PrintWriter out = new PrintWriter(callbacks.getStdout(),true);
			out.println("registerExtenderCallbacks  successful !!!");
			out.close();
			
	}
}
