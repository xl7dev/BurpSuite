package burp.xxser.bin;

import burp.IBurpExtenderCallbacks;

public class BurpCallbacks {
	
	private static IBurpExtenderCallbacks BURPCALLBACK ;
	
	/**
	 *  设置回调函数
	 * @param call
	 */
	public static  void setBacks(IBurpExtenderCallbacks call){
			BURPCALLBACK = call ;
	}
	
	/**
	 *获取回调函数
	 * @return
	 */
	public static IBurpExtenderCallbacks getBacks(){
		return  BURPCALLBACK ;
	}
	
	
}
