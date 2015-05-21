package burp.xxser.bin;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class NetHelper {
	
	public static String[]  getIpAddress(String host){
		
		
		if(host==null || "".equals(host)){
			return  null ;
		}
			
		InetAddress[] address = null ;
		try {
			address =	InetAddress.getAllByName(removeHttp(host));
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return null ;
		}
		
		
		String  temp[] = new String[address.length];
		
		for (int i = 0; i < address.length; i++) {
			temp[i] = address[i].getHostAddress();
		}
		return temp ;
	}
	
	private static String  removeHttp(String host){
		host = host.toLowerCase();
		
		if(host.startsWith("http://")){
			return host.substring(7);
		}
		
		if(host.startsWith("https://")){
			return host.substring(8);
		}
		
		return host ;
	}
	
	
	
	
}
