package burp.xxser.bin;

import java.io.PrintWriter;

public class Out {
	public static PrintWriter  out = new PrintWriter(BurpCallbacks.getBacks().getStdout()) ;
	public static void println(String  str){
		out.println(str);
		out.flush();
	}
	
	public static String  arrToString(String[] str){
		String temp = "" ;
		for (int i = 0; i < str.length; i++) {
			temp+=str[i]+"  |  ";
		}
		
		
		return temp.substring(0,temp.length()-5); 
	}
}
