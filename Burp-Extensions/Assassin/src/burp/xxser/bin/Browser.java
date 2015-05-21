package burp.xxser.bin;

public class Browser {
	public static void start(String url){
		
		int temp =	Command.linuxOrWindows();
		if(temp==0){
			Command.execute("firefox "+url);
		}else{
			Command.execute("start "+url);
		}
	}
}
