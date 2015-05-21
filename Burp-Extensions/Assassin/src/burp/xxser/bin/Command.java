package burp.xxser.bin;

import java.io.IOException;

public class Command {
	public static void execute(String command){
		
		try {
			if(linuxOrWindows()==0){
				Runtime.getRuntime().exec(command);
			}else{
				Runtime.getRuntime().exec("cmd /c "+command);
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * is linux Or Windows
	 * @return
	 */
	public static int linuxOrWindows(){
		if (System.getProperty("os.name").toLowerCase().contains("Linux".toLowerCase())) {
			return 0 ;
		} 
		return 1;
		
	}
	
}
