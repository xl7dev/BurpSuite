package burp.xxser.scan;

import java.util.HashSet;
import java.util.List;

import burp.xxser.bin.MyFile;

public class Test {
	public static int i ;
	public static void main(String[] args) {

		
	
		List<String> list = MyFile.readToList("c:/dic.txt");
		HashSet<String> dic = new HashSet<String>(list);
		for (int i = 0; i < 2; i++) {
			
		}

		
	
	}
}
