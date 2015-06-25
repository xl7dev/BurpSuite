package burp.xxser.bin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MyFile {

	private MyFile() {

	}

	public static Map<String, Object> getFileAttributes(String pathName) {
		Map<String, Object> map = new HashMap<String, Object>();
		File f = new File(pathName);
		map.put("canRead", (Boolean) f.canRead());
		map.put("canWrite", (Boolean) f.canWrite());
		map.put("isDirectory", (Boolean) f.isDirectory());
		map.put("isFil", (Boolean) f.isFile());
		map.put("length", (int) f.length());
		map.put("parent", f.getParent());
		return map;
	}

	/**
	 * 测试文件是否可读
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean canRead(String pathName) {
		return new File(pathName).canRead();
	}

	/**
	 * 测试文件是否可写
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean canWrite(String pathName) {
		return new File(pathName).canWrite();
	}

	/**
	 * 测试是否是目录
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean isDirectory(String pathName) {
		return new File(pathName).isDirectory();
	}

	/**
	 * 测试是否是文件
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean isFile(String pathName) {
		return new File(pathName).isFile();
	}

	/**
	 * 获取文件大小，字节数
	 * 
	 * @param pathName
	 * @return
	 */
	public static long getFileLength(String pathName) {
		return new File(pathName).length();
	}

	/**
	 * 返回父目录，如果没有，返回null
	 * 
	 * @param pathName
	 * @return
	 */
	public String getParent(String pathName) {
		return new File(pathName).getParent();
	}

	/**
	 * 获取目录，以及文件
	 * 
	 * @param pathName
	 * @return
	 */
	public static String[] getFilesName(String pathName) {
		return new File(pathName).list();
	}

	/**
	 * 建立文件夹，必须有父目录
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean mkdir(String pathName) {
		return new File(pathName).mkdir();
	}

	/**
	 * 建立文件夹，如果没有父目录，会先建立
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean mkdirs(String pathName) {
		return new File(pathName).mkdirs();
	}

	/**
	 * 删除文件,以及目录，会删除目录下面的所有目录，慎用
	 * 
	 * @param pathName
	 * @return
	 */
	public static void deleteFile(File file) {

		if (file.isFile()) {
			file.delete(); // 如果是文件的话就删除
		} else { // 否则的话就是目录，递归进行文件和目录的删除
			File[] files = file.listFiles();
			if (files != null) {
				for (File f : files) {
					deleteFile(f);
					f.delete();
				}
				file.delete();
			}
		}
	}

	/**
	 * 删除文件,以及目录，会删除目录下面的所有目录，慎用
	 * 
	 * @param pathName
	 */
	public static void deleteFile(String pathName) {
		deleteFile(new File(pathName));

	}

	/**
	 * 在虚拟机退出的时候删除文件
	 * 
	 * @param pathName
	 * @return
	 */
	public static void deleteOnExit(String pathName) {
		new File(pathName).deleteOnExit();
	}

	/**
	 * 读取文件操作
	 * 
	 * @param pathName
	 * @return
	 * @throws Exception
	 */
	public static String read(String pathName) {
		BufferedReader buffer = null;
		String lin = System.getProperty("line.separator"); // 准备换行符
		StringBuilder sb = new StringBuilder();
		try {
			buffer = new BufferedReader(new FileReader(pathName));
			String temp = buffer.readLine();
			while (temp != null) {
				sb.append(temp + lin);
				temp = buffer.readLine();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				buffer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return sb.toString();
	}

	/**
	 * 读取为List集合 UTF-8编号
	 * 
	 * @param pathName
	 * @return
	 */
	public static List<String> readToList(String pathName) {
		return readToList(pathName, "UTF-8");
	}
	
	
	/**
	 * 读取为List集合 并且制定编码
	 * @param pathName
	 * @return
	 */
	public static List<String> readToList(String pathName, String charset) {
		
		
		try {
			return readToList(new FileInputStream(pathName), charset);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return null ;
	}

	public static List<String> readToList(InputStream in, String charset) {
		ArrayList<String> list = new ArrayList<String>();
		BufferedReader bf = null;
		try {
			bf = new BufferedReader(new InputStreamReader(in,charset));
			for(String temp = bf.readLine();temp!=null;temp=bf.readLine()){
				list.add(temp);
			}
			bf.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		return list;
	}
	
	public static List<String> readToList(InputStream in) {
		return readToList(in, "UTF-8");
	}
	
	
	
	/**
	 * 写文件的操作,如果文件有数据，直接替换掉里面的数据
	 * 
	 * @param pathName
	 *            路径名
	 * @param content
	 *            内容
	 * @return
	 */
	public static boolean write(String pathName, String content) {
		return write(pathName, content, false);
	}

	/**
	 * 写文件的操作
	 * 
	 * @param pathName
	 *            路径
	 * @param content
	 *            内容
	 * @param flag
	 *            是否追加到末尾
	 * @return
	 */
	private static boolean write(String pathName, String content,
			boolean flag) {

		OutputStream os = null;
		boolean flags = false; // 是否成功的标志位
		try {
			os = new FileOutputStream(new File(pathName), flag);
			os.write(content.getBytes()); // 写入数据
			flags = true;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return flags;
	}

	/**
	 * 文件备份操作,默认为当前文件夹
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean backupFile(String pathName) {
		return backupFile(pathName, pathName);
	}

	/**
	 * 文件备份操作,可以设置新路径
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean backupFile(String pathName, String newpathName) {
		File f = new File(pathName);
		if (!f.isFile()) {
			return false;
		}
		return write(newpathName + ".bak", read(pathName));
	}

	/**
	 * 恢复备份文件,恢复在当前目录下
	 * 
	 * @param pathName
	 * @param delete
	 *            是否删除备份文件
	 * @return
	 */
	public static boolean recoveryBackupFile(String pathName, boolean delete) {
		String newpathName = pathName.substring(0, pathName.lastIndexOf("."));
		String temp = read(pathName);
		if (delete) {
			deleteFile(new File(pathName));
		}
		return write(newpathName, temp);
	}

	/**
	 * 恢复备份文件,默认删除备份文件
	 * 
	 * @param pathName
	 * @return
	 */
	public static boolean recoveryBackupFile(String pathName) {
		return recoveryBackupFile(pathName, true);
	}

}
