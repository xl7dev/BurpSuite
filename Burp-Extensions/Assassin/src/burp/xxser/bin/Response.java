package burp.xxser.bin;



import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;

public class Response {

	private HttpURLConnection con;

	public Response(HttpURLConnection con) {
		this.con = con;
	}

	/**
	 * 
	 * @return  获取原始请求
	 */
	public HttpURLConnection getCon() {
		return con;
	}

	/**
	 * 获取请求头
	 * @param key
	 * @return
	 */
	public String getHeader(String key) {
		return this.con.getHeaderField(key);
	}

	/**
	 * 
	 * @return	获取内容，默认编码为GBK
	 */
	public String getBody() {

		return this.getBody("GBK");
	}
	
	
	/**
	 * 
	 * @param charset	字符编码
	 * @return	获取内容
	 */
	public String getBody(String charset) {

		BufferedReader buf = null;
		try {
			buf = new BufferedReader(new InputStreamReader(this.con
					.getInputStream()));
		} catch (IOException e) {
			e.printStackTrace();
		}

		StringBuilder sb = new StringBuilder();
		try {
			for (String temp = buf.readLine(); temp != null; temp = buf
					.readLine()) {
				sb.append(temp);
				sb.append(System.getProperty("line.separator"));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}
	

	/**
	 * 
	 * @return HTTP 状态码
	 */
	public int getResponseCode() {
		int temp = -1 ;
		try {
			 temp = this.con.getResponseCode() ;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return temp ;
		
	}
	
	

}
