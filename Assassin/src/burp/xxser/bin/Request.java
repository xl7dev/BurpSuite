package burp.xxser.bin;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Request {

	private URL url;
	private HttpURLConnection con;
	private Proxy proxy = null;
	
	
	//忽略SSH
	{
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager(){
			    public X509Certificate[] getAcceptedIssuers(){return null;}
			    public void checkClientTrusted(X509Certificate[] certs, String authType){}
			    public void checkServerTrusted(X509Certificate[] certs, String authType){}
			}};
			// Install the all-trusting trust manager
		    SSLContext sc = null;
			sc = SSLContext.getInstance("TLS");
			 sc.init(null, trustAllCerts, new SecureRandom());
			    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 构造方法
	 * 
	 * @param url
	 *            Url信息
	 */
	public Request(String url) {
		try {
			this.url = new URL(url);
			this.init();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param url
	 *            URL 信息
	 * @param proxy
	 *            代理
	 */
	public Request(String url, Proxy proxy) {
		try {
			this.url = new URL(url);
			this.proxy = proxy;
			this.init();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

	public Request(URL url) {
		this.url = url;
		this.init();
	}

	public URL getUrl() {
		return url;
	}

	public HttpURLConnection getCon() {
		return con;
	}

	/**
	 * 初始化 HTTP 信息
	 */
	private void init() {
		try {

		
			if (this.proxy == null) {

				this.con = (HttpURLConnection) url.openConnection();
				
			} else {
				this.con = (HttpURLConnection) this.url
						.openConnection(this.proxy);
			}
this.setHeader("User-Agent","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36 SE 2.X MetaSr 1.0");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 得到Response
	 * 
	 * @return
	 * @throws IOException 
	 */
	public Response getResponse() throws IOException {
		try {
			this.con.setDoOutput(true);
			this.con.getInputStream(); // 发起请求
		} catch (IOException e) {
			e.printStackTrace();
			throw e ;
		}

		Response res = new Response(this.con);
		return res;
	}

	/**
	 * 设置请求方法
	 * 
	 * @param method
	 */
	public void setMethod(String method) {
		try {
			this.con.setRequestMethod(method);
		} catch (ProtocolException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 设置请求头
	 * 
	 * @param h
	 *            头
	 * @param v
	 *            值
	 */
	public Request setHeader(String h, String v) {

		this.con.addRequestProperty(h, v);
		return this;
	}

	/**
	 *设置请求头内容
	 * 
	 * @param data
	 */
	public Request setData(String data) {
		
		OutputStream os = null;
		try {
			os = this.con.getOutputStream();
			os.write(data.getBytes());
			os.close() ;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return this ;
	}
	
	
	
	/**
	 * 设置是否执行302跳转
	 * @param set
	 */
	@SuppressWarnings("static-access")
	public  void setFollowRedirects(boolean set) {
		this.con.setFollowRedirects(set);
	}
}
