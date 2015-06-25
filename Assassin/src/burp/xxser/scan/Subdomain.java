package burp.xxser.scan;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import burp.xxser.bin.NetHelper;
import burp.xxser.bin.Out;
import burp.xxser.bin.Request;
import burp.xxser.bin.Response;

public class Subdomain extends Thread {

	private boolean flag = true; // 进行销毁线程来用
	private boolean destroy = true;
	public boolean getFlag() {
		return flag;
	}

	public void setFlag(boolean flag) {
		this.flag = flag;
	}

	private HashSet<String> dic; // 字典
	private String url; // 原始域名
	private String pentestUrl; // 组建的域名 xx.moonsos.com
	private JTable table;
	private JLabel lbl_scan;
	private JLabel lbl_count;
	private String noip[]; // 要过滤的IP,一般实在过滤运营商的

	public Subdomain(HashSet<String> dic, String url, JTable table,
			JLabel lbl_scan, JLabel lbl_count, String noip[]) {
		this.table = table;
		this.dic = dic;
		this.url = url;
		this.lbl_scan = lbl_scan;
		this.noip = noip;
		this.lbl_count = lbl_count;
	}

	public void destroy() {
		this.flag = false;
		this.destroy = false ;
	}
	
	@Override
	public void run() {
		
		
		while (this.destroy) {
			
			
				while ((dic.size() != 0) && flag) {
				synchronized (dic) {
					String head = dic.iterator().next();
					this.pentestUrl = head + "." + this.url;
					dic.remove(head);
				
				}
				this.scan();
			}
			
			try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		
		/*
		
			while ((dic.size() != 0) && !flag) {
				synchronized (dic) {
				String head = dic.iterator().next();
				this.pentestUrl = head + "." + this.url;
				dic.remove(head);
				this.scan();
				
			}
			*/
			
		}
		
	}

	public void scan() {
		// domain ip cdn server
		String domain = null, ip = null, cdn = null, server = null;

		Request resquest = new Request("http://" + this.pentestUrl);
		resquest.getCon().setReadTimeout(1000);
		System.out.println("Scanner--->  http://"+this.pentestUrl);
		resquest.setMethod("GET");
		resquest.setFollowRedirects(true);
		Response response=null;
		try {
			response = resquest.getResponse();
		} catch (IOException e) {
			return ;
		}
		lbl_scan.setText(pentestUrl);
		lbl_count.setText(String.valueOf(table.getRowCount()));

		int code = response.getResponseCode();

		domain = this.pentestUrl;
		server = response.getHeader("Server");

		String[] temp = NetHelper.getIpAddress(domain);
		domain = this.pentestUrl;
		if (temp == null ) {
			return;
		}
		
		if (temp.length == 1) {
			ip = temp[0];
			for (String string : this.noip) {
				if(ip.equals(string)){
					return ;
				}
			}
			cdn = "NO CDN";
		} else {
			ip = temp[0];
			cdn = Out.arrToString(temp);
		}

		this.updateUI(String.valueOf(this.table.getRowCount()+1),domain, ip, String.valueOf(code), server,cdn); // 更新Jtable
	}

	
	
	
	
	public void updateUI(String id ,String domain, String ip, String code, String server, String cdn) {
		DefaultTableModel model = (DefaultTableModel) this.table.getModel();
		model.addRow(new Object[] { id,domain, ip, code, server ,cdn});
	}

}
