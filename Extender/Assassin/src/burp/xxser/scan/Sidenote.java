package burp.xxser.scan;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.JOptionPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import Decoder.BASE64Encoder;
import burp.xxser.bin.Request;
import burp.xxser.bin.Response;
import burp.xxser.frame.MyFrame;

public class Sidenote extends Thread {
	private HashSet<String> targetIPSet = null;

	private String targetIP = "";

	private JTree tree = null;

	private Set<String> host = new HashSet<String>(); // 为过滤重复而使用，没有其他作用
	private List<String> hostList = new ArrayList<String>();

	public Sidenote(HashSet<String> targetIPSet) {
		this.targetIPSet = targetIPSet;
	}

	public Sidenote(HashSet<String> targetIPSet, JTree tree) {
		this.targetIPSet = targetIPSet;
		this.tree = tree;

	}

	@Override
	public void run() {
		while (targetIPSet.size() != 0) {
			synchronized (targetIPSet) {
				// 获取目标IP并且锁住资源
				targetIP = targetIPSet.iterator().next();
				targetIPSet.remove(targetIP);
			}
			String json = this.getHtml(targetIP); // 获取所有数据
			if(json==null){
				return ;
			}
			// Tree操作
			DefaultMutableTreeNode node = new DefaultMutableTreeNode(targetIP);
			DefaultTreeModel model = (DefaultTreeModel) tree.getModel();

			strAnalysis(json);   //递归处理数据
			
			this.toRepeat(node);  //增加TreeNode数据
			
			model.insertNodeInto(node,
					(DefaultMutableTreeNode) model.getRoot(), 0);
			this.tree.setModel(model);
			this.tree.updateUI();
		}

	}

	/**
	 * 获取微软返回的旁注JSON数据
	 * 
	 * @param targetIP
	 * @return
	 */
	public String getHtml(String targetIP) {

		Request r = new Request(
				"https://api.datamarket.azure.com/Bing/Search/Web?Query=%27ip:"
						+ targetIP + "%27&$format=json");
		
		String k = new MyFrame().getKey();
		if(k==null|| "null".equals(k)){
			JOptionPane.showMessageDialog(null, "Please input the key !", "Prompt information",
					JOptionPane.ERROR_MESSAGE);
			return  null;
		}
		r.getCon().setReadTimeout(2500);
		String key = "%00:" + new MyFrame().getKey();
		String code = new BASE64Encoder().encode(key.getBytes());
		r.setHeader("Authorization", "Basic " + code);
		
		Response p=null;
		try {
			p = r.getResponse();
		} catch (IOException e) {
			JOptionPane.showMessageDialog(null, "Read Time out !", "Prompt information",
					JOptionPane.ERROR_MESSAGE);
			return null ;
		}

		// 判断查询条数是否已用完
		if (p.getResponseCode() == 503 || p.getResponseCode() == 401) {
			JOptionPane.showMessageDialog(null, "查询条数已用完", "提示信息",
					JOptionPane.ERROR_MESSAGE);
			targetIPSet.clear();
			return  null;
		}

		return p.getBody("GBK"); // 获取JSON数据
	}

	/**
	 * 递归方法，进行提取字符串里的 Url 和 title 信息
	 * 
	 * @param json
	 * @param node
	 */
	public void strAnalysis(String json) {
		int titleStart = json.indexOf("Title\"") + 8;
		if (titleStart < 8) {
			return;
		}
		json = json.substring(titleStart);
		int titlEnd = json.indexOf("\"");
		int urlStart = json.indexOf("\"Url\":\"") + 7;
		int urlEnd = json.indexOf("\"}", urlStart);
		String title = json.substring(0, titlEnd);
		String url = json.substring(urlStart, urlEnd);

		// 过滤URL 和 Title

		url = url.substring(0, url.indexOf("/", 8)); // 转换成 http://***.com 或者
														// http://***.com/
		if (title.length() > 12) {
			title = title.substring(0, 12);
		}
		this.hostList.add(url + "_" + title);
		strAnalysis(json);
	}

	/**
	 * 对网址进行去重复的操作
	 */
	public void toRepeat(DefaultMutableTreeNode node) {
		for (String temp : hostList) {
			this.host.add(temp.split("_")[0]); // 过滤重复URL
		}

		for (String url : host) {    //整理对应URL 及　Title
			
			for (String temp : hostList) {
				if (temp.startsWith(url)) {
					node.add(new DefaultMutableTreeNode(url + "\t--->\t"
							+ temp.split("_")[1]));
				}
			}
		}
	}

}
