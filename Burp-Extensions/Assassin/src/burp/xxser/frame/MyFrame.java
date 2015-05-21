/*
 * MyFrame.java
 *
 * Created on __DATE__, __TIME__
 */

package burp.xxser.frame;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import burp.IContextMenuInvocation;
import burp.xxser.bin.Browser;
import burp.xxser.bin.MyFile;
import burp.xxser.bin.NetHelper;
import burp.xxser.bin.Out;
import burp.xxser.bin.TreeUtil;
import burp.xxser.scan.Sidenote;
import burp.xxser.scan.Subdomain;

/**
 *
 * @author  __USER__
 */
public class MyFrame extends javax.swing.JFrame {

	private List<Thread> sub = new ArrayList<Thread>(); //子域名扫描线程集合
	private List<Thread> sid = new ArrayList<Thread>(); //旁注扫描线程集合，其实根本用不到
	private IContextMenuInvocation invocation = null; //Burp上下文

	private SubShow s = null;

	/** Creates new form MyFrame */
	public MyFrame() {
		initComponents();
	}

	public MyFrame(IContextMenuInvocation invocation) {
		this.invocation = invocation;
		initComponents();
		this.txt_url.setText(this.invocation.getSelectedMessages()[0]
				.getHttpService().getHost());
		this.lbl_subdomain.setText(this.invocation.getSelectedMessages()[0]
				.getHttpService().getHost());
		
	}

	//GEN-BEGIN:initComponents
	// <editor-fold defaultstate="collapsed" desc="Generated Code">
	private void initComponents() {

		tabPane = new javax.swing.JTabbedPane();
		sidenode = new javax.swing.JPanel();
		sideTop = new javax.swing.JPanel();
		lbl_domain = new javax.swing.JLabel();
		txt_url = new javax.swing.JTextField();
		btn_SidQuery = new javax.swing.JButton();
		sideFooter = new javax.swing.JPanel();
		treeScroll = new javax.swing.JScrollPane();
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("root");
		DefaultTreeModel  model = new DefaultTreeModel(root);
		tree = new javax.swing.JTree(model);
		tree.setRootVisible(false);
		sidStatus = new javax.swing.JPanel();
		lbl_sid_status_show = new javax.swing.JLabel();
		lbl_sid_status = new javax.swing.JLabel();
		subdomain = new javax.swing.JPanel();
		subTop = new javax.swing.JPanel();
		lbl_subdomain_show = new javax.swing.JLabel();
		lbl_subdomain = new javax.swing.JTextField();
		lbl_subquery = new javax.swing.JButton();
		btn_substop = new javax.swing.JButton();
		scroll_table = new javax.swing.JScrollPane();
		tab_sub = new javax.swing.JTable();
		subFooter = new javax.swing.JPanel();
		lbl_sub_url_show = new javax.swing.JLabel();
		lbl_sub_url = new javax.swing.JLabel();
		lbl_sub_status_show = new javax.swing.JLabel();
		lbl_sub_status = new javax.swing.JLabel();
		lbl_sub_count = new javax.swing.JLabel();
		lbl_sub_count_show = new javax.swing.JLabel();
		option = new javax.swing.JPanel();
		optionTop = new javax.swing.JPanel();
		lbl_key = new javax.swing.JLabel();
		txt_key = new javax.swing.JTextField();
		btn_key = new javax.swing.JButton();
		alert = new javax.swing.JPanel();
		scroll_alert = new javax.swing.JScrollPane();
		txt_area = new javax.swing.JTextArea();

		
		setTitle("Assassin Beta  V1.0");
		setMinimumSize(new java.awt.Dimension(560, 580));
		
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

		sidenode.setLayout(new java.awt.BorderLayout());

		lbl_domain.setText("Domain\uff1a");
		sideTop.add(lbl_domain);

		txt_url.setColumns(20);
		sideTop.add(txt_url);

		btn_SidQuery.setText("Query");
		btn_SidQuery.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				btn_queryMouseClicked(evt);
			}
		});
		sideTop.add(btn_SidQuery);

		sidenode.add(sideTop, java.awt.BorderLayout.PAGE_START);

		sideFooter.setLayout(new java.awt.BorderLayout());

		tree.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				treeMouseClicked(evt);
			}
		});
		treeScroll.setViewportView(tree);

		sideFooter.add(treeScroll, java.awt.BorderLayout.CENTER);

		sidStatus.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		lbl_sid_status_show.setText("Status\uff1a");
		sidStatus
				.add(lbl_sid_status_show,
						new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0,
								-1, -1));

		lbl_sid_status.setText("  ");
		sidStatus.add(lbl_sid_status,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(48, 0, 190,
						-1));

		sideFooter.add(sidStatus, java.awt.BorderLayout.PAGE_END);

		sidenode.add(sideFooter, java.awt.BorderLayout.CENTER);

		tabPane.addTab("Sidenode", sidenode);

		subdomain.setLayout(new java.awt.BorderLayout());

		lbl_subdomain_show.setText("Domain\uff1a");
		subTop.add(lbl_subdomain_show);

		lbl_subdomain.setColumns(20);
		subTop.add(lbl_subdomain);

		lbl_subquery.setText("Query");
		lbl_subquery.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				lbl_subqueryMouseClicked(evt);
			}
		});
		subTop.add(lbl_subquery);

		btn_substop.setText("Stop");
		btn_substop.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				btn_substopMouseClicked(evt);
			}
		});
		subTop.add(btn_substop);

		subdomain.add(subTop, java.awt.BorderLayout.PAGE_START);

		tab_sub.setModel(new javax.swing.table.DefaultTableModel(
				new Object[][] { 
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null } ,
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null } ,
						{ null, null, null, null },
						{ null, null, null, null }, 
						{ null, null, null, null },
						{ null, null, null, null },
						{ null, null, null, null } 
						
						}, new String[] { "id","Domain",
						"IpAddress", "Code", "Server","CDN" }));
		scroll_table.setViewportView(tab_sub);

		subdomain.add(scroll_table, java.awt.BorderLayout.CENTER);

		subFooter.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

		lbl_sub_url_show.setText("Scanner\uff1a");
		subFooter
				.add(lbl_sub_url_show,
						new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0,
								-1, 20));
		subFooter.add(lbl_sub_url,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 0, 180,
						20));

		lbl_sub_status_show.setText("Status\uff1a");
		subFooter.add(lbl_sub_status_show,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 0, 50,
						20));

		lbl_sub_status.setText("0");
		subFooter.add(lbl_sub_status,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(440, 0, 100,
						20));

		lbl_sub_count.setText("0");
		subFooter.add(lbl_sub_count,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(300, 0, 40,
						20));

		lbl_sub_count_show.setText("Count\uff1a");
		subFooter.add(lbl_sub_count_show,
				new org.netbeans.lib.awtextra.AbsoluteConstraints(250, 0, 50,
						20));

		subdomain.add(subFooter, java.awt.BorderLayout.PAGE_END);

		tabPane.addTab("Subdomain", subdomain);

		option.setLayout(new java.awt.BorderLayout());

		lbl_key.setText("Key\uff1a");
		optionTop.add(lbl_key);

		txt_key.setColumns(30);
		optionTop.add(txt_key);

		btn_key.setText("Set Key");
		btn_key.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseClicked(java.awt.event.MouseEvent evt) {
				btn_keyMouseClicked(evt);
			}
		});
		optionTop.add(btn_key);

		option.add(optionTop, java.awt.BorderLayout.PAGE_START);

		tabPane.addTab("Option", option);

		alert.setLayout(new java.awt.BorderLayout());

		txt_area.setColumns(20);
		txt_area.setRows(5);
		txt_area
				.setText("\nBurp\u63d2\u4ef6\u7f16\u5199\uff0c\u4ea4\u6d41\u7fa4\u53f7\uff1a\n\n                            271349669   \u7c73\u5b89\u7f51\u63d0\u4f9b\n\n");
		scroll_alert.setViewportView(txt_area);

		alert.add(scroll_alert, java.awt.BorderLayout.CENTER);

		tabPane.addTab("Alert", alert);

		getContentPane().add(tabPane, java.awt.BorderLayout.CENTER);
		this.setLocationRelativeTo(null);
		this.txt_key.setText(this.getKey());
		pack();
	}// </editor-fold>
	//GEN-END:initComponents

	private void btn_substopMouseClicked(java.awt.event.MouseEvent evt) {
		String temp = this.btn_substop.getText();
		if (temp.equals("Stop")) {
			for (Thread t : this.sub) {
				Subdomain s = (Subdomain) t;
				s.setFlag(false);
			}
			this.btn_substop.setText("Continue");
		} else {
			for (Thread t : this.sub) {
				Subdomain s = (Subdomain) t;
				s.setFlag(true);
			}
			this.btn_substop.setText("Stop");
		}

	}

	/**
	 * 子域名按钮点击事件
	 */
	private void lbl_subqueryMouseClicked(java.awt.event.MouseEvent evt) {

		this.btn_substop.setText("Stop");
		for (Thread t : this.sub) { //销毁线程
			Subdomain s = (Subdomain) t;
			s.destroy();
		}

		if (this.s != null) { //销毁显示线程
			this.s.destroy();
		}

		DefaultTableModel tableModel = (DefaultTableModel) this.tab_sub
				.getModel();
		tableModel.setRowCount(0); //清空所有的表格
		String url = this.lbl_subdomain.getText();

		try {
			InputStream  in =  this.getClass().getResourceAsStream("/dic");
			HashSet<String> dic = new HashSet<String>(MyFile.readToList(in)); //读取字典列表
			int size = dic.size(); //获取字典总数

			
			String a[] = NetHelper.getIpAddress("xxse" + "." + url); //排除运营商的那个IP
			String b[] = NetHelper.getIpAddress("jea" + "." + url); //排除运营商的那个IP
			String c[] = NetHelper.getIpAddress("jee" + "." + url); //排除运营商的那个IP
			String d[] = NetHelper.getIpAddress("jea" + "." + url); //排除运营商的那个IP
			String e[] = NetHelper.getIpAddress("jea" + "." + url); //排除运营商的那个IP
			String f[] = NetHelper.getIpAddress("ioioio" + "." + url); //排除运营商的那个IP
			String noip[] ={ 
					(a != null ? a[0] : null),
					(b != null ? b[0] : null),
					(c != null ? c[0] : null),
					(d != null ? d[0] : null),
					(e != null ? e[0] : null),
					(f != null ? f[0] : null)
			};

			
			for (int i = 0; i < noip.length; i++) {
				Out.println("过滤IP--->"+noip[i]);
			}
			
			for (int i = 0; i < 15; i++) {
				Subdomain domain = new Subdomain(dic, url, this.tab_sub,
						this.lbl_sub_url, this.lbl_sub_count, noip);
				domain.start();
				this.sub.add(domain);
			}

			//状态显示
			this.s = new SubShow(this.lbl_sub_status, size, dic);
			this.s.start();
		} catch (Exception e) {
			Out.println(e.toString());
		}
		

	}

	/**
	 * 增加Key
	 * @param evt
	 */
	private void btn_keyMouseClicked(java.awt.event.MouseEvent evt) {

		String key = this.txt_key.getText();
		if (key == null || "".equals(key)) {
			JOptionPane.showMessageDialog(null, "  input Key ...",
					"Prompt information", JOptionPane.ERROR_MESSAGE);
		}
		MyFile.write(System.getProperty("user.dir") + "/key.bin", key);
		JOptionPane.showMessageDialog(null, "  Ok ...", "Prompt information",
				JOptionPane.INFORMATION_MESSAGE);

	}


	/**
	 * 打开网址模块
	 * @param evt
	 */
	private void treeMouseClicked(java.awt.event.MouseEvent evt) {

		if (evt.getClickCount() == 2) {
			if (this.tree.getSelectionPath() == null) {
				return;
			}

			DefaultMutableTreeNode node = (DefaultMutableTreeNode) this.tree
					.getSelectionPath().getLastPathComponent();
			if (node == null) {
				return;
			}
			String[] temp = node.toString().split("--->"); //截取URL
			if (temp.length != 2) {
				return;
			}
			Browser.start(temp[0]); //启动浏览器

		}

	}

	/**
	 * 旁注查询模块
	 * @param evt
	 */
	private void btn_queryMouseClicked(java.awt.event.MouseEvent evt) {
		new Thread(new Runnable() {
			
			@Override
			public void run() {

				
				lbl_sid_status.setText("Query Start,Please later...");
				
				TreeUtil.removeAll(tree);
				String name = txt_url.getText();
				HashSet<String> set = new HashSet<String>();

				String temp[] = NetHelper.getIpAddress(name);
				if (temp == null) {
					JOptionPane.showMessageDialog(null, "  Host Error ...",
							"Prompt information", JOptionPane.ERROR_MESSAGE);
					lbl_sid_status.setText("  ");
					return;
				}
				if (temp.length > 2) {
					JOptionPane.showMessageDialog(null, "CND:" + Out.arrToString(temp)
							+ " ...", "Prompt information", JOptionPane.ERROR_MESSAGE);
					lbl_sid_status.setText("  ");
					return;
				}
				set.add(temp[0]);

				try {

					Sidenote s = new Sidenote(set, tree);
					s.run();
					sid.add(s);
				} catch (Exception e) {
					lbl_sid_status.setText("  ");
					return  ;
				}

				
				//Map<JLabel, String> map = new HashMap<JLabel, String>(); //進行顯示信息
				//map.put(lbl_sid_status, "Query Ok!");
				//new JLabelShow(sid, map).run();
				lbl_sid_status.setText("Query Ok!");
				
				
			}
		}).start();
		
		
	}

	/**
	 * 获取微软Key
	 * @return
	 */
	public String getKey() {

		if (!new File(System.getProperty("user.dir") + "/key.bin").exists()) {
			return null;
		}
		return MyFile.readToList(System.getProperty("user.dir") + "/key.bin")
				.get(0);
	}

	/**
	 * @param args the command line arguments
	 */
	public static void main(String args[]) {
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new MyFrame().setVisible(true);
			}
		});
	}

	//GEN-BEGIN:variables
	// Variables declaration - do not modify
	private javax.swing.JPanel alert;
	private javax.swing.JButton btn_SidQuery;
	private javax.swing.JButton btn_key;
	private javax.swing.JButton btn_substop;
	private javax.swing.JLabel lbl_domain;
	private javax.swing.JLabel lbl_key;
	private javax.swing.JLabel lbl_sid_status;
	private javax.swing.JLabel lbl_sid_status_show;
	private javax.swing.JLabel lbl_sub_count;
	private javax.swing.JLabel lbl_sub_count_show;
	private javax.swing.JLabel lbl_sub_status;
	private javax.swing.JLabel lbl_sub_status_show;
	private javax.swing.JLabel lbl_sub_url;
	private javax.swing.JLabel lbl_sub_url_show;
	private javax.swing.JTextField lbl_subdomain;
	private javax.swing.JLabel lbl_subdomain_show;
	private javax.swing.JButton lbl_subquery;
	private javax.swing.JPanel option;
	private javax.swing.JPanel optionTop;
	private javax.swing.JScrollPane scroll_alert;
	private javax.swing.JScrollPane scroll_table;
	private javax.swing.JPanel sidStatus;
	private javax.swing.JPanel sideFooter;
	private javax.swing.JPanel sideTop;
	private javax.swing.JPanel sidenode;
	private javax.swing.JPanel subFooter;
	private javax.swing.JPanel subTop;
	private javax.swing.JPanel subdomain;
	private javax.swing.JTabbedPane tabPane;
	private javax.swing.JTable tab_sub;
	private javax.swing.JTree tree;
	private javax.swing.JScrollPane treeScroll;
	private javax.swing.JTextArea txt_area;
	private javax.swing.JTextField txt_key;
	private javax.swing.JTextField txt_url;
	// End of variables declaration//GEN-END:variables

}

/**
 * 子域名扫描显示类
 * @author Administrator
 *
 */
class SubShow extends Thread {

	private boolean flag = true;
	private JLabel j = null;
	private int osize;
	private String str = null;
	private HashSet<String> dic;

	public SubShow(JLabel j, int osize, HashSet<String> dic) {
		this.j = j;
		this.osize = osize;
		this.dic = dic;
	}

	@Override
	public void destroy() {
		this.flag = false;
	}

	@Override
	public void run() {

		while (dic.size() != 0 && flag) {
			this.str = (this.osize - dic.size()) + "/" + this.osize;
			this.j.setText(str);
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

	}

}

/**
 * 线程完毕后显示内容的类
 * @author Administrator
 *
 */
class JLabelShow implements Runnable {

	private Map<JLabel, String> map; //用来显示的类
	private List<Thread> thread; //线程列表

	public JLabelShow(List<Thread> thread, Map<JLabel, String> map) {
		this.thread = thread;
		this.map = map;
	}

	@Override
	public void run() {
		boolean flag = true;
		while (flag) {
			try {
				Thread.sleep(1);
			} catch (Exception e) {
				e.printStackTrace();
			}
			for (Thread t : thread) { //查看线程是否有运行状态
				if (t.getState() == Thread.State.RUNNABLE) {
					
					continue;
				} else {
					flag = false;
				}
			}
			if (!flag) {
				Set<JLabel> lbl = map.keySet();
				for (JLabel jLabel : lbl) {
					jLabel.setText(map.get(jLabel)); //设置内容
				}

				return;
			}
		}
	}
}