package com.wuntee.burp.authz;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITextEditor;

public class TabbedHttpEditor extends Container {

	private static final long serialVersionUID = 1L;

	private IBurpExtenderCallbacks burpCallback;
	private ITextEditor textEditor;
	
	private DefaultTableModel paramsTableModel;
	private String[] PARAMS_HEADERS = {"Type", "Name", "Value"};
	private DefaultTableModel headersTableModel;
	private String[] HEADERS_HEADERS = {"Name", "Value"};
	
	private IHttpRequestResponse requestResponse;
		
	public TabbedHttpEditor(IBurpExtenderCallbacks burpCallback){
		this.burpCallback = burpCallback;
		
		setLayout(new GridLayout(0, 1, 0, 0));

		textEditor = burpCallback.createTextEditor();
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		addRightClickActions(textEditor.getComponent());
		tabbedPane.addTab("Raw", null, new JScrollPane(textEditor.getComponent()), null);
		
		
		paramsTableModel = new DefaultTableModel(null, PARAMS_HEADERS);
		JTable table = new JTable(paramsTableModel){
		    @Override
		    public Dimension getPreferredScrollableViewportSize() {
		        Dimension dim = super.getPreferredScrollableViewportSize();
		        // here we return the pref height
		        dim.height = getPreferredSize().height-150;
		        return dim;
		    }
		};
		table.setAutoscrolls(true);
		table.setAutoCreateRowSorter(true);
		table.setFillsViewportHeight(true);
		addRightClickActions(table);
		tabbedPane.addTab("Params", null, new JScrollPane(table), null);
		
		headersTableModel = new DefaultTableModel(null, HEADERS_HEADERS);
		JTable table2 = new JTable(headersTableModel){
		    @Override
		    public Dimension getPreferredScrollableViewportSize() {
		        Dimension dim = super.getPreferredScrollableViewportSize();
		        // here we return the pref height
		        dim.height = getPreferredSize().height-150;
		        return dim;
		    }
		};
		table2.setFillsViewportHeight(true);
		addRightClickActions(table2);
		table2.setAutoCreateRowSorter(true);
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setViewportView(table2);
		scrollPane.setAutoscrolls(false);
		tabbedPane.addTab("Headers", null, scrollPane, null);
		
	}
	
	public void loadRequest(IHttpRequestResponse request){
		this.requestResponse = request;
		
		IRequestInfo req = burpCallback.getHelpers().analyzeRequest(request);
		
		loadData(request.getRequest(), req.getParameters(), req.getHeaders());
	}
	
	public void loadResponse(IHttpRequestResponse response){
		this.requestResponse = response;
		
		IResponseInfo req = burpCallback.getHelpers().analyzeResponse(response.getResponse());
		 
		loadData(response.getResponse(), new LinkedList<IParameter>(), req.getHeaders());
	}
	
	private void loadData(byte[] data, List<IParameter> params, List<String> headers){
		textEditor.setText(data);
		
		paramsTableModel.getDataVector().removeAllElements();
		for(IParameter param : params){
			String type = BurpApiHelper.iParameterTypeToString(param);
			String name = "";
			if(param.getName() != null){
				name = param.getName();
			}
			String value = "";
			if(param.getValue() != null){
				value = param.getValue();
			}
			paramsTableModel.addRow(new String[]{type, name, value});
		}
		
		headersTableModel.getDataVector().removeAllElements();
		if(headers.size() > 1){
			for(int i=1; i< headers.size(); i++){
				String header = headers.get(i);
				String h[] = header.split(":", 2);
				String key = "";
				if(h.length >= 1){
					key = h[0].trim();
				}
				String val = "";
				if(h.length >= 2){
					val = h[1].trim();
				}
				headersTableModel.addRow(new String[]{key, val});
			}
		}
	}
	
	public void clearData(){
		this.requestResponse = null;
		paramsTableModel.getDataVector().removeAllElements();
		headersTableModel.getDataVector().removeAllElements();
		textEditor.setText(new byte[]{});
	}
	
	public ITextEditor getTextEditor(){
		return(this.textEditor);
	}

	private static void addPopup(Component component, final JPopupMenu popup) {
		component.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			private void showMenu(MouseEvent e) {
				popup.show(e.getComponent(), e.getX(), e.getY());
			}
		});
	}
	
	private void addRightClickActions(Component comp){
		JPopupMenu popupMenu = new JPopupMenu();
		
		JMenuItem mntmSendToRepeater = new JMenuItem("Send to repeater");
		mntmSendToRepeater.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
		    	   IHttpRequestResponse req = requestResponse;
		    	   if(req != null){
		    		   BurpApiHelper.sendRequestResponseToRepeater(burpCallback, req);
		    	   }				
			}
		});
		popupMenu.add(mntmSendToRepeater);
		JMenuItem mntmSendToIntruder = new JMenuItem("Send to intruder");
		mntmSendToIntruder.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
		    	   IHttpRequestResponse req = requestResponse;
		    	   if(req != null){
		    		   BurpApiHelper.sendRequestResponseToIntruder(burpCallback, req);
		    	   }				
			}
		});
		popupMenu.add(mntmSendToIntruder);
		addPopup(comp, popupMenu);
	}

}
