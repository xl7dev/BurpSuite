package com.wuntee.burp.authz;

import java.awt.Component;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.ITextEditor;

public class BurpTextEditorWithData implements ITextEditor {
	private IBurpExtenderCallbacks burpCallback;
	private ITextEditor textEditor;
	private Map<String, Object> data;
	
	public BurpTextEditorWithData(IBurpExtenderCallbacks burpCallback){
		this.burpCallback = burpCallback;
		this.textEditor = burpCallback.createTextEditor();
		this.data = new HashMap<String, Object>();
	}
	
	public void putData(String key, Object value){
		data.put(key, value);
	}
	
	public void removeData(String key){
		data.remove(key);
	}
	
	public Object getData(String key){
		return(data.get(key));
	}

	public Component getComponent() {
		return this.textEditor.getComponent();
	}

	public void setEditable(boolean editable) {
		this.textEditor.setEditable(editable);
	}

	public void setText(byte[] text) {
		this.textEditor.setText(text);

	}

	public byte[] getText() {
		return(this.textEditor.getText());
	}

	public boolean isTextModified() {
		return(this.textEditor.isTextModified());
	}

	public byte[] getSelectedText() {
		return(this.textEditor.getSelectedText());
	}

	public int[] getSelectionBounds() {
		return(this.textEditor.getSelectionBounds());
	}

	public void setSearchExpression(String expression) {
		this.textEditor.setSearchExpression(expression);
	}
	
}
