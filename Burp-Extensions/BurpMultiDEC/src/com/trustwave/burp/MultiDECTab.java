/*
 *	MultiDEC Tab - A helper class for the Burp MultiDEC plugin. Contains all the interface and conversion logic for a tab.
 *	Austin Lane<alane@trustwave.com>
 *	Copyright (C) 2013 Trustwave Holdings, Inc.
 *	
 *	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *	
 *	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package com.trustwave.burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.BoxLayout;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Dimension;
import javax.swing.JComboBox;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

import java.net.URLEncoder;
import java.net.URLDecoder;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

public class MultiDECTab implements ActionListener{

	public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout, errout;
    public IHttpRequestResponse[] messages;
    public byte selectedContext;
    public JPanel multiDECPanel;
    public JTextArea inputBox,outputBox;
    public JComboBox cbEncode, cbDecode;

    private String[] encodeOptions = {"Encode to...", "URL", "HTML", "ASCII Hex", "Base64", "Binary","Hex","Octal"};
    private String[] decodeOptions = {"Decode from...", "URL", "HTML", "ASCII Hex", "Base64", "Binary","Hex","Octal"};

	public MultiDECTab(IBurpExtenderCallbacks Callbacks, PrintWriter STDOUT, PrintWriter ERROUT){
    	this.callbacks = Callbacks;
    	this.helpers = callbacks.getHelpers();
    	this.stdout = STDOUT;
    	this.errout = ERROUT;

		//Container for request/response information in this SessionTestTab
		multiDECPanel = new JPanel();
    	multiDECPanel.setLayout(new BoxLayout(multiDECPanel, BoxLayout.Y_AXIS));

		JLabel lblInput = new JLabel("Input");
    	JPanel inputPanel = new JPanel();
    	inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

		inputBox = new JTextArea(5,30);
		inputBox.setLineWrap(true);

		JScrollPane scrollInputBox = new JScrollPane(inputBox);
		scrollInputBox.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollInputBox.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		inputPanel.add(scrollInputBox);

    	JPanel controlGroupPanel = new JPanel();
    	//controlGroupPanel.setLayout(new BoxLayout(controlGroupPanel, BoxLayout.X_AXIS));

    	cbEncode = new JComboBox(encodeOptions);
    	//cbEncode.setPreferredSize(new Dimension(200,50));
    	cbEncode.setActionCommand("ENCODE");
    	cbEncode.addActionListener(MultiDECTab.this);
    	controlGroupPanel.add(cbEncode);

    	cbDecode = new JComboBox(decodeOptions);
    	//cbDecode.setPreferredSize(new Dimension(200,50));
    	cbDecode.setActionCommand("DECODE");
    	cbDecode.addActionListener(MultiDECTab.this);
    	controlGroupPanel.add(cbDecode);


		JLabel lblOutput = new JLabel("Output");
    	JPanel outputPanel = new JPanel();
    	outputPanel.setLayout(new BoxLayout(outputPanel, BoxLayout.X_AXIS));

		outputBox = new JTextArea(5,30);
		outputBox.setLineWrap(true);

		JScrollPane scrollOutputBox = new JScrollPane(outputBox);
		scrollOutputBox.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollOutputBox.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

		outputPanel.add(scrollOutputBox);

		multiDECPanel.add(lblInput);
		multiDECPanel.add(inputPanel);
    	multiDECPanel.add(controlGroupPanel);
		multiDECPanel.add(lblOutput);
		multiDECPanel.add(outputPanel);
	}


	@Override
	public void actionPerformed(ActionEvent e) {
		String cmd = e.getActionCommand();
		if(cmd.equals("ENCODE")){
			if(cbEncode.getSelectedIndex() > 0){
				String output = "";
				switch(cbEncode.getSelectedIndex()){
					case 1: output = ConvertToURL(helpers.stringToBytes(inputBox.getText()));
					break;
					case 2: output = ConvertToHTML(helpers.stringToBytes(inputBox.getText()));
					break;
					case 3: output = ConvertToASCII(helpers.stringToBytes(inputBox.getText()));
					break;
					case 4: output = ConvertToBase64(helpers.stringToBytes(inputBox.getText()));
					break;
					case 5: output = ConvertToBin(inputBox.getText());
					break;
					case 6: output = ConvertToHex(inputBox.getText());
					break;
					case 7: output = ConvertToOct(inputBox.getText());
					break;
					default: break;
				}
				cbEncode.setSelectedIndex(0);
				outputBox.setText(output);
			}
		}
		if(cmd.equals("DECODE")){
			if(cbDecode.getSelectedIndex() > 0){
				String output = "";
				switch(cbDecode.getSelectedIndex()){
					case 1: output = ConvertFromURL(inputBox.getText());
					break;
					case 2: output = ConvertFromHTML(inputBox.getText());
					break;
					case 3: output = ConvertFromASCII(inputBox.getText());
					break;
					case 4: output = ConvertFromBase64(inputBox.getText());
					break;
					case 5: output = ConvertFromBin(inputBox.getText());
					break;
					case 6: output = ConvertFromHex(inputBox.getText());
					break;
					case 7: output = ConvertFromOct(inputBox.getText());
					break;
					default: break;
				}
				cbDecode.setSelectedIndex(0);
				outputBox.setText(output);
			}
		}
		
	}

	public String ConvertToHTML(byte[] original){
		StringBuilder str = new StringBuilder();
		try{
	    for(int i = 0; i < original.length; i++)
	        str.append("&#x" + String.format("%02x", original[i]) + ";");
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertToURL(byte[] original){
		StringBuilder str = new StringBuilder();
		try{
	    for(int i = 0; i < original.length; i++)
	        str.append("%" + String.format("%02x", original[i]));
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertToASCII(byte[] original){
		StringBuilder str = new StringBuilder();
		try{
	    for(int i = 0; i < original.length; i++)
	        str.append(String.format("%02x", original[i]));
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertToBase64(byte[] original){
		String str = "";
		try{
			str = helpers.base64Encode(original);
		} catch(Exception e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertToBin(String original){
		String str = "";
		try{
			str = Integer.toBinaryString(Integer.parseInt(original));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertToHex(String original){
		String str = "";
		try{
			str = Integer.toHexString(Integer.parseInt(original));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertToOct(String original){
		String str = "";
		try{
			str = Integer.toOctalString(Integer.parseInt(original));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertFromHTML(String original){
		StringBuilder str = new StringBuilder();
		try{
			String stripped = original.replace("&#x", "").replace(";","");
		    for (int i = 0; i < stripped.length(); i+=2) {
		        str.append((char) Integer.parseInt(stripped.substring(i, i + 2), 16));
		    }
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertFromURL(String original){
		StringBuilder str = new StringBuilder();
		try{
			String stripped = original.replace("%","");
		    for (int i = 0; i < stripped.length(); i+=2) {
		        str.append((char) Integer.parseInt(stripped.substring(i, i + 2), 16));
		    }
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertFromASCII(String original){
		StringBuilder str = new StringBuilder();
		try{
		    for (int i = 0; i < original.length(); i+=2) {
		        str.append((char) Integer.parseInt(original.substring(i, i + 2), 16));
		    }
		} catch(Exception e){ errout.println(e.getMessage()); }
	    return str.toString();
	}

	public String ConvertFromBase64(String original){
		String str = "";
		try{
			str = helpers.bytesToString(helpers.base64Decode(original));
		} catch(Exception e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertFromBin(String original){
		String str = "";
		try{
			str = Integer.toString(Integer.parseInt(original,2));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertFromHex(String original){
		String str = "";
		try{
			str = Integer.toString(Integer.parseInt(original,16));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}

	public String ConvertFromOct(String original){
		String str = "";
		try{
			str = Integer.toString(Integer.parseInt(original,8));
		} catch(NumberFormatException e){ errout.println(e.getMessage()); }
		return str;
	}
}