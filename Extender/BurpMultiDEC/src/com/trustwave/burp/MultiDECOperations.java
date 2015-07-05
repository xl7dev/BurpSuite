/*
 *	Session Tester Operations - A helper class for the Burp MultiDEC plugin. Manages the tabs for the plugin.
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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JMenuItem;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import com.sun.tools.javac.resources.javac;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

public class MultiDECOperations{
	//PROPERTIES
	public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout, errout;
    public IHttpRequestResponse[] messages;
    public byte selectedContext;
    public List<MultiDECTab> decTabs;
    public JTabbedPane tabbedPane;

    //KEYWORDS
    //Constructor
    /**
     * Creates a NotesExtensionOperations object, used for performing operations and managing data with the Burp Notes Extension.
     * @param Callbacks The IBurpExtenderCallbacks object provided by the BurpExtender class creating this object.
     */
    public MultiDECOperations(IBurpExtenderCallbacks CALLBACKS){
    	callbacks = CALLBACKS;
    	helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        errout = new PrintWriter(callbacks.getStderr(), true);

    	decTabs = new ArrayList<MultiDECTab>();
    	tabbedPane = new JTabbedPane();
    	MultiDECTab testTab = new MultiDECTab(callbacks, this.stdout, this.errout);
    	decTabs.add(testTab);
    	tabbedPane.add("1", testTab.multiDECPanel);
		tabbedPane.setTabComponentAt(tabbedPane.getTabCount() - 1, new ButtonTabComponent(tabbedPane));

		JButton btnAdd = new JButton("...");
		ActionListener al;
	    al = new ActionListener() {
	      public void actionPerformed(ActionEvent ae) {
	        AddTab();
	      }
	    };
	    btnAdd.addActionListener(al);

	    tabbedPane.add("Add", new JPanel());
		tabbedPane.setTabComponentAt(tabbedPane.getTabCount() - 1, btnAdd);


    }

    public MultiDECTab AddTab(){
		MultiDECTab newTestTab = new MultiDECTab(callbacks, stdout, errout);
    	decTabs.add(newTestTab);
    	int tabCount = tabbedPane.getTabCount();
    	tabbedPane.insertTab(String.valueOf(tabbedPane.getTabCount()), null, newTestTab.multiDECPanel, "", tabCount - 1);
		tabbedPane.setTabComponentAt(tabCount - 1, new ButtonTabComponent(tabbedPane));

		return newTestTab;
    }

	/**
	 * Interpret the command sent by the BurpExtension's ActionListener
	 * @param cmd The command string sent by the ActionListener.
	 */
	public void ParseAction(String cmd){

	}
}