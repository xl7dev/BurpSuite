/*
 *	Burp Multi Decoder/Encoder Extension - A plugin for Burp Suite that adds a tabbed encoder/decoder window.
 *	Austin Lane<alane@trustwave.com>
 *	Copyright (C) 2013 Trustwave Holdings, Inc.
 *	
 *	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *	
 *	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import com.trustwave.burp.MultiDECOperations;

import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionStateListener;
import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab, ActionListener, IExtensionStateListener
{
	private MultiDECOperations ops;
	
	public final String TAB_NAME = "MultiDEC";
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks Callbacks)
    {
    	//Set up our extension operations
    	this.ops = new MultiDECOperations(Callbacks);
        
        //name our extension
        ops.callbacks.setExtensionName("Burp MultiDEC");

        // register ourselves as an extension state listener
        ops.callbacks.registerExtensionStateListener(this);
        
        SwingUtilities.invokeLater(new Runnable(){
        	@Override
        	public void run(){
        		ops.callbacks.customizeUiComponent(ops.tabbedPane);
                ops.callbacks.addSuiteTab(BurpExtender.this);
        	}
        });
        
    }

	@Override
	public String getTabCaption() {
		return TAB_NAME;
	}

	@Override
	public Component getUiComponent() {
		return ops.tabbedPane;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String cmd = e.getActionCommand();
		ops.ParseAction(cmd);
		
	}

	@Override
	public void extensionUnloaded() {
        ops.stdout.println("Extension was unloaded");
	}
}

