/*
 *	Notes Extension Operations - A helper class for the Burp Notes Extensions plugin. Manages all the notes and interprets user interactions on behalf of the plugin.
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
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;

public class NotesExtensionOperations{
	//PROPERTIES
	public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout, errout;
    public JPanel mainPanel, menuPanel;
    public JTabbedPane tabbedPane;
    public JComboBox tabList;
    public JButton btnAddText, btnAddSpreadsheet, btnImportText, btnImportSpreadsheet, btnLoadNotes, btnSaveNotes, btnSaveTabAsTemplate, btnRemoveTab;
    public HashMap<String,String> tabTypes;
    public IHttpRequestResponse[] messages;
    public byte selectedContext;
    public ArrayList<String[]> spreadsheetTemplateFile;
    public String textTemplateFile;
    public File currentNotesFile;

    //KEYWORDS
    public static final String COMMAND_ADD_TEXT = "addText";
    public static final String COMMAND_ADD_SPREADSHEET = "addSpreadsheet";
    public static final String COMMAND_IMPORT_TEXT = "importText";
    public static final String COMMAND_IMPORT_SPREADSHEET = "importSpreadsheet";
    public static final String COMMAND_LOAD_NOTES = "loadNotes";
    public static final String COMMAND_SAVE_NOTES = "saveNotes";
    public static final String COMMAND_ADD_NEW_TEXT = "newTextDoc";
    public static final String COMMAND_SAVE_TAB_AS_TEMPLATE = "saveTabAsTemplate";
    public static final String COMMAND_REMOVE_TAB = "removeTab";
    public static final int TEMPLATE_TEXT = 1;
    public static final int TEMPLATE_SPREADSHEET = 2;
    
    //Constructor
    /**
     * Creates a NotesExtensionOperations object, used for performing operations and managing data with the Burp Notes Extension.
     * @param Callbacks The IBurpExtenderCallbacks object provided by the BurpExtender class creating this object.
     */
    public NotesExtensionOperations(IBurpExtenderCallbacks Callbacks){
    	this.callbacks = Callbacks;
    	this.helpers = callbacks.getHelpers();
    }
    
	//FILE OPERATIONS
    /**
     * Prompt user to choose a file for saving or loading with a JFileChooser.
     * @param saveFile True - Show a Save Dialog. False - Show a Load Dialog.
     * @return The File chosen by the user.
     */
	public File GetFileFromDialog(boolean saveFile, String defaultName){
		JFileChooser fc = new JFileChooser();
		if(defaultName != "") fc.setSelectedFile(new File(defaultName));
		int returnVal;
		if(saveFile) returnVal = fc.showSaveDialog(tabbedPane);
		else returnVal = fc.showOpenDialog(tabbedPane);
		if(returnVal == JFileChooser.APPROVE_OPTION){
			//Save location chosen, open file and iterate through tabs to save data
			File f = fc.getSelectedFile();
			if(!saveFile) return f; //Not saving over file, so just return it
			
			try{
				if(f.exists()){
					f.delete();
				}
				f.createNewFile();
				
				return f;
			} catch(IOException exc){
				errout.println(exc.getMessage());
			}
		}
		return null;
	}
	
	/**
	 * Write out all open documents to a text file using OpenCSV.
	 * Each document begins and ends with TEXT/ENDTEXT or SPREADSHEET/ENDSPREADSHEET.
	 * The second line is the name of the document.
	 * Anything after that is the content of the document.
	 */
	public void SaveNotes(){
		stdout.println("Saving");
		ArrayList<String[]> data = GetNotesData();
		if(data.size() > 0) {
			File f;
			if((f = GetFileFromDialog(true, (currentNotesFile != null ? currentNotesFile.getPath() : "notes.txt"))) != null){
				currentNotesFile = f; //Remember the file location 
				try{
					//Create our various Writers
					FileWriter fw = new FileWriter(f);
					CSVWriter writer = new CSVWriter(fw);
					//Write out to file and close
					writer.writeAll(data);
					writer.close();
					fw.close();
				} catch(IOException exc){
					errout.println(exc.getMessage());
				} 
			}
		} else {
			//No notes could be found
		}
	}
	
	/**
	 * Prompt users to open a Notes Extension file, which will be used to populate documents
	 */
	public void LoadNotes(){
		//Now pick file to load
		File file;
		try {
			if((file = GetFileFromDialog(false, (currentNotesFile != null ? currentNotesFile.getPath() : ""))) != null){
				currentNotesFile = file; //Remember the file just opened for saving later
				ArrayList<String[]> spreadData = new ArrayList<String[]>();
				if(file.exists() && file.isFile() && file.canRead()){
						CSVReader reader = new CSVReader(new FileReader(file));
						String[] nextLine;
						while((nextLine = reader.readNext()) != null){
							spreadData.add(nextLine);
						}
						if(spreadData.size() > 0){
							SetNotesData(spreadData);
						}
						reader.close();
				}
			}
		} catch (IOException exc) {
			errout.println(exc.getMessage());
		}
	}
	
	//TAB OPERATIONS
	/**
	 * Builds an ArrayList based on the documents within the Notes tab. Used for saving data.
	 * @return An ArrayList of String[] used for saving to a file.
	 */
	public ArrayList<String[]> GetNotesData(){
		//ArrayList to store data we will write out
		ArrayList<String[]> allElements = new ArrayList<String[]>();

		for(int tab = 0; tab < tabbedPane.getTabCount(); tab++){ 
			String tabName = tabbedPane.getTitleAt(tab);
			//Check each tab name against our tab types list to determine how we will write it to the file
			if(tabTypes.get(tabName) == "TEXT"){
				//Text tab
				JTextArea textTab = (JTextArea) GetInnerComponent(tab);
				
				if(textTab != null){
					//Begin Block
					allElements.add(new String[]{"TEXT"});
					//Title
					allElements.add(new String[]{tabName});
					//Text
					allElements.add(new String[]{textTab.getText()});
					//End Block
					allElements.add(new String[]{"ENDTEXT"});
				}
				
			} else {
				//Spreadsheet tab
				JTable table = (JTable) GetInnerComponent(tab);
				
				if(table != null){
					//Begin Block
					allElements.add(new String[]{"SPREADSHEET"});
					//Title
					allElements.add(new String[]{tabName});
					//Data
					int numColumns = table.getColumnCount();
					String[] data = new String[numColumns];
					// Write cell data
					for(int i=0;i<table.getRowCount();i++)
					{
						data = new String[numColumns];
					    for(int j=0; j< table.getColumnCount();j++)
					    {
					    		data[j] = (String)table.getModel().getValueAt(i, j);
					    }
						allElements.add(data);
					}
					//End Block
					allElements.add(new String[]{"ENDSPREADSHEET"});
				}
			}
		}
		
		return allElements;
	}
	
	/**
	 * Will populate the Notes tab with any documents inside the ArrayList.
	 * @param data An ArrayList read from a saved Notes file.
	 */
	public void SetNotesData(ArrayList<String[]> data){
		//Various flags to determine how to process lines being read in
		boolean inText = false;
		boolean inSpreadsheet = false;
		boolean inTitle = false;
		//Iterate through the ArrayList read from the file, build out the tabs
		String current = "";
		String tabName = "";
		ArrayList<String[]> spreadData = new ArrayList<String[]>();
		for(int i = 0; i < data.size(); i++){
			String[] nextLine = data.get(i);
			for(int j = 0; j < nextLine.length; j++){
				if(nextLine[j].equals("TEXT")){
					//Start text object
					inText = true;
					inTitle = true;
					current = "";
				} else if(nextLine[j].equals("ENDTEXT")){
					//End of text object, create the new textArea and add the tab
					inText = false;
					AddTextTab(current, tabName);
				} else if(nextLine[j].equals("SPREADSHEET")){
					//Start spreadsheet object
					inSpreadsheet = true;
					inTitle = true;
					spreadData.clear();
				} else if(nextLine[j].equals("ENDSPREADSHEET")){
					//End of spreadsheet block. Take our ArrayList and fill out a table
					inSpreadsheet = false;
					AddSpreadsheetTab(spreadData, tabName);
				} else if(inText){
					//Inside the content of a text block
					if(inTitle){
						tabName = nextLine[j];
						inTitle = false;
					} else {
						current += nextLine[j];
					}
				} else if(inSpreadsheet){
					//Inside the content of a spreadsheet
					if(inTitle){
						tabName = nextLine[j];
						inTitle = false;
					} else {
						spreadData.add(nextLine);
						j = nextLine.length; //End this loop early, we are taking the whole line
					}
				}
			}
		}
	}
	
	/**
	 * Find the inner component of the TabbedPane->ScrollPane->Viewport->Component structure for the given index.
	 * Will need to be cast as a Text Area or Table depending on the tab.
	 * @param tabIndex The index of the Tabbed Pane from which to retrieve the component.
	 * @return The primary display component inside the given tab.
	 */
	public Component GetInnerComponent(int tabIndex){
		JScrollPane sp = (JScrollPane) tabbedPane.getComponentAt(tabIndex);
		if(sp != null && sp.getViewport() != null){
			Component c = sp.getViewport().getView();
			return c;
		}
		return null;
	}
	
	/**
	 * Add a blank text tab to the Tabbed Pane. Will prompt the user for a name.
	 */
	public void AddTextTab(boolean importFile){
		if(importFile) promptUseTemplate(TEMPLATE_TEXT);
		if(textTemplateFile != null) AddTextTab(textTemplateFile);
		else AddTextTab("");
	}
	
	/**
	 * Add a new text tab to the Tabbed pane with the given text. Will prompt the user for a name.
	 * @param text The text to display within the tab.
	 */
	public void AddTextTab(String text){
		//Prompt user to name the document
		String name = getTabName();
		AddTextTab(text, name);
	}
	
	/**
	 * Add a new text tab to the Tabbed Pane with the given text and name.
	 * @param text The text to display within the tab.
	 * @param name The name to appear on the tab.
	 */
	public void AddTextTab(String text, String name){
		// TODO Prompt user for new document or import an existing one
		//Create a JTextArea for displaying plain text
		JTextArea newText = new JTextArea(5,30);
		newText.setText(text);
		//Clear template for next file if it was used
		textTemplateFile = null;
		//Set it in a scroll pane
		JScrollPane scrollWindow = new JScrollPane(newText);
		scrollWindow.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollWindow.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		scrollWindow.setPreferredSize(tabbedPane.getSize());
		//Resize it to fit the tabbed pane
		newText.setBounds(tabbedPane.getBounds());
		//Mark the tab as a TEXT tab
		tabTypes.put(name, "TEXT");
		tabList.addItem(name);
		tabbedPane.addTab(name, scrollWindow);
		tabbedPane.setTabComponentAt(tabbedPane.getTabCount() - 1, new ButtonTabComponent(tabbedPane, this));
		
	}
	
	/**
	 * Add a new blank spreadsheet to the Tabbed Pane. Will prompt the user for a name.
	 */
	public void AddSpreadsheetTab(boolean importFile){
		if(importFile) promptUseTemplate(TEMPLATE_SPREADSHEET);
		if(spreadsheetTemplateFile != null) AddSpreadsheetTab(spreadsheetTemplateFile);
		else AddSpreadsheetTab(null);
	}
	
	/**
	 * Adds a new spreadsheet tab to the Tabbed Pane with the specified data. Will prompt the user for a name.
	 * @param data Data to populate the JTable within the tab.
	 */
	public void AddSpreadsheetTab(ArrayList<String[]> data){
		//Prompt user to name the document
		String name = getTabName();
		AddSpreadsheetTab(data, name);
	}
	
	/**
	 * Adds a new spreadsheet tab to the Tabbed Pane with the specified data and name.
	 * @param data Data to populate the JTable within the tab.
	 * @param name The name to appear on the tab.
	 */
	public void AddSpreadsheetTab(ArrayList<String[]> data, String name){
		// TODO Prompt user for a new document or import an existing one
		// TODO If importing add method for interpreting CSV, investigate XLSX
		//Create a JTable for holding spreadsheet data
		JTable table = new JTable(60,20);
		//Add the table to a scroll pane
		JScrollPane scrollWindow = new JScrollPane(table);
		scrollWindow.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
		scrollWindow.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		scrollWindow.setPreferredSize(tabbedPane.getSize());
		//Size the table and set some view properties
		table.setFillsViewportHeight(true);
		table.setShowVerticalLines(true);
		table.setPreferredScrollableViewportSize(tabbedPane.getSize());
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		
		//If we have spreadsheet data, fill in the table
		if(data != null){
			for(int row = 0; row < data.size(); row++){
				String[] rowData = data.get(row);
				for(int col = 0; col < rowData.length; col++){
					table.setValueAt(rowData[col], row, col);
				}
			}
		}
		
		//Set this tab as a spreadsheet
		tabTypes.put(name, "SPREADSHEET");
		tabList.addItem(name);
		tabbedPane.addTab(name, scrollWindow);
		tabbedPane.setTabComponentAt(tabbedPane.getTabCount() - 1, new ButtonTabComponent(tabbedPane, this));

		//Make sure the template is null at this point for the next new tab
		spreadsheetTemplateFile = null;
	}

	/**
	 * Search through the TabbedPane and return the index of the tab matching the given name.
	 * @param name The name to match within the tabs.
	 * @return The index of a matching Tab or -1 if no matches are found.
	 */
	public int FindTabByName(String name){
		for(int i = 0; i < tabbedPane.getTabCount(); i++){
			//Look for the tab with a name matching the selected document
			if(tabbedPane.getTitleAt(i).equals(name)){
				return i;
			}
		}
		
		return -1;
	}
	
	/**
	 * Prompt the user to choose a name for a new tab.
	 * @return The name entered by the user.
	 */
	public String getTabName(){
		String newName = "";
		while(newName.replaceAll("\\s", "").length() == 0 || tabTypes.containsKey(newName))
		{
			newName = JOptionPane.showInputDialog(tabbedPane, "Please enter a unique name for the document:");
		}
		return newName;
	}
	
	/**
	 * Prompt the user to choose a template file for a new spreadsheet.
	 * @return The name entered by the user.
	 */
	public void promptUseTemplate(int templateType){
		//Pick a file to import and fill in a new tab
		File file;
		try {
			if(templateType == TEMPLATE_TEXT){
				if((file = GetFileFromDialog(false, "TEMPLATE.txt")) != null){
					textTemplateFile = "";
					if(file.exists() && file.isFile() && file.canRead()){
						FileReader input = new FileReader(file);
						BufferedReader br = new BufferedReader(input);
						String strLine;
						//Read File Line By Line
						while ((strLine = br.readLine()) != null)   {
						  // Print the content on the console
						  textTemplateFile += strLine + "\n";
						}
						//Close the input stream
						br.close();
					}
				}
			} else if(templateType == TEMPLATE_SPREADSHEET){
				if((file = GetFileFromDialog(false, "TEMPLATE.csv")) != null){
					spreadsheetTemplateFile = new ArrayList<String[]>();
					if(file.exists() && file.isFile() && file.canRead()){
						CSVReader reader = new CSVReader(new FileReader(file));
						String[] nextLine;
						while((nextLine = reader.readNext()) != null){
							spreadsheetTemplateFile.add(nextLine);
						}
						reader.close();
					}
				}
			}
		} catch (IOException exc) {
			errout.println(exc.getMessage());
		}
	}

	/**
	 * Remove the tab at the specified index
	 * @param index The index of the tab to remove. 
	 */
	public void RemoveTab(int index){
		Object[] options = {"OK", "Cancel"};
		int n = JOptionPane.showOptionDialog(tabbedPane, "If you close this tab you will lose any unsaved data.", "Notes Tab", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
		if(n == JOptionPane.OK_OPTION){
			String name = tabbedPane.getTitleAt(index);
			tabList.removeItem(name);
			tabTypes.remove(name);
			tabbedPane.remove(index);
		}
	}

	public void ClearAllTabs(){
		Object[] options = {"Yes", "No"};
		int n = JOptionPane.showOptionDialog(tabbedPane, "Do you want to clear all open tabs?", "Notes Tab", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
		if(n == JOptionPane.YES_OPTION){
			for(int i = tabbedPane.getTabCount() - 1; i >=0; i--){
				String name = tabbedPane.getTitleAt(i);
				tabList.removeItem(name);
				tabTypes.remove(name);
				tabbedPane.remove(i);
			}
		}
	}

	/**
	 * Save the content of the spreadsheet tab as a template CSV
	 * @param index The index of the tab to save. 
	 */
	public void ExportTab(int index){
		String name = tabbedPane.getTitleAt(index);
		String type = tabTypes.get(name);
		if(type == "SPREADSHEET"){
			ExportSpreadsheetTab(index);
		} else if(type == "TEXT"){
			ExportTextTab(index);
		}
	}

	public void ExportTextTab(int index){
		//Text tab
		JTextArea textTab = (JTextArea) GetInnerComponent(index);
		
		if(textTab != null){
			//Text
			String data = textTab.getText();

			if(data != null ){
				File f;
				if((f = GetFileFromDialog(true, "TEMPLATE.txt")) != null){
					try{
						// Create file 
						FileWriter fstream = new FileWriter(f);
						BufferedWriter out = new BufferedWriter(fstream);
						out.write(data);
						//Close the output stream
						out.close();
					} catch (Exception exc){//Catch exception if any
						errout.println(exc.getMessage());
					}
				}
			}
		}
	}

	public void ExportSpreadsheetTab(int index){
		stdout.println("Exporting Tab Data");
		//ArrayList to store data we will write out
		ArrayList<String[]> data = new ArrayList<String[]>();
		JTable table = (JTable) GetInnerComponent(index);
		
		if(table != null){
			//Data
			int numColumns = table.getColumnCount();
			String[] row;
			// Write cell data
			for(int i=0;i<table.getRowCount();i++)
			{
				row = new String[numColumns];
			    for(int j=0; j< table.getColumnCount();j++)
			    {
			    		row[j] = (String)table.getModel().getValueAt(i, j);
			    }
				data.add(row);
			}

			if(data.size() > 0) {
				File f;
				if((f = GetFileFromDialog(true, "TEMPLATE.csv")) != null){
					try{
						//Create our various Writers
						FileWriter fw = new FileWriter(f);
						CSVWriter writer = new CSVWriter(fw);
						//Write out to file and close
						writer.writeAll(data);
						writer.close();
						fw.close();
					} catch(IOException exc){
						errout.println(exc.getMessage());
					} 
				}
			} else {
				//No notes could be found
			}
		}
	}
	
	//CONTEXT MENU OPERATIONS
	/**
	 * Create menu items for a context menu on behalf of the Burp Extension's createMenuItems().
	 * @param invocation The IContextMenuInvocation sent by the extension.
	 * @param listener The listener to be passed to any created menu items.
	 * @return A new List<JMenuItem> to use in the context menu, null if no valid Contexts are used.
	 */
	public List<JMenuItem> CreateMenuItems(IContextMenuInvocation invocation, ActionListener listener){
		//User has opened a context menu. Check the context to see if its somewhere where we can grab a request/response
		//Remember the context and message so when we go to the action listener we can see what was happening
		selectedContext = invocation.getInvocationContext();
		messages = invocation.getSelectedMessages();
		if(selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || 
				selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
				selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
				selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE){
			//Present each document, the context shows whether they selected response/request
			List<JMenuItem> menu = new ArrayList<JMenuItem>();
			JMenu main = new JMenu("Send to Notes");
			menu.add(main);
			//Send request/response a new text document 
			main.add(CreateMenuItem("New Text Document", "CON|" + NotesExtensionOperations.COMMAND_ADD_NEW_TEXT, listener));
			//Send request/response to an existing document
			for(int i = 0; i < tabbedPane.getTabCount(); i++){
				if(tabTypes.get(tabbedPane.getTitleAt(i)) == "TEXT"){
					String docName = tabbedPane.getTitleAt(i);
					main.add(CreateMenuItem(docName, "CON|" + docName, listener));
				}
			}
			return menu;
		} else if(selectedContext == IContextMenuInvocation.CONTEXT_PROXY_HISTORY || 
				selectedContext == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE){
				//Need to present request/response options for each document
				List<JMenuItem> menu = new ArrayList<JMenuItem>();
				JMenu main = new JMenu("Send to Notes");
				menu.add(main);
				//Add a Request/Response option for a new text document
				main.add(NotesExtensionOperations.CreateMenuItem("New Text Document (Request)", "REQ|newTextDoc", listener));
				main.add(NotesExtensionOperations.CreateMenuItem("New Text Document (Response)", "RES|newTextDoc", listener));
				//Iterate through all open text documents, add a Request and Response option for each
				for(int i = 0; i < tabbedPane.getTabCount(); i++){
					if(tabTypes.get(tabbedPane.getTitleAt(i)) == "TEXT"){
						String docName = tabbedPane.getTitleAt(i);
						main.add(NotesExtensionOperations.CreateMenuItem(docName + " (Request)", "REQ|" + docName, listener));
						main.add(NotesExtensionOperations.CreateMenuItem(docName + " (Response)", "RES|" + docName, listener));
					}
				}
				return menu;
		}

		//No contexts we care about, don't return a menu option
		return null;
	}
	
	/**
	 * Create and return a JMenuItem
	 * @param name The name to be displayed.
	 * @param command The action command to be used by this item.
	 * @param listener The listener responsible for interpreting the command.
	 * @return A new JMenuItem.
	 */
	public static JMenuItem CreateMenuItem(String name, String command, ActionListener listener){
		JMenuItem newItem = new JMenuItem(name);
		newItem.setActionCommand(command);
		newItem.addActionListener(listener);
		
		return newItem;
	}

	/**
	 * Interpret the command sent by the BurpExtension's ActionListener
	 * @param cmd The command string sent by the ActionListener.
	 */
	public void ParseAction(String cmd){
		if(cmd.equals(COMMAND_ADD_TEXT)){
			AddTextTab(false);
		} else if(cmd.equals(COMMAND_ADD_SPREADSHEET)){
			AddSpreadsheetTab(false);
		} else if(cmd.equals(COMMAND_IMPORT_TEXT)){
			AddTextTab(true);
		} else if(cmd.equals(COMMAND_IMPORT_SPREADSHEET)){
			AddSpreadsheetTab(true);
		} else if(cmd.equals(COMMAND_SAVE_NOTES)){
			SaveNotes();
		} else if(cmd.equals(COMMAND_LOAD_NOTES)){
			if(tabbedPane.getTabCount() > 0) ClearAllTabs();
			LoadNotes();
		} else if(cmd.equals(COMMAND_SAVE_TAB_AS_TEMPLATE)){
			if(tabbedPane.getTabCount() > 0) ExportTab(tabbedPane.getSelectedIndex());
		} else if(cmd.equals(COMMAND_REMOVE_TAB)){
			//if(tabList.getSelectedIndex() > 0) RemoveTab(tabList.getSelectedIndex());
		}
		else {
			ParseConCommand(cmd);
		}
	}
	
	/**
	 * Split command from the ActionListener by '|' and see if it results in a context|document command
	 * @param cmd The command string sent by the ActionListener.
	 */
	public void ParseConCommand(String cmd){
		String[] command = cmd.split("\\|");
		if(command != null && command.length == 2){
			boolean getReq = false;
			if(command[0].equals("CON")){
				//Look at selectedContext to see which to copy
				if(selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
						selectedContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) 
					getReq = true;
			} else if(command[0].equals("REQ")){
				//Copy the request
				getReq = true;
			}
			//If getReq == false, we are grabbing the response
			if(messages != null){
				//Copy any response/requests in messages to a string
				String fullText = "";
				for(int i = 0; i < messages.length; i++){
					IHttpRequestResponse rr = messages[i];
					if(getReq) fullText += helpers.bytesToString(rr.getRequest());
					else fullText += helpers.bytesToString(rr.getResponse());
				}
				if(command[1].equals(COMMAND_ADD_NEW_TEXT)){
					//We are adding a new document to the tab
					AddTextTab(fullText);
				} else if(tabTypes.containsKey(command[1])){
					//We are adding the messages to an existing document
					int numTab = FindTabByName(command[1]);
					JTextArea textTab = (JTextArea) GetInnerComponent(numTab);
					String origText = textTab.getText();
					textTab.setText(origText + "\n" + fullText);
				}
			}
			messages = null; //Clear it out once we are done
			selectedContext = Byte.MIN_VALUE;
		}
	}
}