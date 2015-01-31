package burp.customGUI;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.plaf.basic.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.awt.*;
import java.awt.event.*;
import org.fife.ui.rtextarea.*;
import org.fife.ui.rsyntaxtextarea.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;


public class ViewHighlightedTextForm implements ActionListener{
	private JFrame frame;
	private RSyntaxTextArea textArea;
	private JTextField searchField;
	private JCheckBox regexCB;
	private JCheckBox matchCaseCB;
	private JComboBox<String> syntaxComboBox;

	public void showForm(final String title,final String message,final String texttype,final int intWidth,final int intHeight) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					prepareForm(title,message,texttype,intWidth,intHeight);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});

	}

	private void prepareForm(String title,String message,String texttype,int intWidth,int intHeight){
		// Creating the main frame
		frame = new JFrame();
		frame.setTitle(title);
		frame.setBounds(100, 100, 700, 550);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

		// Creating the SplitPane
		JSplitPane splitPane = new JSplitPane();
		// Destroying the borders
		splitPane.setUI(new BasicSplitPaneUI() {
			public BasicSplitPaneDivider createDefaultDivider() {
				return new BasicSplitPaneDivider(this) {
					public void setBorder(Border b) {
					}
				};
			}
		});
		splitPane.setBorder(null);
		splitPane.setEnabled(false);
		// It is a vertical Pane in Centre
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		frame.getContentPane().add(splitPane, BorderLayout.CENTER);		
		// This is the text box with syntax highlighter
		textArea = new RSyntaxTextArea(50, 200);
		textArea.setSyntaxEditingStyle(texttype);
		textArea.setCodeFoldingEnabled(true);
		textArea.setAntiAliasingEnabled(true);
		//textArea.setFont(new Font("LucidaSans", Font.PLAIN, 20));		
		// It is a readonly text box
		textArea.setEditable(false);
		// Set the text that should go to the textbox
		textArea.setText(message);
		// Creating the scroll bars
		RTextScrollPane sp = new RTextScrollPane(textArea);
		sp.setFoldIndicatorEnabled(true);
		// Adding the text box to the SplitPane
		splitPane.setRightComponent(sp);

		// Create a toolbar with searching options. from http://fifesoft.com/rsyntaxtextarea/examples/example4.php
		JToolBar toolBar = new JToolBar();
		searchField = new JTextField(30);
		toolBar.add(searchField);
		final JButton nextButton = new JButton("Find Next");
		nextButton.setActionCommand("FindNext");
		nextButton.addActionListener(this);
		toolBar.add(nextButton);
		searchField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				nextButton.doClick(0);
			}
		});
		JButton prevButton = new JButton("Find Previous");
		prevButton.setActionCommand("FindPrev");
		prevButton.addActionListener(this);
		toolBar.add(prevButton);
		regexCB = new JCheckBox("Regex");
		toolBar.add(regexCB);
		matchCaseCB = new JCheckBox("Match Case");
		toolBar.add(matchCaseCB);
		frame.getContentPane().add(toolBar, BorderLayout.SOUTH);


		// Another panel to keep the "copy to clipboard" and the "close" button
		JPanel panel = new JPanel();
		splitPane.setLeftComponent(panel);
		panel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		// "copy to clipboard" button
		JButton btnCopyToclipboardButton = new JButton("Copy to clipboard");
		// defining the action for the "copy to clipboard" button
		btnCopyToclipboardButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				copyStringToClipboard(textArea.getText());
			}
		});
		// adding the "copy to clipboard" button to the panel
		panel.add(btnCopyToclipboardButton);
		// "close" button
		JButton btnCloseButton = new JButton("Close");
		// defining the action for the "close" button
		btnCloseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				frame.dispose();
			}
		});
		// adding the "close" button to the panel
		panel.add(btnCloseButton);

		// Creating list of useful languages for highlighting
		List<String> syntaxLists = Arrays.asList(SyntaxConstants.SYNTAX_STYLE_ACTIONSCRIPT,SyntaxConstants.SYNTAX_STYLE_ASSEMBLER_X86,SyntaxConstants.SYNTAX_STYLE_BBCODE,
				SyntaxConstants.SYNTAX_STYLE_C, SyntaxConstants.SYNTAX_STYLE_CSHARP, SyntaxConstants.SYNTAX_STYLE_CSS,
				SyntaxConstants.SYNTAX_STYLE_DTD, SyntaxConstants.SYNTAX_STYLE_HTML, SyntaxConstants.SYNTAX_STYLE_JAVA, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT,
				SyntaxConstants.SYNTAX_STYLE_JSP, SyntaxConstants.SYNTAX_STYLE_LATEX, SyntaxConstants.SYNTAX_STYLE_MXML, SyntaxConstants.SYNTAX_STYLE_NONE,
				SyntaxConstants.SYNTAX_STYLE_PERL, SyntaxConstants.SYNTAX_STYLE_PHP, SyntaxConstants.SYNTAX_STYLE_PROPERTIES_FILE, SyntaxConstants.SYNTAX_STYLE_PYTHON,
				SyntaxConstants.SYNTAX_STYLE_RUBY, SyntaxConstants.SYNTAX_STYLE_SQL, SyntaxConstants.SYNTAX_STYLE_UNIX_SHELL, SyntaxConstants.SYNTAX_STYLE_WINDOWS_BATCH,
				SyntaxConstants.SYNTAX_STYLE_XML
				);
		Collections.sort(syntaxLists);
		//Create the combo box
		syntaxComboBox = new JComboBox(syntaxLists.toArray());
		// Default language = html
		syntaxComboBox.setSelectedItem(SyntaxConstants.SYNTAX_STYLE_HTML);
		// Adding action listener for the select language box
		syntaxComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textArea.setSyntaxEditingStyle(syntaxComboBox.getSelectedItem().toString());
			}
		});
		// adding the combo box to the panel
		panel.add(syntaxComboBox);

		// Show the frame
		frame.setVisible(true);
	}

	// Actions of the finder section
	public void actionPerformed(ActionEvent e) {

		// "FindNext" => search forward, "FindPrev" => search backward
		String command = e.getActionCommand();
		boolean forward = "FindNext".equals(command);

		// Create an object defining our search parameters.
		SearchContext context = new SearchContext();
		String text = searchField.getText();
		if (text.length() == 0) {
			return;
		}
		context.setSearchFor(text);
		context.setMatchCase(matchCaseCB.isSelected());
		context.setRegularExpression(regexCB.isSelected());
		context.setSearchForward(forward);
		context.setWholeWord(false);
		boolean found = SearchEngine.find(textArea, context) != null;
		
		if (!found) {
			JOptionPane.showMessageDialog(frame, "Text not found");
		} 

	}

	// It copies the strings to the clipboard
	private void copyStringToClipboard(String str) {
		StringSelection stringSelection = new StringSelection(str);
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(stringSelection, null);
	}
}
