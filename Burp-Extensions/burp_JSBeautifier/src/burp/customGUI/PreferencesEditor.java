package burp.customGUI;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.JSBeautifier.BeautifierPreferences;
import burp.JSBeautifier.JSBeautifierCheckForUpdate;

import java.awt.Component;
import java.awt.Desktop;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JButton;

import java.awt.GridBagLayout;

import javax.swing.JLabel;

import java.awt.GridBagConstraints;

import javax.swing.JCheckBox;

import java.awt.Insets;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Vector;

import javax.swing.JComboBox;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


public class PreferencesEditor extends JPanel implements ITab{
	private final burp.IBurpExtenderCallbacks mCallbacks;
	private JCheckBox isAutomaticInProxy = new JCheckBox("");
	private JCheckBox isAutomaticInAll = new JCheckBox("");
	private JCheckBox isRestrictedToScope = new JCheckBox("");
	private JComboBox indent_size = new JComboBox();
	private JCheckBox detect_packers = new JCheckBox("");
	private JComboBox max_preserve_newlines = new JComboBox();
	private JCheckBox keep_array_indentation = new JCheckBox("");
	private JComboBox wrap_line_length = new JComboBox();
	private JCheckBox break_chained_methods = new JCheckBox("");
	private JComboBox brace_style = new JComboBox();
	private JCheckBox space_before_conditional = new JCheckBox("");
	private JComboBox indent_scripts = new JComboBox();
	private JCheckBox unescape_strings = new JCheckBox("");
	private JCheckBox isDebug = new JCheckBox("");
	private JCheckBox beautifyHeadersInManualMode = new JCheckBox("");
	/**
	 * Create the panel.
	 */
	public PreferencesEditor(final IBurpExtenderCallbacks mCallbacks) {
		this.mCallbacks = mCallbacks;
		setToolTipText("Burp Suite JSBeautifier Settings");
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{47, 211, 231, 0, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		JLabel label = new JLabel("   ");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 1;
		gbc_label.gridy = 0;
		add(label, gbc_label);
		
		JLabel lblAutomaticOnResponses = new JLabel("Beautify PROXY responses automatically?");
		GridBagConstraints gbc_lblAutomaticOnResponses = new GridBagConstraints();
		gbc_lblAutomaticOnResponses.anchor = GridBagConstraints.WEST;
		gbc_lblAutomaticOnResponses.insets = new Insets(0, 0, 5, 5);
		gbc_lblAutomaticOnResponses.gridx = 1;
		gbc_lblAutomaticOnResponses.gridy = 1;
		add(lblAutomaticOnResponses, gbc_lblAutomaticOnResponses);
		
		GridBagConstraints gbc_isAutomatic = new GridBagConstraints();
		gbc_isAutomatic.anchor = GridBagConstraints.WEST;
		gbc_isAutomatic.insets = new Insets(0, 0, 5, 5);
		gbc_isAutomatic.gridx = 2;
		gbc_isAutomatic.gridy = 1;
		add(isAutomaticInProxy, gbc_isAutomatic);
		
		JLabel lblOnlyInScope = new JLabel("Only in scope items?");
		GridBagConstraints gbc_lblOnlyInScope = new GridBagConstraints();
		gbc_lblOnlyInScope.anchor = GridBagConstraints.WEST;
		gbc_lblOnlyInScope.insets = new Insets(0, 0, 5, 5);
		gbc_lblOnlyInScope.gridx = 3;
		gbc_lblOnlyInScope.gridy = 1;
		add(lblOnlyInScope, gbc_lblOnlyInScope);
		
		
		GridBagConstraints gbc_isRestrictedToScope = new GridBagConstraints();
		gbc_isRestrictedToScope.anchor = GridBagConstraints.WEST;
		gbc_isRestrictedToScope.insets = new Insets(0, 0, 5, 5);
		gbc_isRestrictedToScope.gridx = 4;
		gbc_isRestrictedToScope.gridy = 1;
		add(isRestrictedToScope, gbc_isRestrictedToScope);
		
		JLabel lblNewLabel_2 = new JLabel("Beautify ALL responses automatically?");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_2.gridx = 1;
		gbc_lblNewLabel_2.gridy = 2;
		add(lblNewLabel_2, gbc_lblNewLabel_2);
		
		GridBagConstraints gbc_isAutomaticInAll = new GridBagConstraints();
		gbc_isAutomaticInAll.anchor = GridBagConstraints.WEST;
		gbc_isAutomaticInAll.insets = new Insets(0, 0, 5, 5);
		gbc_isAutomaticInAll.gridx = 2;
		gbc_isAutomaticInAll.gridy = 2;
		add(isAutomaticInAll, gbc_isAutomaticInAll);
		
		JLabel lblBeautifyHeaderIn = new JLabel("Beautify headers in Manual mode?");
		lblBeautifyHeaderIn.setToolTipText("This can cause functional issues");
		GridBagConstraints gbc_lblBeautifyHeaderIn = new GridBagConstraints();
		gbc_lblBeautifyHeaderIn.anchor = GridBagConstraints.WEST;
		gbc_lblBeautifyHeaderIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblBeautifyHeaderIn.gridx = 3;
		gbc_lblBeautifyHeaderIn.gridy = 2;
		add(lblBeautifyHeaderIn, gbc_lblBeautifyHeaderIn);
		
		
		GridBagConstraints gbc_beautifyHeadersInManMode = new GridBagConstraints();
		gbc_beautifyHeadersInManMode.anchor = GridBagConstraints.WEST;
		gbc_beautifyHeadersInManMode.insets = new Insets(0, 0, 5, 5);
		gbc_beautifyHeadersInManMode.gridx = 4;
		gbc_beautifyHeadersInManMode.gridy = 2;
		add(beautifyHeadersInManualMode, gbc_beautifyHeadersInManMode);
		
		JLabel lblIndentsize = new JLabel("Indent Size");
		GridBagConstraints gbc_lblIndentsize = new GridBagConstraints();
		gbc_lblIndentsize.anchor = GridBagConstraints.WEST;
		gbc_lblIndentsize.insets = new Insets(0, 0, 5, 5);
		gbc_lblIndentsize.gridx = 1;
		gbc_lblIndentsize.gridy = 3;
		add(lblIndentsize, gbc_lblIndentsize);
		

		
		GridBagConstraints gbc_indent_size = new GridBagConstraints();
		gbc_indent_size.anchor = GridBagConstraints.WEST;
		gbc_indent_size.insets = new Insets(0, 0, 5, 5);
		gbc_indent_size.gridx = 2;
		gbc_indent_size.gridy = 3;
		add(indent_size, gbc_indent_size);
		
		JLabel lblDetectpackers = new JLabel("Detect packers and obfuscators? ");
		GridBagConstraints gbc_lblDetectpackers = new GridBagConstraints();
		gbc_lblDetectpackers.anchor = GridBagConstraints.WEST;
		gbc_lblDetectpackers.insets = new Insets(0, 0, 5, 5);
		gbc_lblDetectpackers.gridx = 3;
		gbc_lblDetectpackers.gridy = 3;
		add(lblDetectpackers, gbc_lblDetectpackers);
		
		
		GridBagConstraints gbc_detect_packers = new GridBagConstraints();
		gbc_detect_packers.anchor = GridBagConstraints.WEST;
		gbc_detect_packers.insets = new Insets(0, 0, 5, 5);
		gbc_detect_packers.gridx = 4;
		gbc_detect_packers.gridy = 3;
		add(detect_packers, gbc_detect_packers);
		
		JLabel lblNewLabel = new JLabel("Max Preserve Newlines");
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel.gridx = 1;
		gbc_lblNewLabel.gridy = 4;
		add(lblNewLabel, gbc_lblNewLabel);

		
		GridBagConstraints gbc_max_preserve_newlines = new GridBagConstraints();
		gbc_max_preserve_newlines.anchor = GridBagConstraints.WEST;
		gbc_max_preserve_newlines.insets = new Insets(0, 0, 5, 5);
		gbc_max_preserve_newlines.gridx = 2;
		gbc_max_preserve_newlines.gridy = 4;
		add(max_preserve_newlines, gbc_max_preserve_newlines);
		
		JLabel lblKeeparrayindentation = new JLabel("Keep array indentation?");
		GridBagConstraints gbc_lblKeeparrayindentation = new GridBagConstraints();
		gbc_lblKeeparrayindentation.anchor = GridBagConstraints.WEST;
		gbc_lblKeeparrayindentation.insets = new Insets(0, 0, 5, 5);
		gbc_lblKeeparrayindentation.gridx = 3;
		gbc_lblKeeparrayindentation.gridy = 4;
		add(lblKeeparrayindentation, gbc_lblKeeparrayindentation);
		
		
		GridBagConstraints gbc_keep_array_indentation = new GridBagConstraints();
		gbc_keep_array_indentation.anchor = GridBagConstraints.WEST;
		gbc_keep_array_indentation.insets = new Insets(0, 0, 5, 5);
		gbc_keep_array_indentation.gridx = 4;
		gbc_keep_array_indentation.gridy = 4;
		add(keep_array_indentation, gbc_keep_array_indentation);
		
		JLabel lblWraplinelength = new JLabel("Wrap Line Length");
		GridBagConstraints gbc_lblWraplinelength = new GridBagConstraints();
		gbc_lblWraplinelength.anchor = GridBagConstraints.WEST;
		gbc_lblWraplinelength.insets = new Insets(0, 0, 5, 5);
		gbc_lblWraplinelength.gridx = 1;
		gbc_lblWraplinelength.gridy = 5;
		add(lblWraplinelength, gbc_lblWraplinelength);

		
		GridBagConstraints gbc_wrap_line_length = new GridBagConstraints();
		gbc_wrap_line_length.anchor = GridBagConstraints.WEST;
		gbc_wrap_line_length.insets = new Insets(0, 0, 5, 5);
		gbc_wrap_line_length.gridx = 2;
		gbc_wrap_line_length.gridy = 5;
		add(wrap_line_length, gbc_wrap_line_length);
		
		JLabel lblBreakchainedmethods = new JLabel("Break lines on chained methods?");
		GridBagConstraints gbc_lblBreakchainedmethods = new GridBagConstraints();
		gbc_lblBreakchainedmethods.anchor = GridBagConstraints.WEST;
		gbc_lblBreakchainedmethods.insets = new Insets(0, 0, 5, 5);
		gbc_lblBreakchainedmethods.gridx = 3;
		gbc_lblBreakchainedmethods.gridy = 5;
		add(lblBreakchainedmethods, gbc_lblBreakchainedmethods);
		
		
		GridBagConstraints gbc_break_chained_methods = new GridBagConstraints();
		gbc_break_chained_methods.anchor = GridBagConstraints.WEST;
		gbc_break_chained_methods.insets = new Insets(0, 0, 5, 5);
		gbc_break_chained_methods.gridx = 4;
		gbc_break_chained_methods.gridy = 5;
		add(break_chained_methods, gbc_break_chained_methods);
		
		JLabel lblBracestyle = new JLabel("Brace Style");
		GridBagConstraints gbc_lblBracestyle = new GridBagConstraints();
		gbc_lblBracestyle.anchor = GridBagConstraints.WEST;
		gbc_lblBracestyle.insets = new Insets(0, 0, 5, 5);
		gbc_lblBracestyle.gridx = 1;
		gbc_lblBracestyle.gridy = 6;
		add(lblBracestyle, gbc_lblBracestyle);
		


		
		GridBagConstraints gbc_brace_style = new GridBagConstraints();
		gbc_brace_style.anchor = GridBagConstraints.WEST;
		gbc_brace_style.insets = new Insets(0, 0, 5, 5);
		gbc_brace_style.gridx = 2;
		gbc_brace_style.gridy = 6;
		add(brace_style, gbc_brace_style);
		
		JLabel lblSpacebeforeconditional = new JLabel("Space before conditional: \"if(x)\" / \"if (x)\"");
		GridBagConstraints gbc_lblSpacebeforeconditional = new GridBagConstraints();
		gbc_lblSpacebeforeconditional.anchor = GridBagConstraints.WEST;
		gbc_lblSpacebeforeconditional.insets = new Insets(0, 0, 5, 5);
		gbc_lblSpacebeforeconditional.gridx = 3;
		gbc_lblSpacebeforeconditional.gridy = 6;
		add(lblSpacebeforeconditional, gbc_lblSpacebeforeconditional);
		
		
		GridBagConstraints gbc_space_before_conditional = new GridBagConstraints();
		gbc_space_before_conditional.anchor = GridBagConstraints.WEST;
		gbc_space_before_conditional.insets = new Insets(0, 0, 5, 5);
		gbc_space_before_conditional.gridx = 4;
		gbc_space_before_conditional.gridy = 6;
		add(space_before_conditional, gbc_space_before_conditional);
		
		JLabel lblIndentscripts = new JLabel("Indent Scripts");
		GridBagConstraints gbc_lblIndentscripts = new GridBagConstraints();
		gbc_lblIndentscripts.anchor = GridBagConstraints.WEST;
		gbc_lblIndentscripts.insets = new Insets(0, 0, 5, 5);
		gbc_lblIndentscripts.gridx = 1;
		gbc_lblIndentscripts.gridy = 7;
		add(lblIndentscripts, gbc_lblIndentscripts);

		GridBagConstraints gbc_indent_scripts = new GridBagConstraints();
		gbc_indent_scripts.anchor = GridBagConstraints.WEST;
		gbc_indent_scripts.insets = new Insets(0, 0, 5, 5);
		gbc_indent_scripts.gridx = 2;
		gbc_indent_scripts.gridy = 7;
		add(indent_scripts, gbc_indent_scripts);
		
		JLabel lblUnescapestrings = new JLabel("Unescape printable chars encoded as \\xNN or \\uNNNN?");
		GridBagConstraints gbc_lblUnescapestrings = new GridBagConstraints();
		gbc_lblUnescapestrings.anchor = GridBagConstraints.WEST;
		gbc_lblUnescapestrings.insets = new Insets(0, 0, 5, 5);
		gbc_lblUnescapestrings.gridx = 3;
		gbc_lblUnescapestrings.gridy = 7;
		add(lblUnescapestrings, gbc_lblUnescapestrings);
		
				GridBagConstraints gbc_unescape_strings = new GridBagConstraints();
				gbc_unescape_strings.anchor = GridBagConstraints.WEST;
				gbc_unescape_strings.insets = new Insets(0, 0, 5, 5);
				gbc_unescape_strings.gridx = 4;
				gbc_unescape_strings.gridy = 7;
				add(unescape_strings, gbc_unescape_strings);
		
		JLabel lblNewLabel_1 = new JLabel("Debug Mode?");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_1.gridx = 1;
		gbc_lblNewLabel_1.gridy = 8;
		add(lblNewLabel_1, gbc_lblNewLabel_1);

		GridBagConstraints gbc_isDebug = new GridBagConstraints();
		gbc_isDebug.anchor = GridBagConstraints.WEST;
		gbc_isDebug.insets = new Insets(0, 0, 5, 5);
		gbc_isDebug.gridx = 2;
		gbc_isDebug.gridy = 8;
		add(isDebug, gbc_isDebug);
		
		JButton btnResetToOriginal = new JButton("Reset To Original Values");
		btnResetToOriginal.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.resetBeautifierPreferences();
				setPreferencesValues();
			}
		});
		
		JLabel label_1 = new JLabel("     ");
		GridBagConstraints gbc_label_1 = new GridBagConstraints();
		gbc_label_1.insets = new Insets(0, 0, 5, 5);
		gbc_label_1.gridx = 1;
		gbc_label_1.gridy = 9;
		add(label_1, gbc_label_1);
		GridBagConstraints gbc_btnResetToOriginal = new GridBagConstraints();
		gbc_btnResetToOriginal.anchor = GridBagConstraints.WEST;
		gbc_btnResetToOriginal.insets = new Insets(0, 0, 5, 5);
		gbc_btnResetToOriginal.gridx = 1;
		gbc_btnResetToOriginal.gridy = 10;
		add(btnResetToOriginal, gbc_btnResetToOriginal);
		
		JButton btnCheckForUpdate = new JButton("Check For Update");
		btnCheckForUpdate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JSBeautifierCheckForUpdate checkForUpdate = new burp.JSBeautifier.JSBeautifierCheckForUpdate(mCallbacks);
					JOptionPane.showMessageDialog(null, checkForUpdate.updateMessage);
					
			}
		});
		GridBagConstraints gbc_btnCheckForUpdate = new GridBagConstraints();
		gbc_btnCheckForUpdate.anchor = GridBagConstraints.WEST;
		gbc_btnCheckForUpdate.insets = new Insets(0, 0, 5, 5);
		gbc_btnCheckForUpdate.gridx = 1;
		gbc_btnCheckForUpdate.gridy = 11;
		add(btnCheckForUpdate, gbc_btnCheckForUpdate);
		
		JButton btnOpenExtensionHome = new JButton("Open Extension Home Page");
		btnOpenExtensionHome.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage(burp.JSBeautifier.BeautifierPreferences.getProjectLink());
			}
		});
		GridBagConstraints gbc_btnOpenExtensionHome = new GridBagConstraints();
		gbc_btnOpenExtensionHome.anchor = GridBagConstraints.WEST;
		gbc_btnOpenExtensionHome.insets = new Insets(0, 0, 5, 5);
		gbc_btnOpenExtensionHome.gridx = 1;
		gbc_btnOpenExtensionHome.gridy = 12;
		add(btnOpenExtensionHome, gbc_btnOpenExtensionHome);
		
		JLabel label_2 = new JLabel("     ");
		GridBagConstraints gbc_label_2 = new GridBagConstraints();
		gbc_label_2.insets = new Insets(0, 0, 5, 5);
		gbc_label_2.gridx = 1;
		gbc_label_2.gridy = 13;
		add(label_2, gbc_label_2);
		
		JLabel appInfoLabel = new JLabel(BeautifierPreferences.getAppInfo());
		GridBagConstraints gbc_appInfoLabel = new GridBagConstraints();
		gbc_appInfoLabel.anchor = GridBagConstraints.WEST;
		gbc_appInfoLabel.gridwidth = 4;
		gbc_appInfoLabel.insets = new Insets(0, 0, 0, 5);
		gbc_appInfoLabel.gridx = 1;
		gbc_appInfoLabel.gridy = 14;
		add(appInfoLabel, gbc_appInfoLabel);
		
		
		fillComboBoxes();
		setPreferencesValues();
		setComponentsActions();
	}
	private void setComponentsActions(){
		isAutomaticInProxy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setAutomaticInProxy(isAutomaticInProxy.isSelected());
			}
		});
		
		isAutomaticInAll.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setAutomaticInAll(isAutomaticInAll.isSelected());
			}
		});
		
		isRestrictedToScope.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setRestrictedToScope(isRestrictedToScope.isSelected());
			}
		});
		beautifyHeadersInManualMode.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setBeautifyHeadersInManualMode(beautifyHeadersInManualMode.isSelected());
			}
		});
		detect_packers.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setDetect_packers(detect_packers.isSelected());
			}
		});
		keep_array_indentation.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setKeep_array_indentation(keep_array_indentation.isSelected());
			}
		});
		break_chained_methods.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setBreak_chained_methods(break_chained_methods.isSelected());
			}
		});
		space_before_conditional.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setSpace_before_conditional(space_before_conditional.isSelected());
			}
		});
		unescape_strings.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setUnescape_strings(unescape_strings.isSelected());
			}
		});
		isDebug.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				BeautifierPreferences.setDebugMode(isDebug.isSelected());
			}
		});
		
		indent_size.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Item item = (Item) indent_size.getSelectedItem();
				int key = Integer.valueOf(item.key);
				BeautifierPreferences.setIndent_size(key);
			}
		});
		
		max_preserve_newlines.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Item item = (Item) max_preserve_newlines.getSelectedItem();
				int key = Integer.valueOf(item.key);
				BeautifierPreferences.setMax_preserve_newlines(key);
			}
		});
		
		wrap_line_length.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Item item = (Item) wrap_line_length.getSelectedItem();
				int key = Integer.valueOf(item.key);
				BeautifierPreferences.setWrap_line_length(key);
			}
		});
		
		brace_style.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Item item = (Item) brace_style.getSelectedItem();
				BeautifierPreferences.setBrace_style(item.key);
			}
		});
		
		indent_scripts.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				Item item = (Item) indent_scripts.getSelectedItem();
				BeautifierPreferences.setIndent_scripts(item.key);
			}
		});
		
	}
	
	private void fillComboBoxes(){
		// Filling ComboBoxes
		indent_size.setModel(new DefaultComboBoxModel(indent_size_model()));
		max_preserve_newlines.setModel(new DefaultComboBoxModel(max_preserve_newlines_model()));
		wrap_line_length.setModel(new DefaultComboBoxModel(wrap_line_length_model()));
		brace_style.setModel(new DefaultComboBoxModel(brace_style_model()));
		indent_scripts.setModel(new DefaultComboBoxModel(indent_scripts_model()));
	}
	
	private void setPreferencesValues(){
		
		// ComboBoxes Values
		int indexValue;
		switch(String.valueOf(BeautifierPreferences.getIndent_size())){
		case "1":
			indexValue=0;
			break;
		case "2":
			indexValue=1;
			break;
		case "3":
			indexValue=2;
			break;
		case "4":
			indexValue=3;
			break;
		case "8":
			indexValue=4;
			break;
		default:
			indexValue=0;
			break;
		}
		indent_size.setSelectedIndex(indexValue);
		
		switch(String.valueOf(BeautifierPreferences.getMax_preserve_newlines())){
		case "-1":
			indexValue=0;
			break;
		case "1":
			indexValue=1;
			break;
		case "2":
			indexValue=2;
			break;
		case "5":
			indexValue=3;
			break;
		case "10":
			indexValue=4;
			break;
		case "0":
			indexValue=5;
			break;
		default:
			indexValue=0;
			break;
		}
		max_preserve_newlines.setSelectedIndex(indexValue);

		switch(String.valueOf(BeautifierPreferences.getWrap_line_length())){
		case "0":
			indexValue=0;
			break;
		case "40":
			indexValue=1;
			break;
		case "70":
			indexValue=2;
			break;
		case "80":
			indexValue=3;
			break;
		case "110":
			indexValue=4;
			break;
		case "120":
			indexValue=5;
			break;
		case "160":
			indexValue=6;
			break;
		default:
			indexValue=0;
			break;
		}
		wrap_line_length.setSelectedIndex(indexValue);
		
		switch(String.valueOf(BeautifierPreferences.getBrace_style())){
		case "collapse":
			indexValue=0;
			break;
		case "expand":
			indexValue=1;
			break;
		case "end-expand":
			indexValue=2;
			break;
		default:
			indexValue=0;
			break;
		}
		brace_style.setSelectedIndex(indexValue);
		
		switch(String.valueOf(BeautifierPreferences.getIndent_scripts())){
		case "keep":
			indexValue=0;
			break;
		case "normal":
			indexValue=1;
			break;
		case "separate":
			indexValue=2;
			break;
		default:
			indexValue=0;
			break;
		}
		indent_scripts.setSelectedIndex(indexValue);
		
		// CheckBoxes Values
		isAutomaticInProxy.setSelected(BeautifierPreferences.isAutomaticInProxy());
		isRestrictedToScope.setSelected(BeautifierPreferences.isRestrictedToScope());
		isAutomaticInAll.setSelected(BeautifierPreferences.isAutomaticInAll());
		beautifyHeadersInManualMode.setSelected(BeautifierPreferences.isBeautifyHeadersInManualMode());
		detect_packers.setSelected(BeautifierPreferences.isDetect_packers());
		keep_array_indentation.setSelected(BeautifierPreferences.isKeep_array_indentation());
		break_chained_methods.setSelected(BeautifierPreferences.isBreak_chained_methods());
		space_before_conditional.setSelected(BeautifierPreferences.isSpace_before_conditional());
		unescape_strings.setSelected(BeautifierPreferences.isUnescape_strings());
		isDebug.setSelected(BeautifierPreferences.isDebugMode());
		
	}
	
	
	private Vector indent_size_model(){
		Vector model = new Vector();  
		model.addElement( new Item("1", "Indent with a tab character"));
		model.addElement( new Item("2", "Indent with 2 spaces" ));
		model.addElement( new Item("3", "Indent with 3 spaces" ));
		model.addElement( new Item("4", "Indent with 4 spaces" ));
		model.addElement( new Item("8", "Indent with 8 spaces" ));
		return model;
	}

	private Vector max_preserve_newlines_model(){
		Vector model = new Vector();  
		model.addElement( new Item("-1", "Remove all extra newlines"));
		model.addElement( new Item("1", "Allow 1 newline between tokens" ));
		model.addElement( new Item("2", "Allow 2 newlines between tokens" ));
		model.addElement( new Item("5", "Allow 5 newlines between tokens" ));
		model.addElement( new Item("10", "Allow 10 newlines between tokens" ));
		model.addElement( new Item("0", "Allow unlimited newlines between tokens" ));
		return model;
	}
	
	private Vector wrap_line_length_model(){
		Vector model = new Vector();  
		model.addElement( new Item("0", "Do not wrap lines"));
		model.addElement( new Item("40", "Wrap lines near 40 characters" ));
		model.addElement( new Item("70", "Wrap lines near 70 characters" ));
		model.addElement( new Item("80", "Wrap lines near 80 characters" ));
		model.addElement( new Item("110", "Wrap lines near 110 characters" ));
		model.addElement( new Item("120", "Wrap lines near 120 characters" ));
		model.addElement( new Item("160", "Wrap lines near 160 characters" ));
		return model;
	}
	
	private Vector brace_style_model(){
		Vector model = new Vector();  
		model.addElement( new Item("collapse", "Braces with control statement"));
		model.addElement( new Item("expand", "Braces on own line" ));
		model.addElement( new Item("end-expand", "End braces on own line" ));
		return model;
	}
	
	private Vector indent_scripts_model(){
		Vector model = new Vector();  
		model.addElement( new Item("keep", "Keep indent level of the tag"));
		model.addElement( new Item("normal", "Add one indent level" ));
		model.addElement( new Item("separate", "Separate indentation" ));
		return model;
	}
	
	class Item  
    {  
        private String key;  
        private String value;  
  
        public Item(String key, String value)  
        {  
            this.key = key;  
            this.value = value;  
        }  
  
        public String getKey()  
        {  
            return key;  
        }  
  
        public String getValue()  
        {  
            return value;  
        }  
  
        public String toString()  
        {  
            return value;  
        }  
    }  
	@Override
	public String getTabCaption() {
		return "JSBeautifier Settings";
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this;
	}

	public static void openWebpage(URI uri) {
	    Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
	    if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
	        try {
	            desktop.browse(uri);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	}

	public static void openWebpage(String url) {
	    try {
	        openWebpage((new URL(url)).toURI());
	    } catch (URISyntaxException e) {
	        e.printStackTrace();
	    } catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}
}
