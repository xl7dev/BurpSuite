package gui;

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JSplitPane;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import application.SamlTabController;
import burp.IBurpExtenderCallbacks;

public class SamlMain extends javax.swing.JPanel{
	
	private static final long serialVersionUID = 1L;
	IBurpExtenderCallbacks callbacks;
	private RSyntaxTextArea textArea;
	private RTextScrollPane scrollPane;
	private SamlTabController controller;
	private SamlPanelAction panelAction;
	private SamlPanelInfo panelInformation;
	
	public SamlMain() {
		super();
		initializeUI();
	}
	
	public SamlMain(SamlTabController controller){
		super();
		this.controller = controller;
		initializeUI();
	}
	
	private void initializeUI(){
		setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPaneMain = new JSplitPane();
		splitPaneMain.setOrientation(JSplitPane.VERTICAL_SPLIT);
		add(splitPaneMain, BorderLayout.CENTER);
		
		JPanel panelTop = new JPanel();
		splitPaneMain.setLeftComponent(panelTop);
		panelTop.setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPaneTop = new JSplitPane();
		splitPaneTop.setResizeWeight(0.3);
		panelTop.add(splitPaneTop);
		
		panelAction = new SamlPanelAction(controller);
		splitPaneTop.setLeftComponent(panelAction);
		
		panelInformation = new SamlPanelInfo();
		splitPaneTop.setRightComponent(panelInformation);
		
		JPanel panelText = new JPanel();
		splitPaneMain.setRightComponent(panelText);
		panelText.setLayout(new BorderLayout(0, 0));
		
		textArea = new RSyntaxTextArea();
		textArea.setText("<failureInInitialization></failureInInitialization>");
        scrollPane = new RTextScrollPane(textArea);
        scrollPane.add(textArea);
        panelText.add(scrollPane, BorderLayout.CENTER);
        scrollPane.setViewportView(textArea);
		
        this.invalidate();
        this.updateUI();
        
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
        textArea.setEditable(true);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(false);
        textArea.setAnimateBracketMatching(false);
        textArea.setAutoIndentEnabled(false);
        textArea.setBracketMatchingEnabled(false);
	}
	
	public RSyntaxTextArea getTextArea(){
		return textArea;
	}
	
	public SamlPanelAction getActionPanel(){
		return panelAction;
	}
	
	public SamlPanelInfo getInfoPanel(){
		return panelInformation;
	}
	
}
