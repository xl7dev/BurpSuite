package application;

import gui.SamlMain;
import gui.SamlPanelInfo;
import gui.SignatureHelpWindow;
import gui.XSWHelpWindow;
import helpers.HTTPHelpers;
import helpers.XMLHelpers;
import helpers.XSWHelpers;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.zip.DataFormatException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import model.BurpCertificate;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rtextarea.SearchContext;
import org.fife.ui.rtextarea.SearchEngine;
import org.fife.ui.rtextarea.SearchResult;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class SamlTabController implements IMessageEditorTab, Observer {

	private static final String XML_CERTIFICATE_NOT_FOUND = "X509 Certificate not found";
	private static final String XSW_ATTACK_APPLIED = "XSW Attack applied";
	private static final String XML_COULD_NOT_SIGN = "Could not sign XML";
	private static final String XML_COULD_NOT_SERIALIZE = "Could not serialize XML";
	private static final String XML_NOT_WELL_FORMED = "XML isn't well formed or binding is not supported";
	private static final String XML_NOT_SUITABLE_FOR_XSW = "This XML Message is not suitable for this particular XSW, is there a signature?";
	private static final String NO_BROWSER = "Could not open diff in Browser. Path to file was copied to clipboard";
	private static final String NO_DIFF_TEMP_FILE = "Could not create diff temp file.";

	private IExtensionHelpers helpers;
	private XMLHelpers xmlHelpers;
	private byte[] message;
	private String orgSAMLMessage;
	private String SAMLMessage;
	private boolean isInflated = true;
	private boolean isGZip = false;
	private boolean isWSSUrlEncoded = false;
	private RSyntaxTextArea textArea;
	private SamlMain samlGUI;
	private boolean editable;
	private boolean edited;
	private boolean isSOAPMessage;
	private boolean isWSSMessage;
	private CertificateTabController certificateTabController;
	private XSWHelpers xswHelpers;
	private HTTPHelpers httpHelpers;

	public SamlTabController(IBurpExtenderCallbacks callbacks, boolean editable,
			CertificateTabController certificateTabController) {
		this.editable = editable;
		this.helpers = callbacks.getHelpers();
		samlGUI = new SamlMain(this);
		textArea = samlGUI.getTextArea();
		addTextAreaKeyListener();
		textArea.setEditable(editable);
		textArea.setEnabled(true);
		xmlHelpers = new XMLHelpers();
		xswHelpers = new XSWHelpers();
		httpHelpers = new HTTPHelpers();
		this.certificateTabController = certificateTabController;
		this.certificateTabController.addObserver(this);
	}

	private void addTextAreaKeyListener() {
		textArea.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent arg0) {
			}

			@Override
			public void keyReleased(KeyEvent arg0) {
			}

			@Override
			public void keyPressed(KeyEvent arg0) {
				edited = true;
			}
		});
	}

	@Override
	public byte[] getMessage() {
		byte[] byteMessage = message;
		if (edited) {
			if (isSOAPMessage) {
				try {
					// TODO Only working with getString for both documents,
					// otherwise namespaces and attributes are emptied -.-
					IResponseInfo responseInfo = helpers.analyzeResponse(byteMessage);
					int bodyOffset = responseInfo.getBodyOffset();
					String HTTPHeader = new String(byteMessage, 0, bodyOffset, "UTF-8");

					String soapMessage = new String(byteMessage, bodyOffset, byteMessage.length - bodyOffset, "UTF-8");
					Document soapDocument = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
					Element soapBody = xmlHelpers.getSOAPBody(soapDocument);
					xmlHelpers.getString(soapDocument);
					Document samlDocumentEdited = xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage);
					xmlHelpers.getString(samlDocumentEdited);
					Element samlResponse = (Element) samlDocumentEdited.getFirstChild();
					soapDocument.adoptNode(samlResponse);
					Element soapFirstChildOfBody = (Element) soapBody.getFirstChild();
					soapBody.replaceChild(samlResponse, soapFirstChildOfBody);
					String wholeMessage = HTTPHeader + xmlHelpers.getString(soapDocument);
					byteMessage = wholeMessage.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
				} catch (SAXException e) {
					setInfoMessageText(XML_NOT_WELL_FORMED);
				} catch (IOException e) {
					e.printStackTrace();
				}

			} 
			else {
				String textMessage = null;

				try {
					textMessage = xmlHelpers.getStringOfDocument(
							xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText()), 0, true);
				} catch (IOException e) {
					setInfoMessageText(XML_COULD_NOT_SERIALIZE);
				} catch (SAXException e) {
					setInfoMessageText(XML_NOT_WELL_FORMED);
				}
				
				String parameterToUpdate = "SAMLResponse";
				if(isWSSMessage){
					parameterToUpdate = "wresult";
				}
				IParameter newParameter = helpers.buildParameter(parameterToUpdate, getEncodedSAMLMessage(textMessage),
						IParameter.PARAM_BODY);
				byteMessage = helpers.updateParameter(byteMessage, newParameter);
			}
		}
		return byteMessage;
	}

	@Override
	public byte[] getSelectedData() {
		try {
			return (textArea.getSelectedText()).getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
		}
		return null;
	}

	@Override
	public String getTabCaption() {
		return "SAML Raider";
	}

	@Override
	public Component getUiComponent() {
		return samlGUI;
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return isRequest && isSAMLMessage(content);
	}

	private boolean isSAMLMessage(byte[] content) {
		IRequestInfo info = helpers.analyzeRequest(content);
		if (info.getContentType() == IRequestInfo.CONTENT_TYPE_XML) {
			isSOAPMessage = true;
			try {
				IRequestInfo requestInfo = helpers.analyzeRequest(content);
				int bodyOffset = requestInfo.getBodyOffset();
				String soapMessage = new String(content, bodyOffset, content.length - bodyOffset, "UTF-8");
				Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
				return xmlHelpers.getAssertions(document).getLength() != 0
						|| xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
			} catch (UnsupportedEncodingException e) {
			} catch (SAXException e) {
				e.printStackTrace();
				return false;
			}
		} 
		//WSS Security
		else if( null != helpers.getRequestParameter(content, "wresult")){
			try {
				IRequestInfo requestInfo = helpers.analyzeRequest(content);
				isWSSUrlEncoded = requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED;
				isWSSMessage = true;
				IParameter parameter = helpers.getRequestParameter(content, "wresult");
				String wssMessage = getDecodedSAMLMessage(parameter.getValue());
				Document document;
				document = xmlHelpers.getXMLDocumentOfSAMLMessage(wssMessage);
				return xmlHelpers.getAssertions(document).getLength() != 0
						|| xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
			} catch (SAXException e) {
				e.printStackTrace();
				return false;
			}
		}
		else {
			isWSSMessage = false;
			isSOAPMessage = false;
			return (null != helpers.getRequestParameter(content, "SAMLResponse"));
		}
		return false;
	}

	@Override
	public boolean isModified() {
		return edited;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		resetInfoMessageText();
		edited = false;
		if (content == null) {
			textArea.setText(null);
			textArea.setEditable(false);
			setGUIEditable(false);
			resetInformationDisplay();
		} else {
			message = content;
			try {
				if (isSOAPMessage) {
					IResponseInfo responseInfo = helpers.analyzeResponse(content);
					int bodyOffset = responseInfo.getBodyOffset();
					String soapMessage = new String(content, bodyOffset, content.length - bodyOffset, "UTF-8");
					Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
					Document documentSAML = xmlHelpers.getSAMLResponseOfSOAP(document);
					SAMLMessage = xmlHelpers.getStringOfDocument(documentSAML, 0, false);
				} 
				else if(isWSSMessage){
					IParameter parameter = helpers.getRequestParameter(content, "wresult");
					SAMLMessage = getDecodedSAMLMessage(parameter.getValue());
				}
				else {
					IParameter parameter = helpers.getRequestParameter(content, "SAMLResponse");
					SAMLMessage = getDecodedSAMLMessage(parameter.getValue());
				}
				Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage);
				SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
			} catch (IOException e) {
				e.printStackTrace();
				setInfoMessageText(XML_COULD_NOT_SERIALIZE);
			} catch (SAXException e) {
				e.printStackTrace();
				setInfoMessageText(XML_NOT_WELL_FORMED);
				SAMLMessage = "<error>" + XML_NOT_WELL_FORMED + "</error>";
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
			}
			
			setInformationDisplay();
			updateCertificateList();
			updateXSWList();
			orgSAMLMessage = SAMLMessage;
			textArea.setText(SAMLMessage);
			textArea.setEditable(editable);
			setGUIEditable(editable);
		}
	}

	private void setInformationDisplay() {
		SamlPanelInfo infoPanel = samlGUI.getInfoPanel();

		try {
			Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage);
			NodeList assertions = xmlHelpers.getAssertions(document);
			if (assertions.getLength() > 0) {
				Node assertion = assertions.item(0);
				infoPanel.setIssuer(xmlHelpers.getIssuer(document));
				infoPanel.setConditionNotBefore(xmlHelpers.getConditionNotBefore(assertion));
				infoPanel.setConditionNotAfter(xmlHelpers.getConditionNotAfter(assertion));
				infoPanel.setSubjectConfNotBefore(xmlHelpers.getSubjectConfNotBefore(assertion));
				infoPanel.setSubjectConfNotAfter(xmlHelpers.getSubjectConfNotAfter(assertion));
				infoPanel.setSignatureAlgorithm(xmlHelpers.getSignatureAlgorithm(assertion));
				infoPanel.setDigestAlgorithm(xmlHelpers.getDigestAlgorithm(assertion));
			} else {
				assertions = xmlHelpers.getEncryptedAssertions(document);
				Node assertion = assertions.item(0);
				infoPanel.setEncryptionAlgorithm(xmlHelpers.getEncryptionMethod(assertion));
			}
		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		}
	}

	private void resetInformationDisplay() {
		SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
		infoPanel.setIssuer("");
		infoPanel.setConditionNotBefore("");
		infoPanel.setConditionNotAfter("");
		infoPanel.setSubjectConfNotBefore("");
		infoPanel.setSubjectConfNotAfter("");
		infoPanel.setSignatureAlgorithm("");
		infoPanel.setDigestAlgorithm("");
		infoPanel.setEncryptionAlgorithm("");
	}

	public String getEncodedSAMLMessage(String message) {
		byte[] byteMessage;
		try {
			if(isWSSMessage){
				if(isWSSUrlEncoded){
					return URLEncoder.encode(message, "UTF-8");
				}
				else{
					return message;
				}
			}
			byteMessage = message.getBytes("UTF-8");
			if (isInflated) {
				try {
					byteMessage = httpHelpers.compress(byteMessage, isGZip);
				} catch (IOException e) {
				}
			}
			String base64Encoded = helpers.base64Encode(byteMessage);
			return URLEncoder.encode(base64Encoded, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
		}
		return null;
	}

	public String getDecodedSAMLMessage(String message) {
		
		if(isWSSMessage){
			if(isWSSUrlEncoded){
				return helpers.urlDecode(message);
			}
			else{
				return message;
			}
		}
		
		String urlDecoded = helpers.urlDecode(message);
		byte[] base64Decoded = helpers.base64Decode(urlDecoded);
		
		isInflated = true;
		isGZip = true;
		
		// try normal Zip Inflate
		try {
			byte[] inflated = httpHelpers.decompress(base64Decoded, true);
			return new String(inflated, "UTF-8");
		} catch (IOException e) {
		} catch (DataFormatException e) {
			isGZip = false;
		}
		
		//try Gzip Inflate
		try {
			byte[] inflated = httpHelpers.decompress(base64Decoded, false);
			return new String(inflated, "UTF-8");
		} catch (IOException e) {
		} catch (DataFormatException e) {
			isInflated = false;
		}

		try {
			return new String(base64Decoded, "UTF-8");
		} catch (UnsupportedEncodingException e) {
		}
		return null;
	}

	public void removeSignature() {
		resetInfoMessageText();
		try {
			Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
			if (xmlHelpers.removeAllSignatures(document) > 0) {
				SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
				textArea.setText(SAMLMessage);
				edited = true;
				setInfoMessageText("Message signature successful removed");
			} else {
				setInfoMessageText("No Signatures available to remove");
			}
		} catch (SAXException e1) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		} catch (IOException e) {
			setInfoMessageText(XML_COULD_NOT_SERIALIZE);
		}
	}


	public void resetMessage() {
		SAMLMessage = orgSAMLMessage;
		textArea.setText(SAMLMessage);
		edited = false;
	}

	public void resignAssertion() {
		try {
			resetInfoMessageText();
			BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
			if (cert != null) {
				setInfoMessageText("Signing...");
				Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
				NodeList assertions = xmlHelpers.getAssertions(document);
				String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
				String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

				xmlHelpers.removeAllSignatures(document);
				String string = xmlHelpers.getString(document);
				Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
				xmlHelpers.removeEmptyTags(doc);
				xmlHelpers.signAssertion(doc, signAlgorithm, digestAlgorithm, cert.getCertificate(),
						cert.getPrivateKey());
				SAMLMessage = xmlHelpers.getStringOfDocument(doc, 2, true);
				textArea.setText(SAMLMessage);
				edited = true;
				setInfoMessageText("Assertions successfully signed");
			} else {
				setInfoMessageText("no certificate chosen to sign");
			}
		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		} catch (IOException e) {
			setInfoMessageText(XML_COULD_NOT_SERIALIZE);
		} catch (Exception e) {
			setInfoMessageText(XML_COULD_NOT_SIGN);
		}
	}

	public void resignMessage() {
		try {
			resetInfoMessageText();
			if(isWSSMessage){
				setInfoMessageText("Message signing is not possible with WS-Security messages");
			}
			else{
				setInfoMessageText("Signing...");
				BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
				if (cert != null) {
					Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
					NodeList responses = xmlHelpers.getResponse(document);
					String signAlgorithm = xmlHelpers.getSignatureAlgorithm(responses.item(0));
					String digestAlgorithm = xmlHelpers.getDigestAlgorithm(responses.item(0));
	
					xmlHelpers.removeOnlyMessageSignature(document);
					xmlHelpers.signMessage(document, signAlgorithm, digestAlgorithm, cert.getCertificate(),
							cert.getPrivateKey());
					SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
					textArea.setText(SAMLMessage);
					edited = true;
					setInfoMessageText("Message successfully signed");
				} else {
					setInfoMessageText("no certificate chosen to sign");
				}
			}
		} catch (IOException e) {
			setInfoMessageText(XML_COULD_NOT_SERIALIZE);
		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		} catch (CertificateException e) {
			setInfoMessageText(XML_COULD_NOT_SIGN);
		} catch (NoSuchAlgorithmException e) {
			setInfoMessageText(XML_COULD_NOT_SIGN + ", no such algorithm");
		} catch (InvalidKeySpecException e) {
			setInfoMessageText(XML_COULD_NOT_SIGN + ", invalid private key");
		} catch (MarshalException e) {
			setInfoMessageText(XML_COULD_NOT_SERIALIZE);
		} catch (XMLSignatureException e) {
			setInfoMessageText(XML_COULD_NOT_SIGN);
		}
	}

	private void setInfoMessageText(String infoMessage) {
		samlGUI.getActionPanel().getInfoMessageLabel().setText(infoMessage);
	}

	private void resetInfoMessageText() {
		samlGUI.getActionPanel().getInfoMessageLabel().setText("");
	}

	private void updateCertificateList() {
		List<BurpCertificate> list = certificateTabController.getCertificatesWithPrivateKey();
		samlGUI.getActionPanel().setCertificateList(list);
	}

	private void updateXSWList() {
		samlGUI.getActionPanel().setXSWList(XSWHelpers.xswTypes);
	}

	public void sendToCertificatesTab() {
		try {
			Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
			String cert = xmlHelpers.getCertificate(document.getDocumentElement());
			if (cert != null) {
				certificateTabController.importCertificateFromString(cert);
			} else {
				setInfoMessageText(XML_CERTIFICATE_NOT_FOUND);
			}
		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		}
	}

	public void showXSWPreview() {
		try {
			Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
			xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
			String after = xmlHelpers.getStringOfDocument(document, 2, true);
			String diff = xswHelpers.diffLineMode(orgSAMLMessage, after);

			File file = File.createTempFile("tmp", ".html", null);
			FileOutputStream fileOutputStream = new FileOutputStream(file);
			file.deleteOnExit();
			fileOutputStream.write(diff.getBytes("UTF-8"));
			fileOutputStream.flush();
			fileOutputStream.close();

			URI uri = new URL("file://" + file.getAbsolutePath()).toURI();

			Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
			if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
				desktop.browse(uri);
			} else {
				StringSelection stringSelection = new StringSelection(uri.toString());
				Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
				clpbrd.setContents(stringSelection, null);
				setInfoMessageText(NO_BROWSER);
			}

		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		} catch (DOMException e) {
			setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
		} catch (MalformedURLException e) {
		} catch (URISyntaxException e) {
		} catch (IOException e) {
			setInfoMessageText(NO_DIFF_TEMP_FILE);
		}
	}

	public void applyXSW() {
		Document document;
		try {
			document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
			xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
			SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
			textArea.setText(SAMLMessage);
			edited = true;
			setInfoMessageText(XSW_ATTACK_APPLIED);
		} catch (SAXException e) {
			setInfoMessageText(XML_NOT_WELL_FORMED);
		} catch (IOException e) {
			setInfoMessageText(XML_COULD_NOT_SERIALIZE);
		} catch (DOMException | NullPointerException e) {
			setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
		}
	}

	public void setGUIEditable(boolean editable) {
		if (editable) {
			samlGUI.getActionPanel().enableControls();
		} else {
			samlGUI.getActionPanel().disableControls();
		}
	}
	
	public void searchInTextarea(){
		String text = samlGUI.getActionPanel().getSearchText();
		SearchContext context = new SearchContext();
		context.setMatchCase(false);
		context.setMarkAll(true);
		context.setSearchFor(text);
		context.setWholeWord(false);
		SearchResult result = SearchEngine.find(textArea, context);
		if (!result.wasFound()) {
			textArea.setCaretPosition(0);
			SearchEngine.find(textArea, context);
		}
	}
	
	public void showSignatureHelp() {
		SignatureHelpWindow window = new SignatureHelpWindow();
		window.setVisible(true);
	}

	public void showXSWHelp() {
		XSWHelpWindow window = new XSWHelpWindow();
		window.setVisible(true);
	}

	@Override
	public void update(Observable arg0, Object arg1) {
		updateCertificateList();
	}
}
