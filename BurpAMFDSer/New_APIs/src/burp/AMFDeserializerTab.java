package burp;
import java.awt.Color;
import java.awt.Component;

import javax.swing.plaf.basic.BasicTabbedPaneUI;

import org.apache.jmeter.protocol.amf.util.AmfXmlConverter;

import burp.*;

 class AMFDeserializerTab implements IMessageEditorTab
 {
	private boolean editable;
	private ITextEditor txtInput;
	private byte[] currentMessage;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	public AMFDeserializerTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks2, IExtensionHelpers helpers2) {
		this.editable = editable;
		callbacks = callbacks2;
		helpers = helpers2;
		// create an instance of Burp's text editor, to display our deserialized
		// data
		txtInput = callbacks.createTextEditor();
		txtInput.setEditable(editable);
	}

	//
	// implement IMessageEditorTab
	//

	@Override
	public String getTabCaption() {
		return "AMF Deserialized";
	}

	@Override
	public Component getUiComponent() {
		return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		// enable this tab for requests containing a data parameter

		return true;
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (content == null) {
			// clear our display
			txtInput.setText(null);
			txtInput.setEditable(false);
		} else {
			// retrieve the data parameter
			IParameter parameter = helpers.getRequestParameter(content, "data");

			// deserialize the parameter value
			txtInput.setText((AmfXmlConverter.convertAmfMessageToXml(AMFUtilities.getBody(content), true)).getBytes());
			txtInput.setEditable(editable);
		}

		// remember the displayed content
		currentMessage = content;
	}

	@Override
	public byte[] getMessage() {
		// determine whether the user modified the deserialized data
		if (txtInput.isTextModified()) {
			// reserialize the data
			return AMFUtilities.serializeProxyItem(currentMessage, txtInput.getText());
			// helpers.buildParameter("data", input, IParameter.PARAM_BODY));
		} else
			return currentMessage;
	}

	@Override
	public boolean isModified() {
		return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
		return txtInput.getSelectedText();
	}
}