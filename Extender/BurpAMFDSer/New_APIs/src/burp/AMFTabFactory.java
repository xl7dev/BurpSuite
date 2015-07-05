package burp;

public class AMFTabFactory implements IMessageEditorTabFactory {
	private IBurpExtenderCallbacks m_callbacks;
	private IExtensionHelpers m_helpers;

	public AMFTabFactory(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		m_callbacks = callbacks;
		m_helpers = helpers;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		AMFDeserializerTab amfDeserializerTab = new AMFDeserializerTab(controller, editable, m_callbacks, m_helpers);
		return amfDeserializerTab;
	}

}
