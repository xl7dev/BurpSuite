package burp;


import java.awt.Component;

import org.apache.jmeter.protocol.amf.util.AmfXmlConverter;

import burp.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
    private IBurpExtenderCallbacks m_callbacks;
    private IExtensionHelpers m_helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.m_callbacks = callbacks;
        
        // obtain an extension helpers object
        m_helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("AMF Deserializer");
        
        // register ourselves as a message editor tab factory
        AMFTabFactory factory = new AMFTabFactory(m_callbacks, m_helpers);

        callbacks.registerMessageEditorTabFactory(factory);
        
        callbacks.registerContextMenuFactory(new AMFMenu(callbacks));
        
        callbacks.registerHttpListener(new AMFHttpListener());
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new AMFDeserializerTab(controller, editable, m_callbacks, m_helpers);
    }

    //
    // class implementing IMessageEditorTab
    //

   
}
