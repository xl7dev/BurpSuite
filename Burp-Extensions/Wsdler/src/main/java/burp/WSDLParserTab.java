package burp;

import java.awt.*;

import javax.swing.*;

public class WSDLParserTab implements ITab {

  JTabbedPane tabs;
  private IBurpExtenderCallbacks callbacks;
  static int tabCount = 0;
  static int removedTabCount = 0;

  public WSDLParserTab(final IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    callbacks.setExtensionName("WSDL Parser");

    tabs = new JTabbedPane();

    callbacks.customizeUiComponent(tabs);

    callbacks.addSuiteTab(WSDLParserTab.this);

  }

  public WSDLTab createTab() {
    WSDLTab wsdltab = new WSDLTab((callbacks), tabs);
    tabCount++;
    //tabs.addTab("test",tabs);

    return wsdltab;
  }

  @Override
  public String getTabCaption() {
    return "Wsdler";
  }

  @Override
  public Component getUiComponent() {
    return tabs;
  }
}
