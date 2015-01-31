package burp;

public class BurpExtender implements IBurpExtender {


  @Override
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

    callbacks.registerContextMenuFactory(new WSDLMenu(callbacks));
  }
}
