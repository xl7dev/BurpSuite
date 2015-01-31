package burp;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

public class WSDLMenu implements IContextMenuFactory {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  private WSDLParserTab tab;

  public WSDLMenu(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    helpers = callbacks.getHelpers();
    tab = new WSDLParserTab(callbacks);
  }

  public List<JMenuItem> createMenuItems(
      final IContextMenuInvocation invocation) {
    List<JMenuItem> list;
    list = new ArrayList<JMenuItem>();
    JMenuItem item = new JMenuItem("Parse WSDL");

    item.addMouseListener(new MouseListener() {
      @Override
      public void mouseClicked(MouseEvent e) {

      }
      @Override
      public void mousePressed(MouseEvent e) {
        WSDLParser parser = new WSDLParser(callbacks, helpers, tab);
        parser.parseWSDL(invocation.getSelectedMessages()[0]);
      }

      @Override
      public void mouseReleased(MouseEvent e) {

      }

      @Override
      public void mouseEntered(MouseEvent e) {

      }

      @Override
      public void mouseExited(MouseEvent e) {

      }
    });
    list.add(item);

    return list;
  }

}
