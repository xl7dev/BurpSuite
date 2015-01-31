package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class WSDLTab extends AbstractTableModel implements IMessageEditorController {

  private final List<WSDLEntry> entries = new ArrayList<WSDLEntry>();
  public WSDLTable wsdlTable;
  public EachRowEditor rowEditor = new EachRowEditor(wsdlTable);
  private IMessageEditor requestViewer;
  private IHttpRequestResponse currentlyDisplayedItem;

  public WSDLTab(final IBurpExtenderCallbacks callbacks, JTabbedPane tabbedPane) {
    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    wsdlTable = new WSDLTable(WSDLTab.this);
    rowEditor = new EachRowEditor(wsdlTable);
    JScrollPane scrollPane = new JScrollPane(wsdlTable);

    splitPane.setLeftComponent(scrollPane);

    JTabbedPane tabs = new JTabbedPane();
    requestViewer = callbacks.createMessageEditor(WSDLTab.this, false);
    tabs.addTab("Request", requestViewer.getComponent());
    splitPane.setResizeWeight(0.5);
    splitPane.setTopComponent(scrollPane);
    splitPane.setBottomComponent(tabs);
    tabbedPane.add(Integer.toString(WSDLParserTab.tabCount), splitPane);
    tabbedPane.setTabComponentAt(WSDLParserTab.tabCount - WSDLParserTab.removedTabCount, new ButtonTabComponent(tabbedPane));

  }

  public void addEntry(WSDLEntry entry) {
    synchronized (entries) {
      int row = entries.size();
      entries.add(entry);
      fireTableRowsInserted(row, row);
      //create combobox if there are more than one service URLs.
      //not really needed anymore.
    /*  if (entry.endpoints.size() > 1) {
        JComboBox<String> combo = createComboBox(entry);
        rowEditor.setEditorAt(row, new DefaultCellEditor(combo));
        wsdlTable.getColumnModel().getColumn(2).setCellEditor(rowEditor);
      }*/
    }
  }

  @Override
  public int getRowCount() {
    return entries.size();
  }

  @Override
  public int getColumnCount() {
    return 3;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "Binding";
      case 1:
        return "Operation";
      case 2:
        return "Port";
      default:
        return "";
    }
  }

  @Override
  public Class getColumnClass(int columnIndex) {
    return getValueAt(0, columnIndex).getClass();
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    WSDLEntry wsdlEntry = entries.get(rowIndex);

    switch (columnIndex) {
      case 0:
        return wsdlEntry.bindingName;
      case 1:
        return wsdlEntry.operationName;
      case 2:
        return wsdlEntry.endpoints.get(0);
      default:
        return "";
    }
  }

  public boolean isCellEditable(int row, int col) {
    return col >= 2;
  }

  @Override
  public byte[] getRequest() {
    return currentlyDisplayedItem.getRequest();
  }

  @Override
  public byte[] getResponse() {
    return currentlyDisplayedItem.getResponse();
  }

  @Override
  public IHttpService getHttpService() {
    return currentlyDisplayedItem.getHttpService();
  }

  private class WSDLTable extends JTable {

    public WSDLTable(TableModel tableModel) {
      super(tableModel);

    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {

      WSDLEntry wsdlEntry = entries.get(row);
      requestViewer.setMessage(wsdlEntry.request, true);
      currentlyDisplayedItem = wsdlEntry.requestResponse;
      super.changeSelection(row, col, toggle, extend);
    }
  }
}
