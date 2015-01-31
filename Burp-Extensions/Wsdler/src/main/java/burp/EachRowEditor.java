package burp;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.EventObject;
import java.util.Hashtable;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.table.TableCellEditor;

class EachRowEditor implements TableCellEditor {

  protected Hashtable editors;
  protected TableCellEditor editor, defaultEditor;
  JTable table;

  /**
   * Constructs a EachRowEditor. create default editor
   *
   * @see javax.swing.table.TableCellEditor
   * @see javax.swing.DefaultCellEditor
   */
  public EachRowEditor(JTable table) {
    this.table = table;
    editors = new Hashtable();
    defaultEditor = new DefaultCellEditor(new JComboBox());
  }

  /**
   * @param row    table row
   * @param editor table cell editor
   */
  public void setEditorAt(int row, TableCellEditor editor) {
    editors.put(row, editor);
  }

  public Component getTableCellEditorComponent(JTable table, Object value,
                                               boolean isSelected, int row, int column) {

    //editor = (TableCellEditor)editors.get(new Integer(row));
    //if (editor == null) {
    //  editor = defaultEditor;
    //}
    return editor.getTableCellEditorComponent(table, value, isSelected,
                                              row, column);
  }


  public Object getCellEditorValue() {
    return editor.getCellEditorValue();
  }

  public boolean stopCellEditing() {
    return editor.stopCellEditing();
  }

  public void cancelCellEditing() {
    editor.cancelCellEditing();
  }

  public boolean isCellEditable(EventObject anEvent) {
    selectEditor((MouseEvent) anEvent);
    return editor.isCellEditable(anEvent);
  }

  public void addCellEditorListener(CellEditorListener l) {
    editor.addCellEditorListener(l);
  }

  public void removeCellEditorListener(CellEditorListener l) {
    editor.removeCellEditorListener(l);
  }

  public boolean shouldSelectCell(EventObject anEvent) {
    selectEditor((MouseEvent) anEvent);
    return editor.shouldSelectCell(anEvent);
  }

  protected void selectEditor(MouseEvent e) {
    int row;
    if (e == null) {
      row = table.getSelectionModel().getAnchorSelectionIndex();
    } else {
      row = table.rowAtPoint(e.getPoint());
    }
    editor = (TableCellEditor) editors.get(new Integer(row));
    if (editor == null) {
      editor = defaultEditor;
    }
  }
}
