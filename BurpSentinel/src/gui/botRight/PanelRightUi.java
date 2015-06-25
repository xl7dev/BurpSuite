/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package gui.botRight;

import gui.SentinelMainApi;
import gui.comparer.ComparerWindow;
import gui.mainBot.PanelBotUi;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.LinkedList;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import util.BurpCallbacks;
import util.SettingsManager;

/**
 *
 * @author unreal
 */
public class PanelRightUi extends javax.swing.JPanel {

    private PanelBotUi panelParent;
    private PanelRightModel panelRightModel;
    private int currentSelectedRow = -1;
    private PopupTableHeader popupTableHeader;
    
    private PanelRightPopup panelRightPopup;
    private PanelRightPopupMultiple panelRightPopupMultiple;
    
    /**
     * Creates new form PanelRightUi
     */
    public PanelRightUi() {
        panelRightModel = new PanelRightModel(this);
        initComponents();

        int width = 60;
        tableMessages.getColumnModel().getColumn(0).setMaxWidth(40);
        tableMessages.getColumnModel().getColumn(0).setMinWidth(40);
        
        tableMessages.getColumnModel().getColumn(1).setMaxWidth(60);
        tableMessages.getColumnModel().getColumn(1).setMinWidth(60);
        
        tableMessages.getColumnModel().getColumn(5).setMaxWidth(width);
        tableMessages.getColumnModel().getColumn(5).setMinWidth(width);
        
        tableMessages.getColumnModel().getColumn(6).setMaxWidth(width);
        tableMessages.getColumnModel().getColumn(6).setMinWidth(width);
        
        tableMessages.getColumnModel().getColumn(7).setMaxWidth(width);
        tableMessages.getColumnModel().getColumn(7).setMinWidth(width);
        
        tableMessages.getColumnModel().getColumn(8).setMaxWidth(width);
        tableMessages.getColumnModel().getColumn(8).setMinWidth(width);
        
        tableMessages.getColumnModel().getColumn(9).setMaxWidth(width);
        tableMessages.getColumnModel().getColumn(9).setMinWidth(width);

        tableMessages.getColumnModel().getColumn(10).setMaxWidth(20);
        tableMessages.getColumnModel().getColumn(10).setMinWidth(20);
        
        //tableMessages.getColumnModel().getColumn(11).setMaxWidth(80);
        //tableMessages.getColumnModel().getColumn(11).setMinWidth(80);
        
        
        tableMessages.setAutoCreateRowSorter(true);

        SettingsManager.restoreTableDimensions(tableMessages, this);
        SettingsManager.restoreSplitLocation(jSplitPane1, this);
        
        ListSelectionModel lsm = tableMessages.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener() {
            @Override
                public void valueChanged(ListSelectionEvent e) {
                    //Ignore extra messages.
                    if (e.getValueIsAdjusting()) return;
 
                    ListSelectionModel lsm = (ListSelectionModel)e.getSource();
                    if (lsm.isSelectionEmpty()) {
                       //
                    } else {
                        int oldSelectedRow = currentSelectedRow;
                        currentSelectedRow = lsm.getMinSelectionIndex();
                        // Only update if differ
                        if (oldSelectedRow != currentSelectedRow) {
                            viewHttpMessage(currentSelectedRow);
                            tableMessages.getSelectionModel().setSelectionInterval(currentSelectedRow, currentSelectedRow);
                        }
                    }
                }});
 
        popupTableHeader = new PopupTableHeader(tableMessages);
        tableMessages.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupTableHeader.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        
        
        panelRightPopup = new PanelRightPopup(this);
        panelRightPopupMultiple = new PanelRightPopupMultiple(this);
        
        // Add mouse listener for on-row popup menu
        tableMessages.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (panelRightPopup.getPopup().isPopupTrigger(e)) {
                    JTable source = (JTable) e.getSource();
                    int row = source.rowAtPoint(e.getPoint());
                    currentSelectedRow = row;
                    int column = source.columnAtPoint(e.getPoint());
                    
                    // Check if only one is selected
                    ListSelectionModel lsm = tableMessages.getSelectionModel();
                    if (lsm.getMinSelectionIndex() == lsm.getMaxSelectionIndex()) {
                        if (!source.isRowSelected(row)) {
                            source.changeSelection(row, column, false, false);
                        }
                        panelRightPopup.getPopup().show(e.getComponent(), e.getX(), e.getY());
                    } else {
                        panelRightPopupMultiple.getPopup().show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });    
    }
    
    public void setSelected(int index) {
        currentSelectedRow = index;
        viewHttpMessage(currentSelectedRow);
    }
    
    public int getSelected() {
        return currentSelectedRow;
    }
    
    
    private TableModel getMessageTableModel() {
      return panelRightModel;
    }
    
    /*
     *  Add Attack Message
     * 
     *  Generated by NetworkerWorker, called from PanelBotUi by PanelLeftUi
     */
    public void addHttpMessage(SentinelHttpMessageAtk httpMessage) {
        panelRightModel.addMessage(httpMessage);

        // Show very first message upon adding
        // But not every new message following after that
        if (currentSelectedRow == -1) {
            currentSelectedRow = 0;
            viewHttpMessage(currentSelectedRow);
        }
        
        // When adding to tableMessage, currently selected message will be
        // deselected. aquire it and select it again.
        tableMessages.getSelectionModel().setSelectionInterval(currentSelectedRow, currentSelectedRow);
        
        // It seems that the following line is not necessary
        //tableMessages.scrollRectToVisible(tableMessages.getCellRect(panelRightModel.getRowCount() - 1, 0, true));
    }
    
    
    /*
     * Add Original Message
     * 
     * Sometimes, like when restoring state from file, the original http message
     * already has attack messages. If so, they will be added here.
     */
    public void setMessage(SentinelHttpMessageOrig httpMessage) {
        for(SentinelHttpMessageAtk messageAtk: httpMessage.getHttpMessageChildren()) {
            panelRightModel.addMessage(messageAtk);
        }
    }
    
    public void viewHttpMessage(int n) {
        try {
            SentinelHttpMessageAtk atkMsg = panelRightModel.getHttpMessage(n);
            panelViewMessage.setHttpMessage(atkMsg);
            
            // Set parent as httpmessage reference for diff
            panelViewMessage.setBuddy( atkMsg.getParentHttpMessage() );
        } catch (Exception ex) {
            BurpCallbacks.getInstance().print(ex.getLocalizedMessage());
        }
    }
    
    
    public void setPanelParent(PanelBotUi aThis) {
        this.panelParent = aThis;
        panelViewMessage.setLinkManager(panelParent.getLinkManager());
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSplitPane1 = new javax.swing.JSplitPane();
        panelTop = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        tableMessages = new PanelRightCustomTable(panelRightModel);
        panelBot = new javax.swing.JPanel();
        panelViewMessage = new gui.viewMessage.PanelViewMessageUi();

        jSplitPane1.setDividerLocation(200);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        tableMessages.setModel(getMessageTableModel());
        tableMessages.setRowHeight(20);
        tableMessages.setSelectionBackground(new java.awt.Color(255, 205, 129));
        tableMessages.setSelectionForeground(new java.awt.Color(0, 0, 0));
        jScrollPane2.setViewportView(tableMessages);

        javax.swing.GroupLayout panelTopLayout = new javax.swing.GroupLayout(panelTop);
        panelTop.setLayout(panelTopLayout);
        panelTopLayout.setHorizontalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 622, Short.MAX_VALUE)
        );
        panelTopLayout.setVerticalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 199, Short.MAX_VALUE)
        );

        jSplitPane1.setTopComponent(panelTop);

        javax.swing.GroupLayout panelBotLayout = new javax.swing.GroupLayout(panelBot);
        panelBot.setLayout(panelBotLayout);
        panelBotLayout.setHorizontalGroup(
            panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 622, Short.MAX_VALUE)
            .addGroup(panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(panelViewMessage, javax.swing.GroupLayout.DEFAULT_SIZE, 622, Short.MAX_VALUE))
        );
        panelBotLayout.setVerticalGroup(
            panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 221, Short.MAX_VALUE)
            .addGroup(panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(panelViewMessage, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE))
        );

        jSplitPane1.setRightComponent(panelBot);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.Alignment.TRAILING)
        );
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JPanel panelBot;
    private javax.swing.JPanel panelTop;
    private gui.viewMessage.PanelViewMessageUi panelViewMessage;
    private javax.swing.JTable tableMessages;
    // End of variables declaration//GEN-END:variables

    public void storeUiPrefs() {
        SettingsManager.storeSplitLocation(jSplitPane1, this);
        SettingsManager.storeTableDimensions(tableMessages, this);
    }
    
    public LinkedList<SentinelHttpMessageAtk> getAttackMessage() {
        return panelRightModel.getAllAttackMessages();
    }

    /*** Functions for children ***/
    /*
    public void c_sendAgain() {
        BurpCallbacks.getInstance().sendRessource(, true, this);
    }*/
    
    public void c_sendToRepeater() {
        BurpCallbacks.getInstance().sendToRepeater(panelRightModel.getHttpMessage(currentSelectedRow));
    }
    
    public void c_copySmart() {
        SentinelHttpMessage httpMessage;
        
        httpMessage = panelRightModel.getHttpMessage(currentSelectedRow);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

        StringSelection ss = new StringSelection(ClipboardCopyHelpers.copySmart(httpMessage));
        clipboard.setContents(ss, null);
    }

    void c_compare() {
        ListSelectionModel lsm = tableMessages.getSelectionModel();
        
        int first = lsm.getMinSelectionIndex();
        int second = lsm.getMaxSelectionIndex();
        
        BurpCallbacks.getInstance().print("Compare: " + first + " " + second);
        ComparerWindow comparer = new ComparerWindow();
        comparer.setMessages( panelRightModel.getHttpMessage(first), panelRightModel.getHttpMessage(second));
        comparer.setVisible(true);
    }

    void c_sendToSentinel() {
            SentinelMainApi.getInstance().addNewMessage(panelRightModel.getHttpMessage(currentSelectedRow));
    }

    
}
