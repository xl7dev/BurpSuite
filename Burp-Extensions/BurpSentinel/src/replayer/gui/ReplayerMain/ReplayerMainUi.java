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
package replayer.gui.ReplayerMain;

import burp.IHttpRequestResponse;
import burp.ITab;
import gui.viewMessage.ViewMessageLinkManager;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageOrig;
import util.BurpCallbacks;

/**
 *
 * @author unreal
 */
public class ReplayerMainUi extends javax.swing.JPanel implements ITab {

    private int currentSelectedRow = 0;
    private ReplayerMainTableModel tableModel;
    private boolean virgin = true;
    private ReplayerMainPopup popup;
    private ViewMessageLinkManager linkManager;
    //private SentinelHttpMessage origHttpMessage;
    
    private MainMessageEditorController rightRequestMessageEditorController;
    private burp.IMessageEditor rightRequestMessageEditor;
    
    private MainMessageEditorController leftRequestMessageEditorController;
    private burp.IMessageEditor leftRequestMessageEditor;
    
    /**
     * Creates new form ReplayerMainUi
     */
    public ReplayerMainUi() {
        linkManager = new ViewMessageLinkManager();
        tableModel = new ReplayerMainTableModel();
        initComponents();
        jSplitPane1.setDividerLocation(0.5f);
        
//        panelViewMessageUiLeft.setLinkManager(linkManager);
//        panelViewMessageUiRight.setLinkManager(linkManager);
//        panelViewMessageUiLeft.setRequestEditor(true);
                
        popup = new ReplayerMainPopup(this);
        
        rightRequestMessageEditorController = new MainMessageEditorController(new SentinelHttpMessageOrig("GET / HTTP/1.1\r\nHost: www.dobin.ch\r\n\r\n", "www.dobin.ch", 80, false));
        rightRequestMessageEditor = BurpCallbacks.getInstance().getBurp().createMessageEditor(rightRequestMessageEditorController, true);
        panelRightRequest.add(rightRequestMessageEditor.getComponent(), BorderLayout.CENTER);
        panelRightRequest.invalidate();
        panelRightRequest.updateUI();
        
        leftRequestMessageEditorController = new MainMessageEditorController(new SentinelHttpMessageOrig("GET / HTTP/1.1\r\nHost: www.dobin.ch\r\n\r\n", "www.dobin.ch", 80, false));
        leftRequestMessageEditor = BurpCallbacks.getInstance().getBurp().createMessageEditor(leftRequestMessageEditorController, true);
        panelLeftRequest.add(leftRequestMessageEditor.getComponent(), BorderLayout.CENTER);
        panelLeftRequest.invalidate();
        panelLeftRequest.updateUI();
        
        
        jTable1.getColumnModel().getColumn(0).setMaxWidth(40);
        jTable1.getColumnModel().getColumn(0).setMinWidth(40);
        
        jTable1.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (popup.getPopup().isPopupTrigger(e)) {
                    JTable source = (JTable) e.getSource();
                    int row = source.rowAtPoint(e.getPoint());
                    int column = source.columnAtPoint(e.getPoint());

                    if (!source.isRowSelected(row)) {
                        source.changeSelection(row, column, false, false);
                    }

                    popup.getPopup().show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        // Add selection listener
        ListSelectionModel lsm = jTable1.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                //Ignore extra messages.
                if (e.getValueIsAdjusting()) {
                    return;
                }

                ListSelectionModel lsm = (ListSelectionModel) e.getSource();
                if (lsm.isSelectionEmpty()) {
                    //
                } else {
                    // Get selected row and tell the main frame to show it 
                    // in the bottom frame
                    currentSelectedRow = lsm.getMinSelectionIndex();
                    viewMessage(currentSelectedRow);
                }
            }
        });
    }

    
    private TableModel getTableModel() {
        return tableModel;
    }
    
    public void addNewMessage(IHttpRequestResponse iHttpRequestResponse) {
        SentinelHttpMessage origHttpMessage = new SentinelHttpMessageOrig(iHttpRequestResponse);

        // Add to table
        tableModel.addHttpMessage(origHttpMessage);

        setOrigMessage(0);
        viewMessage(0);
    }

    void setSelectedMessageAsOriginal() {
        int selected = jTable1.getSelectedRow();
        
        setOrigMessage(selected);
        
        //BurpCallbacks.getInstance().print("Selected: " + jTable1.getSelectedRow());
    }
    
    private int messageOrigIndex = -1;
    private int messageCurrentIndex = -1;
    
    private void setOrigMessage(int n) {
        messageOrigIndex = n;
        
        SentinelHttpMessage m = tableModel.getHttpMessage(n);
        
        // Set as main (initially)
//        panelViewMessageUiRight.setHttpMessage(m);
        rightRequestMessageEditor.setMessage(m.getRequest(), true);
    }
    
    private void viewMessage(int index) {
        messageCurrentIndex = index;
        SentinelHttpMessage m = tableModel.getMessage(index);
        
        leftRequestMessageEditor.setMessage(m.getRequest(), true);
//        panelViewMessageUiLeft.setShowResponse(true);
//        panelViewMessageUiLeft.setHttpMessage(m);
        jTable1.getSelectionModel().setSelectionInterval(index, index);
        this.currentSelectedRow = index;
        this.updateUI();
    }
    
    private void sendMessage() {
        //String s = panelViewMessageUiLeft.getRequestContent();
        SentinelHttpMessage origHttpMessage = tableModel.getHttpMessage(0);
        String s = BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(leftRequestMessageEditor.getMessage());
        
        if (s != null) {
            //SentinelHttpMessage newMessage = new SentinelHttpMessage(s, origHttpMessage.getHttpService());
//            SentinelHttpMessage newMessage = new SentinelHttpMessageAtk(s,
//                    origHttpMessage.getHttpService().getHost(),
//                    origHttpMessage.getHttpService().getPort(),
//                    origHttpMessage.getHttpService().getProtocol().toLowerCase().equals("https") ? true : false);
            //newMessage.setParentHttpMessage(origHttpMessage);
            
 //           BurpCallbacks.getInstance().sendRessource(newMessage, true);
            
 //           tableModel.addHttpMessage(newMessage);
            
            viewLastMessage();
            this.updateUI();
        } else {
            BurpCallbacks.getInstance().print("No request");
        }
    }

    
    private void viewLastMessage() {
        viewMessage(tableModel.getMessageCount()-1);
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        panelLeft = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        panelRight = new javax.swing.JPanel();
        jSplitPane1 = new javax.swing.JSplitPane();
        panelMsgOne = new javax.swing.JPanel();
        jSplitPane2 = new javax.swing.JSplitPane();
        jPanel3 = new javax.swing.JPanel();
        jPanel1 = new javax.swing.JPanel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        panelLeftRequest = new javax.swing.JPanel();
        jSplitPane3 = new javax.swing.JSplitPane();
        jPanel5 = new javax.swing.JPanel();
        jPanel7 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jButton6 = new javax.swing.JButton();
        panelRightRequest = new javax.swing.JPanel();
        panelRightResponse = new javax.swing.JPanel();

        jTable1.setModel(getTableModel());
        jScrollPane1.setViewportView(jTable1);

        javax.swing.GroupLayout panelLeftLayout = new javax.swing.GroupLayout(panelLeft);
        panelLeft.setLayout(panelLeftLayout);
        panelLeftLayout.setHorizontalGroup(
            panelLeftLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        panelLeftLayout.setVerticalGroup(
            panelLeftLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING)
        );

        jSplitPane1.setDividerLocation(650);
        jSplitPane1.setResizeWeight(0.5);

        jSplitPane2.setDividerLocation(200);
        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jPanel3.setLayout(new java.awt.BorderLayout());

        jButton1.setText("Go");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Cancel");

        jButton3.setText("<");

        jButton4.setText(">");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jButton1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton4)
                .addGap(0, 407, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jButton1)
                .addComponent(jButton2)
                .addComponent(jButton3)
                .addComponent(jButton4))
        );

        jPanel3.add(jPanel1, java.awt.BorderLayout.NORTH);

        panelLeftRequest.setLayout(new java.awt.BorderLayout());
        jPanel3.add(panelLeftRequest, java.awt.BorderLayout.CENTER);

        jSplitPane2.setTopComponent(jPanel3);

        javax.swing.GroupLayout panelMsgOneLayout = new javax.swing.GroupLayout(panelMsgOne);
        panelMsgOne.setLayout(panelMsgOneLayout);
        panelMsgOneLayout.setHorizontalGroup(
            panelMsgOneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane2)
        );
        panelMsgOneLayout.setVerticalGroup(
            panelMsgOneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 401, Short.MAX_VALUE)
        );

        jSplitPane1.setLeftComponent(panelMsgOne);

        jSplitPane3.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        jPanel5.setLayout(new java.awt.BorderLayout());

        jLabel1.setText("jLabel1");

        jButton6.setText("jButton6");

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton6)
                .addGap(0, 444, Short.MAX_VALUE))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel1)
            .addComponent(jButton6)
        );

        jPanel5.add(jPanel7, java.awt.BorderLayout.NORTH);

        panelRightRequest.setLayout(new java.awt.BorderLayout());
        jPanel5.add(panelRightRequest, java.awt.BorderLayout.CENTER);

        jSplitPane3.setLeftComponent(jPanel5);

        javax.swing.GroupLayout panelRightResponseLayout = new javax.swing.GroupLayout(panelRightResponse);
        panelRightResponse.setLayout(panelRightResponseLayout);
        panelRightResponseLayout.setHorizontalGroup(
            panelRightResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 601, Short.MAX_VALUE)
        );
        panelRightResponseLayout.setVerticalGroup(
            panelRightResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 364, Short.MAX_VALUE)
        );

        jSplitPane3.setRightComponent(panelRightResponse);

        jSplitPane1.setRightComponent(jSplitPane3);

        javax.swing.GroupLayout panelRightLayout = new javax.swing.GroupLayout(panelRight);
        panelRight.setLayout(panelRightLayout);
        panelRightLayout.setHorizontalGroup(
            panelRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.Alignment.TRAILING)
        );
        panelRightLayout.setVerticalGroup(
            panelRightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(panelLeft, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(panelRight, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(panelLeft, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(panelRight, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        sendMessage();
    }//GEN-LAST:event_jButton1ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton6;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JSplitPane jSplitPane3;
    private javax.swing.JTable jTable1;
    private javax.swing.JPanel panelLeft;
    private javax.swing.JPanel panelLeftRequest;
    private javax.swing.JPanel panelMsgOne;
    private javax.swing.JPanel panelRight;
    private javax.swing.JPanel panelRightRequest;
    private javax.swing.JPanel panelRightResponse;
    // End of variables declaration//GEN-END:variables

    @Override
    public String getTabCaption() {
        return "Replayer";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

}
