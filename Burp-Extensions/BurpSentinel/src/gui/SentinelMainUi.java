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
package gui;

import model.ModelRoot;
import burp.ITab;
import gui.mainBot.PanelBotUi;
import gui.mainTop.PanelTopUi;
import java.awt.CardLayout;
import java.awt.Component;
import java.util.LinkedList;
import java.util.Observable;
import java.util.Observer;
import model.SentinelHttpMessageOrig;
import util.BurpCallbacks;
import util.SettingsManager;

/**
 * The main GUI Window
 *
 * - Displays Top and Bottom Panel 
 * - Interface between Top/Bot Panel 
 * - Interface for burp to add HttpMessages to sentinel
 *
 * @author Dobin
 */
public class SentinelMainUi extends javax.swing.JPanel implements ITab, Observer {

    // A list of Panels of the added HttpMessages
    private LinkedList<PanelBotUi> panelBotUiList = new LinkedList<PanelBotUi>();
    private ModelRoot modelRoot;
    
    static void setMainUi(SentinelMainUi ui) {
        mainUi = ui;
    }
    static SentinelMainUi mainUi;
    public static SentinelMainUi getMainUi() {
        return mainUi;
    }
    
    
    /**
     * Creates new form MainGuiFrame
     */
    public SentinelMainUi(ModelRoot modelRoot) {
        SentinelMainUi.setMainUi(this);
        initComponents();
        
        this.modelRoot = modelRoot;
    }

    
    public void init() {
        modelRoot.addObserver(this);
        
        // Has to be on top-top, or will not restore split location correclty
        SettingsManager.restoreSplitLocation(jSplitPane1, this);
        
        // Has to be on top, or it breaks panelTopUi init stuff
        //initTestMessages();
        
        // panelTopUi was inserted with Netbeans palette
        // Set his parent here
        panelTopUi.init();
    }
    
    
    /*
     * Gets called when a new message arrives.
     * 
     * As we observer() ModelRoot, we will get notified when a new message
     * is added to the Model.
     * This is usually if the user sent a message to Sentinel with the menu entry.
     */
    @Override
    public void update(Observable o, Object arg) {
        SentinelHttpMessageOrig newHttpMessage = (SentinelHttpMessageOrig) arg;
        
        newHttpMessage.setSentinelIdentifier(lastMessageNr);
        lastMessageNr++;
        
        addNewMessage(newHttpMessage);
    }

    
    /*
     * Restore complete state from model
     * 
     * This is called if the user wants to restore a previously saved state.
     * As the messages already have attackmessages and results, this is different
     * than just addNewMessage().
     * 
     */
    public void reset() {
        // Clean everything
        panelTopUi.reset();
        
        panelBotUiList = new LinkedList<PanelBotUi>();
    }
    

    private int lastMessageNr = 0;
    
    public void addNewMessage(SentinelHttpMessageOrig myHttpMessage) {
        // Save ui preferences
        // For example, the row width's are not automatically stored upon change,
        // but needed for new messages.
        storeUiPrefs();
        
        BurpCallbacks.getInstance().print("addMessage: " + myHttpMessage.getMessageNr());
        
        // Add request to top overview (where user can select requests)
        panelTopUi.addMessage(myHttpMessage);

        // Create a new PanelBot card and add it to the botPanel and the 
        // LinkedList of available cards
        PanelBotUi newPanelBot = new PanelBotUi(myHttpMessage);
        newPanelBot.setName(Integer.toString(myHttpMessage.getMessageNr()));
        panelBotUiList.add(newPanelBot);
        panelCard.add(newPanelBot, Integer.toString(myHttpMessage.getMessageNr()));
        showMessage(myHttpMessage);
    }
    
    
    /* 
     * Can be called by:
     *   - addMessage()
     *   - PanelTopUi table selection listener
     */
    public void showMessage(SentinelHttpMessageOrig myMessage) {
        if (myMessage == null) {
            return;
        } 
        
        panelTopUi.setSelected(myMessage);
        
        CardLayout cl = (CardLayout) panelCard.getLayout();
        cl.show(panelCard, Integer.toString(myMessage.getMessageNr()));
    }

    public void removeMessage(SentinelHttpMessageOrig removeMsg) {
        // First, remove it from PanelTopUi
        panelTopUi.removeMessage(removeMsg);
        
        // Second, remove it from CardLayout
        CardLayout cl = (CardLayout) panelCard.getLayout();
        Component[] components = panelCard.getComponents();

        for (int i = 0; i < components.length; i++) {
            if (components[i].getName().equals(Integer.toString(removeMsg.getMessageNr()))) {
                //cl.removeLayoutComponent(components[i]);
                break;
            }
        }
        
        // Last, show another message
        SentinelHttpMessageOrig firstMsg = panelTopUi.getFirstMessage();
        if (firstMsg == null) {
            // No message to show...
            
        } else {
            showMessage(firstMsg);
        }
    }
 
    
    /*
     * Init testcase messages
     */
    private void initTestMessages() {
        SentinelMainApi.getInstance().initTestMessages();
    }

    public PanelTopUi getPanelTop() {
        return panelTopUi;
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
        panelTopUi = new gui.mainTop.PanelTopUi();
        panelBot = new javax.swing.JPanel();
        panelCard = new javax.swing.JPanel();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();

        jSplitPane1.setDividerLocation(100);
        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        panelTop.setLayout(new java.awt.BorderLayout());
        panelTop.add(panelTopUi, java.awt.BorderLayout.CENTER);

        jSplitPane1.setTopComponent(panelTop);

        panelBot.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));
        panelBot.setLayout(new java.awt.BorderLayout());

        panelCard.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        panelCard.setLayout(new java.awt.CardLayout());
        panelBot.add(panelCard, java.awt.BorderLayout.CENTER);

        jSplitPane1.setBottomComponent(panelBot);

        jMenu1.setText("File");

        jMenuItem2.setText("Load Tests");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem2);

        jMenuItem1.setText("Reset");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem1);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit");
        jMenuBar1.add(jMenu2);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 1214, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSplitPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 633, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        //this.dispose();
        //initComponents();
        //init();
        panelTopUi.reset();
        panelBotUiList = new LinkedList<PanelBotUi>();
        panelCard.removeAll();
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
        initTestMessages();
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JPanel panelBot;
    private javax.swing.JPanel panelCard;
    private javax.swing.JPanel panelTop;
    private gui.mainTop.PanelTopUi panelTopUi;
    // End of variables declaration//GEN-END:variables

    
    public void storeUiPrefs() {
        // store this preferences
        SettingsManager.storeSplitLocation(jSplitPane1, this);
        
        panelTopUi.storeUiPrefs();

        // Store table preferences of last PanelBottom
        if (panelBotUiList.size() != 0) {
            panelBotUiList.get(panelBotUiList.size() - 1).storeUiPrefs();
        } else {
        }
    }
    
    
    @Override
    public String getTabCaption() {
        return "Sentinel";
    }
    
    @Override
    public Component getUiComponent() {
        return this;
    }



}
