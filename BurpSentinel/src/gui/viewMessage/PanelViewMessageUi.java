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
package gui.viewMessage;

import model.ResponseHighlight;
import gui.session.SessionManager;
import gui.session.SessionUser;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.BoundedRangeModel;
import javax.swing.ComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import model.SentinelHttpParam;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.fife.ui.rtextarea.SearchContext;
import org.fife.ui.rtextarea.SearchEngine;
import org.w3c.tidy.Tidy;
import util.BurpCallbacks;
import util.SettingsManager;
import util.diff.DiffPrint.UnifiedSmallPrint;
import util.diff.GnuDiff;
import util.diff.GnuDiff.change;

/**
 * Displays httpMessages
 *
 * - Response with it's information - and the request - accumulates data to
 * highlight
 *
 *
 * @author Dobin
 */
public class PanelViewMessageUi extends javax.swing.JPanel implements ExternalUpdater {

    private SentinelHttpMessage httpMessage = null;
    private boolean showResponse = true;
    private PanelViewMessagePopup messagePopup;
    
    private PanelViewComboboxModel panelViewComboboxModel;
    
    private ViewMessageLinkManager linkManager = null;
    
    private int selectIndex = -1;
    private Object currentHighlight;
    
    private int savedCursor = -1;

    private BoundedRangeModel origScrollbarModel;
    
    private boolean isRequestEditor = false;
    
    private RSyntaxTextArea textareaMessage;
    private RTextScrollPane scrollPane;
    
    private String lastSearch = "";
    private SearchContext searchContext = null;
    
    private String currentView = "Default";

    
    private LinkedList<SentinelHighlight> myHighlights;

    private SentinelHttpMessage diffHttpMessage;
    
    
    /**
     * Creates new form PanelResponseUi
     */
    public PanelViewMessageUi() {
        panelViewComboboxModel = new PanelViewComboboxModel();
        
        initComponents();
        textareaMessage = new RSyntaxTextArea();
        scrollPane = new RTextScrollPane(textareaMessage);
        scrollPane.add(textareaMessage);
        panelCenter.removeAll();
        panelCenter.add(scrollPane, BorderLayout.CENTER);
        scrollPane.setViewportView(textareaMessage);

        this.invalidate();
        this.updateUI();
        
        panelHighlight.setVisible(false);
        
        messagePopup = new PanelViewMessagePopup(this);
        
        textareaMessage.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
        textareaMessage.setEditable(true);
        textareaMessage.setLineWrap(true);
        textareaMessage.setWrapStyleWord(false);
        textareaMessage.setAnimateBracketMatching(false);
        textareaMessage.setAutoIndentEnabled(false);
        textareaMessage.setBracketMatchingEnabled(false);
        textareaMessage.setPopupMenu(messagePopup.getPopup());
        SettingsManager.getTheme().apply(textareaMessage);
        textareaMessage.revalidate(); // TODO necessary?
        textareaMessage.requestFocusInWindow();
        textareaMessage.setMarkAllHighlightColor(new Color(0xff, 0xea, 0x00, 100));
        
        labelPosition.setText(" ");
        
        origScrollbarModel = scrollPane.getVerticalScrollBar().getModel();

        comboboxView.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JComboBox cb = (JComboBox)e.getSource();
                String selected = (String) cb.getSelectedItem();

                currentView = selected;
                showMessage();
            }
        });

        textfieldSearch.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                initSearchContext(textfieldSearch.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                initSearchContext(textfieldSearch.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                initSearchContext(textfieldSearch.getText());
            }
        });
    }
        

    public void setHttpMessage(SentinelHttpMessage httpMessage) {
        if (httpMessage == null) {
            BurpCallbacks.getInstance().print("setResponse(): HttpMessage NULL");
            return;
        }
        this.httpMessage = httpMessage;
        reInit();

    }

    private void reInit() {
        if (httpMessage.getRes().hasResponse()) {
            ///labelSize.setText(Integer.toString(httpMessage.getRes().getSize()));
            ///labelHttpCode.setText(httpMessage.getRes().getHttpCode());
            ///labelDom.setText(Integer.toString(httpMessage.getRes().getDom()));
            
            if (httpMessage instanceof SentinelHttpMessageOrig) {
                panelViewComboboxModel.hasParent(false);
            } else {
                panelViewComboboxModel.hasParent(true);
                SentinelHttpMessageAtk atk = (SentinelHttpMessageAtk) httpMessage;
                
                ///labelRedirected.setText(atk.isRedirected() ? "(R)" : "");
            }
        } else {
            
        }

        showMessage();
    }


    /*** Show Data based on different selected views ***/
    
    private void showDefaultView() {
        String viewDefaultContent = httpMessage.getRes().getResponseStr();
        setMessageText(viewDefaultContent);
        highlightResponse();
    }
    
    private void showBeautifyView() {
        String viewBeautifyContent = null;

        String res = httpMessage.getRes().extractBody();

        InputStream is = new ByteArrayInputStream(res.getBytes());
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        Tidy tidy = new Tidy();
        tidy.setWraplen(0);
        tidy.setDropEmptyParas(false);
        tidy.setDropFontTags(false);
        tidy.setDropProprietaryAttributes(false);
        tidy.setIndentContent(true);

        tidy.parse(is, os);
        try {
            String s = new String(os.toByteArray(), "UTF-8");
            viewBeautifyContent = s;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PanelViewMessageUi.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        setMessageText(viewBeautifyContent);
        highlightResponse();
    }
    
    
    
    public void setBuddy(SentinelHttpMessage msg) {
        this.diffHttpMessage = msg;
    }
    
    
    private void showUnifiedDiffView() {
        if (httpMessage instanceof SentinelHttpMessageOrig) {
            return;
        }
        String viewDiffContent = null;
        SentinelHttpMessageAtk messageAtk = (SentinelHttpMessageAtk) httpMessage;
        
        String origRes = diffHttpMessage.getRes().getResponseStr();
        String newRes = httpMessage.getRes().getResponseStr();

        String[] origResArr = origRes.split("\n");
        String[] newResArr = newRes.split("\n");

        GnuDiff gnuDiff = new GnuDiff(origResArr, newResArr);
        change changes = gnuDiff.diff(GnuDiff.forwardScript);

        UnifiedSmallPrint unifiedPrint = new UnifiedSmallPrint(origResArr, newResArr);
        StringWriter a = new StringWriter();
        unifiedPrint.setOutput(a);
        unifiedPrint.print_script(changes);

        viewDiffContent = a.toString();
        
        setMessageText(viewDiffContent);
        
        highlightResponse();
    }
    
    private void showContextDiffView() {
         if (httpMessage instanceof SentinelHttpMessageOrig) {
            return;
        }
        String viewDiffContent = httpMessage.getRes().getResponseStr();;
        SentinelHttpMessageAtk messageAtk = (SentinelHttpMessageAtk) httpMessage;
        
        setMessageText(viewDiffContent);

        String origRes = diffHttpMessage.getRes().getResponseStr();
        String newRes = httpMessage.getRes().getResponseStr();

        String[] origResArr = origRes.split("\n");
        String[] newResArr = newRes.split("\n");

        GnuDiff gnuDiff = new GnuDiff(origResArr, newResArr);
        change changes = gnuDiff.diff(GnuDiff.forwardScript);
    
        setMessageText(viewDiffContent);
        while(changes != null) {
            int linesAdded = changes.line1;
            int linesDeleted = changes.line0;
            
            //BurpCallbacks.getInstance().print("Highlight: #Added1: " + changes.inserted + " #Del0: " + changes.deleted);
            //BurpCallbacks.getInstance().print("Highlight: linenr ins1: " + changes.line1 + " linenr del0: " + changes.line0);
            
            addContextDiffHighlight(linesAdded);
            if (linesAdded != linesDeleted) {
                addContextDiffHighlight(linesDeleted);
            }
            
            changes = changes.link;
        }
        
        highlightResponse();
    }
    
    private void addContextDiffHighlight(int lineNr) {
        try {
            int offsetStart = textareaMessage.getLineStartOffset(lineNr);
            int offsetEnd = textareaMessage.getLineEndOffset(lineNr);
            
            //BurpCallbacks.getInstance().print("Highlight line: " + lineNr + " from: " + offsetStart + " to " + offsetEnd);
            
            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(new Color(0xf9, 0x4f, 0x4f, 100));
            try {
               //textareaMessage.getHighlighter().addHighlight(offsetStart, offsetEnd, painter);
                textareaMessage.addLineHighlight(lineNr, new Color(0xf9, 0x4f, 0x4f, 100));
            } catch (BadLocationException ex) {
                BurpCallbacks.getInstance().print("ARERRR2");
            }
            
        } catch (BadLocationException ex) {
            Logger.getLogger(PanelViewMessageUi.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    
    public void setShowResponse(boolean b) {
        this.showResponse = b;
    }
    
    private void showMessage() {
        textareaMessage.getHighlighter().removeAllHighlights();

        if (showResponse) {
            buttonShowRequest.setText("Response");

            if (currentView.equals("Default")) {
                showDefaultView();
            } else if (currentView.equals("Beautify")) {
                showBeautifyView();
            } else if (currentView.equals("Unified Diff")) {
                showUnifiedDiffView();
            } else if (currentView.equals("Context Diff")) {
                showContextDiffView();
            }
            
            comboboxView.setVisible(true);
        } else {
            buttonShowRequest.setText("Request");
            setMessageText(httpMessage.getReq().getRequestStr());
            highlightRequest();
            
            comboboxView.setVisible(false);
        }

        if (! checkboxIsFix.isSelected()) {
                selectIndex = -1;
        }
        
        if (myHighlights != null && myHighlights.size() > 0) {
            panelHighlight.setVisible(true);
            
            if (selectIndex >= 0) {
                labelPosition.setText((selectIndex + 1) + "/" + myHighlights.size());
            } else {
                labelPosition.setText("/" + myHighlights.size());
            }
        } else {
            panelHighlight.setVisible(false);
        }
        viewMessagePart(0, true);
        

    }

    
    /*** Highlights ***/
    
    /*
     * Highlight important data in request:
     * - origparam
     * - session
     */
    private void highlightRequest() {
        // Highlight session (original, as defined by cookie name)
        String sessionName = SessionManager.getInstance().getSessionVarName();
        for(SentinelHttpParam param: httpMessage.getReq().getParams()) {
            if (param.getName().equals(sessionName)) {
                //System.out.println("sessionName: " + sessionName + " "+ param.getValueStart());
                Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.orange);
                try {
                    textareaMessage.getHighlighter().addHighlight(param.getValueStart(), param.getValueEnd(), painter);
                } catch (BadLocationException ex) {
                    BurpCallbacks.getInstance().print("ARERRR1");
                }
            }
        }
        
        // Highlight session (defined, as by session value)
        LinkedList<SessionUser> sessionUsers = SessionManager.getInstance().getSessionUsers();
        String content = textareaMessage.getText();
        for(SessionUser sessionUser: sessionUsers) {
            String value = sessionUser.getValue();
            for (int index = content.indexOf(value); index >= 0; index = content.indexOf(value, index + 1)) {
                Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.green);
                try {
                    textareaMessage.getHighlighter().addHighlight(index, index + value.length(), painter);
                } catch (BadLocationException ex) {
                    BurpCallbacks.getInstance().print("ARERRR2");
                }
            }
        }
        
        // Highlight changeparam
        SentinelHttpParam httpParam = httpMessage.getReq().getChangeParam();
        if (httpParam == null) {
            return;
        }
        Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(new Color(0xc0dbff));
        try {
            textareaMessage.getHighlighter().addHighlight(httpParam.getValueStart(), httpParam.getValueEnd(), painter);
        } catch (BadLocationException ex) {
            BurpCallbacks.getInstance().print("ARERRR3");
        }
    }

    private void highlightResponse() {
        String response = textareaMessage.getText();
        myHighlights = new LinkedList<SentinelHighlight>();
        SentinelHighlight sh;
        
        // Highlight session (defined, as by session value)
        LinkedList<SessionUser> sessionUsers = SessionManager.getInstance().getSessionUsers();
        for(SessionUser sessionUser: sessionUsers) {
            String value = sessionUser.getValue();
            for (int index = response.indexOf(value); index >= 0; index = response.indexOf(value, index + 1)) {
                sh = new SentinelHighlight(index, index+value.length(), new Color(0xf9, 0x4f, 0x4f, 100));

                Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(sh.getColor());
                try {
                    textareaMessage.getHighlighter().addHighlight(sh.getStart(), sh.getEnd(), painter);
                    myHighlights.add(sh);
                } catch (BadLocationException ex) {
                    BurpCallbacks.getInstance().print("ARERRR2");
                }
            }
        }

        // Highlight response highlights
        for (ResponseHighlight h : httpMessage.getRes().getResponseHighlights()) {
            for (int index = response.indexOf(h.getStr()); index >= 0; index = response.indexOf(h.getStr(), index + 1)) {
                if (index == -1) {
                    BurpCallbacks.getInstance().print("highlightResponse: index=-1, string not found. catch it damned!");
                }
                
                if (isDuplicateHighlight(index, index + h.getStr().length())) {
                    continue;
                }
                
                sh = new SentinelHighlight(index, index + h.getStr().length(), h.getColor());

                // Also add highlighter to indicate to the user where it is
                Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(h.getColor());

                try {
                    textareaMessage.getHighlighter().addHighlight(sh.getStart(), sh.getEnd(), painter);
                    
                    myHighlights.add(sh);
                } catch (BadLocationException ex) {
                    BurpCallbacks.getInstance().print("ARERRR");
                }
            }
        }
    }
    
    
    private boolean isDuplicateHighlight(int start, int end) {
        for (SentinelHighlight h: myHighlights) {
            if (start >= h.getStart() && end <= h.getEnd()) {
                BurpCallbacks.getInstance().print("Duplicate Highlight: " + start +":"+end);
                return true;
            }
        }
        return false;
    }
    
    
    /*** Functions for children ***/
    
    public void c_sendAgain() {
        BurpCallbacks.getInstance().sendRessource(httpMessage, true, this);
    }
    
    public void c_sendToRepeater() {
        BurpCallbacks.getInstance().sendToRepeater(httpMessage);
    }
    
    public void c_copySmart() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

        String s = "Request:\n";
        s += httpMessage.getReq().getRequestStr();
        s += "\n\nResponse:\n";
        s += httpMessage.getRes().getResponseStr();
        
        StringSelection ss = new StringSelection(s);
        
        clipboard.setContents(ss, null);
    }

    
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        panelMain = new javax.swing.JPanel();
        panelTop = new javax.swing.JPanel();
        jPanel7 = new javax.swing.JPanel();
        buttonShowRequest = new javax.swing.JButton();
        comboboxView = new javax.swing.JComboBox();
        jPanel1 = new javax.swing.JPanel();
        checkboxIsLink = new javax.swing.JCheckBox();
        panelHighlight = new javax.swing.JPanel();
        checkboxIsFix = new javax.swing.JCheckBox();
        buttonUp = new javax.swing.JButton();
        buttonDown = new javax.swing.JButton();
        labelPosition = new javax.swing.JLabel();
        lblSearch = new javax.swing.JLabel();
        lblIndex = new javax.swing.JLabel();
        panelCenter = new javax.swing.JPanel();
        panelBot = new javax.swing.JPanel();
        buttonPrev = new javax.swing.JButton();
        buttonNext = new javax.swing.JButton();
        textfieldSearch = new javax.swing.JTextField();

        buttonShowRequest.setFont(new java.awt.Font("Tahoma", 0, 11)); // NOI18N
        buttonShowRequest.setText("Request");
        buttonShowRequest.setFocusable(false);
        buttonShowRequest.setMargin(new java.awt.Insets(0, 2, 0, 2));
        buttonShowRequest.setPreferredSize(new java.awt.Dimension(86, 24));
        buttonShowRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonShowRequestActionPerformed(evt);
            }
        });

        comboboxView.setModel(getPanelViewComboboxModel());

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel7Layout.createSequentialGroup()
                .addComponent(comboboxView, 0, 134, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(buttonShowRequest, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(comboboxView)
            .addComponent(buttonShowRequest, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        checkboxIsLink.setText("Link Window");
        checkboxIsLink.setToolTipText("Link Both Window Togeter - Scroll Together");
        checkboxIsLink.setMargin(new java.awt.Insets(0, 0, 0, 0));
        checkboxIsLink.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                checkboxIsLinkActionPerformed(evt);
            }
        });

        panelHighlight.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        checkboxIsFix.setText("Fix To Index");
        checkboxIsFix.setToolTipText("Fix Cursor Location - keep view for all messages");
        checkboxIsFix.setMargin(new java.awt.Insets(0, 0, 0, 0));

        buttonUp.setIcon(new javax.swing.ImageIcon(getClass().getResource("/resources/1356984817_arrow_large_up.png"))); // NOI18N
        buttonUp.setToolTipText("Select previous Highlight");
        buttonUp.setMargin(new java.awt.Insets(2, 2, 2, 2));
        buttonUp.setMaximumSize(new java.awt.Dimension(24, 20));
        buttonUp.setMinimumSize(new java.awt.Dimension(24, 20));
        buttonUp.setPreferredSize(new java.awt.Dimension(32, 22));
        buttonUp.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonUpActionPerformed(evt);
            }
        });

        buttonDown.setIcon(new javax.swing.ImageIcon(getClass().getResource("/resources/1356984823_arrow_large_down.png"))); // NOI18N
        buttonDown.setToolTipText("Select next Highlight");
        buttonDown.setMargin(new java.awt.Insets(1, 1, 1, 1));
        buttonDown.setMaximumSize(new java.awt.Dimension(24, 20));
        buttonDown.setMinimumSize(new java.awt.Dimension(24, 20));
        buttonDown.setPreferredSize(new java.awt.Dimension(32, 22));
        buttonDown.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonDownActionPerformed(evt);
            }
        });

        labelPosition.setText("00/00");
        labelPosition.setToolTipText("Current Highlight Index / Number of Highlights");

        lblSearch.setText("Search:");

        lblIndex.setText("Index:");

        javax.swing.GroupLayout panelHighlightLayout = new javax.swing.GroupLayout(panelHighlight);
        panelHighlight.setLayout(panelHighlightLayout);
        panelHighlightLayout.setHorizontalGroup(
            panelHighlightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelHighlightLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(lblSearch, javax.swing.GroupLayout.PREFERRED_SIZE, 58, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonUp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonDown, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(7, 7, 7)
                .addComponent(lblIndex)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(labelPosition)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(checkboxIsFix)
                .addGap(2, 2, 2))
        );
        panelHighlightLayout.setVerticalGroup(
            panelHighlightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelHighlightLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(labelPosition, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(checkboxIsFix)
                .addComponent(lblIndex))
            .addComponent(lblSearch)
            .addComponent(buttonDown, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addComponent(buttonUp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(checkboxIsLink)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(panelHighlight, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 8, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(checkboxIsLink, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(panelHighlight, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        javax.swing.GroupLayout panelTopLayout = new javax.swing.GroupLayout(panelTop);
        panelTop.setLayout(panelTopLayout);
        panelTopLayout.setHorizontalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelTopLayout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        panelTopLayout.setVerticalGroup(
            panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelTopLayout.createSequentialGroup()
                .addGroup(panelTopLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(jPanel7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(0, 2, Short.MAX_VALUE))
        );

        panelCenter.setLayout(new java.awt.BorderLayout());

        buttonPrev.setText("<");
        buttonPrev.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonPrevActionPerformed(evt);
            }
        });

        buttonNext.setText(">");
        buttonNext.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonNextActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelBotLayout = new javax.swing.GroupLayout(panelBot);
        panelBot.setLayout(panelBotLayout);
        panelBotLayout.setHorizontalGroup(
            panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelBotLayout.createSequentialGroup()
                .addComponent(buttonPrev)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonNext)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(textfieldSearch))
        );
        panelBotLayout.setVerticalGroup(
            panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelBotLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addGroup(panelBotLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttonPrev)
                    .addComponent(buttonNext)
                    .addComponent(textfieldSearch, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
        );

        javax.swing.GroupLayout panelMainLayout = new javax.swing.GroupLayout(panelMain);
        panelMain.setLayout(panelMainLayout);
        panelMainLayout.setHorizontalGroup(
            panelMainLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(panelTop, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(panelCenter, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(panelBot, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        panelMainLayout.setVerticalGroup(
            panelMainLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelMainLayout.createSequentialGroup()
                .addComponent(panelTop, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(2, 2, 2)
                .addComponent(panelCenter, javax.swing.GroupLayout.DEFAULT_SIZE, 305, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(panelBot, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(panelMain, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(panelMain, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void buttonShowRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonShowRequestActionPerformed
        this.showResponse = ! this.showResponse;
        showMessage();
    }//GEN-LAST:event_buttonShowRequestActionPerformed


    /*** Highlight index functions ***/
    
    private void moveCursorDown() {
        if (currentHighlight != null) {
            textareaMessage.getHighlighter().removeHighlight(currentHighlight);
            currentHighlight = null;
        }
        
        try {
            selectIndex++;
            if (selectIndex >= myHighlights.size()) {
                selectIndex = 0;
            }
            SentinelHighlight nextHighlight = myHighlights.get(selectIndex);

            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.GRAY);
            currentHighlight = textareaMessage.getHighlighter().addHighlight(nextHighlight.getStart()-1, nextHighlight.getEnd()+1, painter);
            
            int o = nextHighlight.getStart();
            viewMessagePart(o, false);
            labelPosition.setText(Integer.toString(selectIndex + 1) + "/" + Integer.toString(myHighlights.size()));
        } catch (BadLocationException ex) {
            BurpCallbacks.getInstance().print("CANT HIGHLIGHT1");
        }
    }

        
    private void moveCursorUp() {
        if (currentHighlight != null) {
            textareaMessage.getHighlighter().removeHighlight(currentHighlight);
            currentHighlight = null;
        }
        
        try {
            selectIndex--;
            if (selectIndex < 0) {
                selectIndex = myHighlights.size() - 1;
            }
            SentinelHighlight nextHighlight = myHighlights.get(selectIndex);
            
            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.GRAY);
            currentHighlight = textareaMessage.getHighlighter().addHighlight(nextHighlight.getStart()-1, nextHighlight.getEnd()+1, painter);
            
            int o = nextHighlight.getStart();
            
            viewMessagePart(o, false);
            labelPosition.setText(Integer.toString(selectIndex + 1) + "/" + Integer.toString(myHighlights.size()));
        } catch (BadLocationException ex) {
            BurpCallbacks.getInstance().print("CANT HIGHLIGHT2");
        }
    }
    
    private void viewMessagePart(int n, boolean isNew) {
        if (isNew) {
            if (checkboxIsFix.isSelected()) {
                textareaMessage.setCaretPosition(savedCursor);
            } else {
                textareaMessage.setCaretPosition(n);
            }
        } else {
            textareaMessage.setCaretPosition(n);
            
            if (checkboxIsLink.isSelected() && linkManager != null) {
                linkManager.setPosition(n, this);
            }
        }
    }
    
    public void setPosition(int n) {
        textareaMessage.setCaretPosition(n);
    }
        
    
    /*** ***/
    
    private void setMessageText(String s) {
        savedCursor = textareaMessage.getCaretPosition();
        textareaMessage.setText(s);
    }
    
    public void setLinkManager(ViewMessageLinkManager linkManager) {
        this.linkManager = linkManager;
        linkManager.registerViewMessage(this);
    }
    
    /* Callled from LinkManager */
    public void setScrollBarModel(BoundedRangeModel model) {
        if (model == null) {
            int pos = scrollPane.getVerticalScrollBar().getValue();
            origScrollbarModel.setValue(pos);
            scrollPane.getVerticalScrollBar().setModel(origScrollbarModel);
            checkboxIsLink.setSelected(false);
        } else {
            // Set new model
            //origScrollbarModel = jScrollPane2.getVerticalScrollBar().getModel();
            scrollPane.getVerticalScrollBar().setModel(model);
            checkboxIsLink.setSelected(true);
        }
    }
    
    private void buttonDownActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonDownActionPerformed
        moveCursorDown();
    }//GEN-LAST:event_buttonDownActionPerformed

    private void buttonUpActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonUpActionPerformed
        moveCursorUp();
    }//GEN-LAST:event_buttonUpActionPerformed

    private void checkboxIsLinkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_checkboxIsLinkActionPerformed
        if (checkboxIsLink.isSelected()) {
            // Other window should have same model
            linkManager.setScrollModel(scrollPane.getVerticalScrollBar().getModel(), this);
        } else {
            // Restore original model on all window
            linkManager.setScrollModel(null, this);
            scrollPane.getVerticalScrollBar().setModel(origScrollbarModel);
        }
    }//GEN-LAST:event_checkboxIsLinkActionPerformed

    /*** Search Stuff ***/
    
    private void initSearchContext(String newSearchString) {
        if (lastSearch.equals(newSearchString)) {
            return;
        }
        lastSearch = newSearchString;
        if (newSearchString.equals("")) {
            searchContext = new SearchContext();
            textareaMessage.clearMarkAllHighlights();
            return;
        }

        textareaMessage.setCaretPosition(0);
        searchContext = new SearchContext();
        searchContext.setSearchFor(newSearchString);
        searchContext.setSearchForward(true);
        SearchEngine.find(textareaMessage, searchContext);
        
        textareaMessage.markAll(newSearchString, true, false, false);
    }
    
    private void searchForward() {
        searchContext.setSearchForward(true);
        SearchEngine.find(textareaMessage, searchContext);
    }
    
    private void searchBackward() {
        searchContext.setSearchForward(false);
        SearchEngine.find(textareaMessage, searchContext);
    }
    
    
    private void buttonNextActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonNextActionPerformed
        searchForward();
    }//GEN-LAST:event_buttonNextActionPerformed

    private void buttonPrevActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonPrevActionPerformed
        searchBackward();
    }//GEN-LAST:event_buttonPrevActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonDown;
    private javax.swing.JButton buttonNext;
    private javax.swing.JButton buttonPrev;
    private javax.swing.JButton buttonShowRequest;
    private javax.swing.JButton buttonUp;
    private javax.swing.JCheckBox checkboxIsFix;
    private javax.swing.JCheckBox checkboxIsLink;
    private javax.swing.JComboBox comboboxView;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JLabel labelPosition;
    private javax.swing.JLabel lblIndex;
    private javax.swing.JLabel lblSearch;
    private javax.swing.JPanel panelBot;
    private javax.swing.JPanel panelCenter;
    private javax.swing.JPanel panelHighlight;
    private javax.swing.JPanel panelMain;
    private javax.swing.JPanel panelTop;
    private javax.swing.JTextField textfieldSearch;
    // End of variables declaration//GEN-END:variables

    public String getRequestContent() {
        if (showResponse) {
            return null;
        }
        
        String s = textareaMessage.getText();
        return s;
    }

    public void setRequestEditor(boolean b) {
        isRequestEditor = b;
        textareaMessage.setEditable(b);
    }

    private ComboBoxModel getPanelViewComboboxModel() {
        return panelViewComboboxModel;
    }

    @Override
    public void externalUpdate() {
        this.reInit();
    }
    

}
