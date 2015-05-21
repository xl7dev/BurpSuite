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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rtextarea.RTextArea;

/**
 *
 * @author unreal
 */
public class PanelViewMessagePopup implements ActionListener {
    private JPopupMenu menu;
    
    
    private JMenuItem menuRepeater;
    private JMenuItem menuReissue;
    private JMenuItem menuCopy;
    private JMenuItem menuCopySmart;
//    private JMenuItem menuDiff;
    
    private PanelViewMessageUi panelMessage;
    
    public PanelViewMessagePopup(PanelViewMessageUi panelMessage) {
        this.panelMessage = panelMessage;
        
        menu = new JPopupMenu("Message");
        
//        RecordableTextAction a = RSyntaxTextArea.getAction(RTextArea.COPY_ACTION);
//        a.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, ActionEvent.CTRL_MASK));
//        a.setEnabled(true);
//        RSyntaxTextArea.setA
//          BurpCallbacks.getInstance().print(a.getAccelerator().toString());
        
        menuCopy = new JMenuItem(RSyntaxTextArea.getAction(RTextArea.COPY_ACTION));
        menu.add(menuCopy);
        
        menuRepeater = new JMenuItem("Send to Repeater");
        menuRepeater.addActionListener(this);
        menu.add(menuRepeater);
        
        menuReissue = new JMenuItem("Send again");
        menuReissue.addActionListener(this);
        menu.add(menuReissue);
        
        menuCopySmart = new JMenuItem("Copy Smart");
        menuCopySmart.addActionListener(this);
        menu.add(menuCopySmart);
        

//        menuDiff = new JMenuItem("Diff");
//        menuDiff.addActionListener(this);
//        menu.add(menuDiff);
        
    }
    
    public JPopupMenu getPopup() {
        return menu;
    }
    
    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();
        
        if (o == menuRepeater) {
            panelMessage.c_sendToRepeater();
        }
        if (o == menuReissue) {
            panelMessage.c_sendAgain();
        }
        if (o == menuCopySmart) {
            panelMessage.c_copySmart();
        }
    }
    
}
