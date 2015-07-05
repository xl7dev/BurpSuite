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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rtextarea.RTextArea;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class PanelRightPopupMultiple implements ActionListener {

    private JPopupMenu menu;
    private JMenuItem menuCompare;
    private JMenuItem menuRepeater;
    private JMenuItem menuReissue;
    private JMenuItem menuCopy;
    private JMenuItem menuCopySmart;
    private PanelRightUi panelMessage;
    
    public PanelRightPopupMultiple(PanelRightUi panelMessage) {
        this.panelMessage = panelMessage;
        
        menu = new JPopupMenu("Message");
        
        menuCompare = new JMenuItem("Compare");
        menuCompare.addActionListener(this);
        menu.add(menuCompare);
        
        menuCopy = new JMenuItem(RSyntaxTextArea.getAction(RTextArea.COPY_ACTION));
        menu.add(menuCopy);
        
        menuRepeater = new JMenuItem("Send to Repeater");
        menuRepeater.addActionListener(this);
        menu.add(menuRepeater);
/*        
        menuReissue = new JMenuItem("Send again");
        menuReissue.addActionListener(this);
        menu.add(menuReissue);
        */
        menuCopySmart = new JMenuItem("Copy Smart");
        menuCopySmart.addActionListener(this);
        menu.add(menuCopySmart);
        
        
        
    }
    
    public JPopupMenu getPopup() {
        return menu;
    }
    
    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();
        
        if (o == menuCompare) {
            panelMessage.c_compare();
        }
        
        if (o == menuRepeater) {
            panelMessage.c_sendToRepeater();
        }
        /*
        if (o == menuReissue) {
            panelMessage.c_sendAgain();
        }*/
        if (o == menuCopySmart) {
            panelMessage.c_copySmart();
        }
    }
}
