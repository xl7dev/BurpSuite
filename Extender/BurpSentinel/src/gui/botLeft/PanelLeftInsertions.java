/*
 * Copyright (C) 2014 DobinRutishauser@broken.ch
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
package gui.botLeft;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import util.BurpCallbacks;
import util.SettingsManager;


/**
 * Provides Insertions submenu, and handles option details
 * 
 * Will provide the Insertions menu for panelleft.
 * 
 * @author DobinRutishauser@broken.ch
 */
public class PanelLeftInsertions extends JButton implements ActionListener {

    private JPopupMenu menuMain;

    // Menus
    //private JMenu menuInsert;
    private JMenuItem menuItemReplace;
    private JMenuItem menuItemInsertLeft;
    private JMenuItem menuItemInsertRight;
    
    public static enum InsertPositions {
        REPLACE,
        LEFT,
        RIGHT,};
    private PanelLeftInsertions.InsertPositions optionInsertPosition;

    public PanelLeftInsertions() {
    }

    public void init() {
        // Options
        optionInsertPosition = SettingsManager.restorePanelLeftOptionPosition();

        // Menu
        menuMain = new JPopupMenu("Options");

        menuItemReplace = new JMenuItem("Replace");
        menuItemInsertLeft = new JMenuItem("Insert Left");
        menuItemInsertRight = new JMenuItem("Insert Right");
        menuItemReplace.addActionListener(this);
        menuItemInsertLeft.addActionListener(this);
        menuItemInsertRight.addActionListener(this);
        menuMain.add(menuItemReplace);
        menuMain.add(menuItemInsertLeft);
        menuMain.add(menuItemInsertRight);

        refresh();
    }

    private void refresh() {
        switch (optionInsertPosition) {
            case REPLACE:
                menuItemReplace.setEnabled(false);
                menuItemInsertLeft.setEnabled(true);
                menuItemInsertRight.setEnabled(true);
                this.setText("Payload: Replace");
                break;
            case LEFT:
                menuItemReplace.setEnabled(true);
                menuItemInsertLeft.setEnabled(false);
                menuItemInsertRight.setEnabled(true);
                this.setText("Payload: Add Left");
                break;
            case RIGHT:
                menuItemReplace.setEnabled(true);
                menuItemInsertLeft.setEnabled(true);
                menuItemInsertRight.setEnabled(false);
                this.setText("Payload: Add Right");
                break;
            default:
                BurpCallbacks.getInstance().print("Nope");
        }
    }

    void storeUiPrefs() {
        SettingsManager.storePanelLeftOptionPosition(optionInsertPosition);
    }

    public JPopupMenu getPopupMenu() {
        return menuMain;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == menuItemReplace) {
            optionInsertPosition = PanelLeftInsertions.InsertPositions.REPLACE;
        } else if (e.getSource() == menuItemInsertLeft) {
            optionInsertPosition = PanelLeftInsertions.InsertPositions.LEFT;
        } else if (e.getSource() == menuItemInsertRight) {
            optionInsertPosition = PanelLeftInsertions.InsertPositions.RIGHT;
        }

        refresh();
    }
    
    PanelLeftInsertions.InsertPositions getOptionInsertPosition() {
        return optionInsertPosition;
    }
}
