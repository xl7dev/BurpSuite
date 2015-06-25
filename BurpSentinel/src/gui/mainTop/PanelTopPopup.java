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
package gui.mainTop;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

/**
 *
 * @author dobin
 */
public class PanelTopPopup implements ActionListener {

    private JMenuItem menuDelete;
    private JPopupMenu menu;
    private PanelTopUi parent;

    public PanelTopPopup(PanelTopUi parent) {
        this.parent = parent;

        menu = new JPopupMenu("Message");

        menuDelete = new JMenuItem("Delete");
        menuDelete.addActionListener(this);
        
        menu.add(menuDelete);
    }

    public JPopupMenu getPopup() {
        return menu;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();

        if (o == menuDelete) {
            parent.removeMessageAction();
        }
    }
}
