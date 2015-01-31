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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class PopupTableHeaderLeft extends JPopupMenu implements ActionListener {
    private JTable tableMessages;
    private PanelLeftTableModel tableModel;

    private JMenuItem menuItemSelectAll;
    private JMenuItem menuItemInvert;
    
    private int selectedColumn = -1;
    
    public PopupTableHeaderLeft(JTable tableMessages, PanelLeftTableModel tableModel) {
        super();
        this.tableMessages = tableMessages;
        this.tableModel = tableModel;

        menuItemSelectAll = new JMenuItem("Select all");
        menuItemSelectAll.addActionListener(this);
        this.add(menuItemSelectAll);
        
        menuItemInvert = new JMenuItem("Invert selection");
        menuItemInvert.addActionListener(this);
        this.add(menuItemInvert);
        
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        JMenuItem menuItem = (JMenuItem) e.getSource();
        
        if (menuItem == menuItemSelectAll) {
            tableModel.intentSelectAll(selectedColumn);
        } else if (menuItem == menuItemInvert) {
            tableModel.intentInvertSelection(selectedColumn);
        }
    }
    
    public void show(Component invoker, MouseEvent e) {
        selectedColumn = tableMessages.columnAtPoint(e.getPoint());
        
        if (selectedColumn == 3 || selectedColumn == 4 || selectedColumn == 5) {
            this.show(invoker, e.getX(), e.getY());
        }
    }
}
