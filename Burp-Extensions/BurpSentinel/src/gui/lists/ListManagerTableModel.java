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
package gui.lists;

import javax.swing.table.AbstractTableModel;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class ListManagerTableModel extends AbstractTableModel {
    
    private ListManagerModel managerModel;
    
    public ListManagerTableModel(ListManagerModel model) {
        this.managerModel = model;
    }
    
    @Override
    public void setValueAt(Object value, int row, int col) {
        if (! (value instanceof String)) {
            return;
        }
        
        managerModel.getList(row).setName((String) value);
        refresh(); 
    }
    
    @Override
    public boolean isCellEditable(int row, int column) {
        return true;
    }

    @Override
    public int getRowCount() {
        return managerModel.getCount();
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return managerModel.getList(rowIndex).getName();
    }

    void refresh() {
        this.fireTableDataChanged();
    }
    
}
