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

import java.util.LinkedList;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;

/**
 *
 * @author unreal
 */
public class PanelViewComboboxModel extends AbstractListModel implements ComboBoxModel {

    private boolean hasParent = false;
    
    private LinkedList<String> values = new LinkedList<String>();
    
    public PanelViewComboboxModel() {
        values.add("Default");
        values.add("Beautify");
        values.add("Unified Diff");
        values.add("Context Diff");
    }
    
    public void hasParent(boolean hasParent) {
        this.hasParent = hasParent;
    }
    
    
    @Override
    public int getSize() {
        if (hasParent) {
            return 4;
        } else {
            return 2;
        }
    }

    @Override
    public Object getElementAt(int index) {
        if (index < values.size()) {
            return values.get(index);
        } else {
            return "";
        }
    }

    private int selected = 0;
    
    @Override
    public void setSelectedItem(Object anItem) {
        for(int n=0; n<values.size(); n++) {
            if (values.get(n).equals(anItem)) {
                selected = n;
            }
        }
    }

    @Override
    public Object getSelectedItem() {
        return values.get(selected);
    }
    
}
