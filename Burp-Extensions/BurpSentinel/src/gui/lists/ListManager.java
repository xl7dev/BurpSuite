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

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class ListManager {
    static private ListManager listManager;
    
    static public ListManager getInstance() {
        if (listManager == null) {
            listManager = new ListManager();
        }
        
        return listManager;
    }
    
    private ListManagerModel listModel;
    
    public ListManager() {
        listModel = new ListManagerModel();
        listModel.readConfig();
        listModel.initFuzzDB();
    }

    public ListManagerModel getModel() {
        return listModel;
    }
    
}
