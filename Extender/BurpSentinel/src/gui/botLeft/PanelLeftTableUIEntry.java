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
package gui.botLeft;

import model.SentinelHttpParam;

/**
 * Hold state for individual rows of panel left table.
 * 
 * 
 * @author dobin
 */
class PanelLeftTableUIEntry {
    
    public SentinelHttpParam sourceHttpParam;
    
    public boolean isXssEnabled;
    public boolean isSqlEnabled;
    public boolean isOtherEnabled;
    
    public boolean isAuthEnabled;
    public String authData;
    
    public boolean isOrigEnabled;
    
    public boolean isSomethingEnabled() {
        return isXssEnabled || isSqlEnabled || isOtherEnabled;
    }
}
