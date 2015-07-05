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
package model;

import java.io.Serializable;

/**
 *
 * @author unreal
 */
public class AttackTypeData implements Serializable {
    private boolean active;
    private String data;
    
    public AttackTypeData() {
        // Deserializing Constructor
    }
    
    public AttackTypeData(boolean active) {
        this.active = active;
    }
    
    public AttackTypeData(boolean active, String data) {
        this.active = active;
        this.data = data;
    }    
    
    public boolean isActive() {
        return active;
    }
    
    public String getData() {
        return data;
    }
    
}
