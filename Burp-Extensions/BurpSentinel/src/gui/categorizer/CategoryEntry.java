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
package gui.categorizer;

import java.awt.Color;

/**
 *
 * @author dobin
 */
public class CategoryEntry {
    private String name;
    private String regex;

    private Boolean isEnabled;
    private Color myColor = Color.black;
    
    public CategoryEntry(String name, String regex) {
        this.name = name;
        this.regex = regex;
 
        isEnabled = true;
        myColor = Color.black;
    }
    
    public CategoryEntry(String name, String regex, Color c, boolean isEnabled) {
        this.name = name;
        this.regex = regex;
        this.myColor = c;
        this.isEnabled = isEnabled;
    }
        
    public String getTag() {
        return name;
    }
    
    public void setTag(String tag) {
        this.name = tag;
    }
    
    public void setRegex(String regex) {
        this.regex = regex;
    }
    
    public String getRegex() {
        return regex;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(Boolean aBoolean) {
        this.isEnabled = aBoolean;
    }
    
    public Color getColor() {
        return myColor;
    }

    public void setColor(Color color) {
        this.myColor = color;
    }
    
}
