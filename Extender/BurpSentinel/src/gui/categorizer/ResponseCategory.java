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

import java.io.Serializable;

/**
 *
 * Is serializable, because it is used by model
 *
 * @author DobinRutishauser@broken.ch
 */
public class ResponseCategory implements Serializable {

    private CategoryEntry categoryEntry;
    private String indicator;
    private String categoryDescription;

    public ResponseCategory() {
        // Default constructor for deserializing
    }

    public ResponseCategory(CategoryEntry categoryEntry, String i, String categoryDescription) {
        this.categoryEntry = categoryEntry;
        this.indicator = i;
        this.categoryDescription = categoryDescription;
    }

    public CategoryEntry getCategoryEntry() {
        return categoryEntry;
    }

    public String getIndicator() {
        return indicator;
    }

    public String getCategoryDescription() {
        return categoryDescription;
    }
}
