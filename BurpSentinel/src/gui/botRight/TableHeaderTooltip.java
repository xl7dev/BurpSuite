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
package gui.botRight;

import java.awt.event.MouseEvent;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class TableHeaderTooltip extends JTableHeader {

    public TableHeaderTooltip(TableColumnModel model) {
        super(model);
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        int col = columnAtPoint(e.getPoint());
        int modelCol = getTable().convertColumnIndexToModel(col);
        
        switch(modelCol) {
            case 0:
                return "Index";
            case 1:
                return "Type of request (GET or POST)";
            case 2:
                return "Name of parameter";
            case 3:
                return "Original content of parameter";
            case 4:
                return "New attack-content of parameter";
            case 5:
                return "HTTP Response Status (200, 404, ...)";
            case 6:
                return "HTTP Response body length (without headers)";
            case 7:
                return "Number of tags in HTTP Response";
            case 8:
                return "Response time in milliseconds";
            case 9:
                return "Which attack has been performed";
            case 10:
                return "Result of the test (if possible)";
            case 11:
                return "Categorizer tags (error, sqlerr, and self-defined)";
        }
        
        return "";
    }
    
}
