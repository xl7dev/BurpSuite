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
package util;

import java.awt.Color;
import java.awt.Component;
import javax.swing.JTable;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class Utility {
    
    // http://www.chka.de/swing/table/cell-sizes.html
    public static void calcColumnWidths(JTable table) {
        JTableHeader header = table.getTableHeader();

        TableCellRenderer defaultHeaderRenderer = null;

        if (header != null) {
            defaultHeaderRenderer = header.getDefaultRenderer();
        }

        TableColumnModel columns = table.getColumnModel();
        TableModel data = table.getModel();

        int margin = columns.getColumnMargin(); // only JDK1.3
        int rowCount = data.getRowCount();
        int totalWidth = 0;

        for (int i = columns.getColumnCount() - 1; i >= 0; --i) {
            TableColumn column = columns.getColumn(i);

            int columnIndex = column.getModelIndex();
            int width = -1;

            TableCellRenderer h = column.getHeaderRenderer();
            if (h == null) {
                h = defaultHeaderRenderer;
            }

            if (h != null) // Not explicitly impossible
            {
                Component c = h.getTableCellRendererComponent(table, column.getHeaderValue(),
                        false, false, -1, i);
                width = c.getPreferredSize().width;
            }

            for (int row = rowCount - 1; row >= 0; --row) {
                TableCellRenderer r = table.getCellRenderer(row, i);
                Component c = r.getTableCellRendererComponent(table,
                        data.getValueAt(row, columnIndex),
                        false, false, row, i);
                width = Math.max(width, c.getPreferredSize().width);
            }

            if (width >= 0) {
                column.setPreferredWidth(width + margin); // <1.3: without margin
            } else
            ; // ???

            totalWidth += column.getPreferredWidth();
        }
    }
    
    
    // From: http://stackoverflow.com/questions/4059133/getting-html-color-codes-with-a-jcolorchooser
    public static String ColorToHtmlString(Color c) {
        StringBuilder sb = new StringBuilder("#");

        if (c.getRed() < 16) {
            sb.append('0');
        }
        sb.append(Integer.toHexString(c.getRed()));

        if (c.getGreen() < 16) {
            sb.append('0');
        }
        sb.append(Integer.toHexString(c.getGreen()));

        if (c.getBlue() < 16) {
            sb.append('0');
        }
        sb.append(Integer.toHexString(c.getBlue()));

        return sb.toString();
    }

}
