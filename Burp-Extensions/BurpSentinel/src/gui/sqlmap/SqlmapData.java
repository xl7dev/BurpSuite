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
package gui.sqlmap;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SqlmapData {
    public String pythonPath;
    public String sqlmapPath;
    public String workingDir;
    
    public SqlmapData(String a, String b, String c) {
        this.pythonPath = a;
        this.sqlmapPath = b;
        this.workingDir = c;
    }
    
    public SqlmapData() {
        
    }
}
