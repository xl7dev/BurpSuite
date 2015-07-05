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

import java.util.regex.Pattern;

/**
 *
 * @author unreal
 */
public class XssIndicator {

    static private XssIndicator xssIndicator;
    
    private String base = "Xss";
    private int count = 0;
    private Pattern pattern;
        
    public static XssIndicator getInstance() {
        if (xssIndicator == null) {
            xssIndicator = new XssIndicator();
        }

        return xssIndicator;
    }

    public XssIndicator() {
        count = 0;
        
        pattern = Pattern.compile("Xss\\w\\w");
    }
    
    public String getIndicatorRegex() {
        return "";
    }

    public String getBaseIndicator() {
        return base;
    }
    
    public String getIndicator() {
        String ret = "";
        ret = base + getAsciiCount();
        count++;

        return ret;
    }
    
    public int getCount() {
        return count;
    }
    
    public Pattern getPattern() {
        return pattern;
    }
    
    /*
     * Return a-z A-z for 0<n<52
     */
    private char getA(int n) {
        char r;

        if (n < 26) {
            r = (char) (((int) 'a') + n);
        } else if (n < 52) {
            n -= 26;
            r = (char) (((int) 'A') + n);
        } else {
            r = '0';
        }

        return r;
    }

    /*
     * Converts a number into base 52 (a-zA-z)
     * 
     * Currently two letters (aa-ZZ)
     */
    public String getAsciiCount() {
        String ret = "";
        int number = count;

        for (int x = 0; x < 2; x++) {
            int remainder = number % 52;
            ret = getA(remainder) + ret;
            number = (int) Math.floor(number / 52f);
        }

        return ret;
    }

}
