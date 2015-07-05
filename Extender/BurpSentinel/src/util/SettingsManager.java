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
package util;

import gui.botLeft.PanelLeftInsertions.InsertPositions;
import gui.session.SessionUser;
import gui.categorizer.CategoryEntry;
import gui.lists.ListManagerList;
import gui.sqlmap.SqlmapData;
import java.awt.Color;
import java.awt.Frame;
import java.awt.Rectangle;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import org.fife.ui.rsyntaxtextarea.Theme;

/**
 *
 * 
 */
public class SettingsManager {

    private static Theme theme = null;
    
    public static void resetConfig() {
        BurpCallbacks.getInstance().print("AAA");
        try {
            //Preferences.userRoot().removeNode();
            
            for (String s: Preferences.userRoot().childrenNames()) {
                
                BurpCallbacks.getInstance().print("Remove: " + s);
                for (String ss: Preferences.userRoot().node(s).keys()) {
                    BurpCallbacks.getInstance().print("remove 1: " + ss);
                    Preferences.userRoot().node(s).remove(ss);
                }
            }
            
            Preferences.userRoot().flush();
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    public static Theme getTheme() {
        if (theme == null) {
            try {
                InputStream in = SettingsManager.class.getResourceAsStream("/resources/BurpTheme.xml");
                theme = Theme.load(in);
            } catch (IOException ex) {
                BurpCallbacks.getInstance().print("error loading theme: " + ex.getLocalizedMessage());
            }
        }
        return theme;
    }
    
    public static void storeTableDimensions(JTable table, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());
        TableColumnModel columns = table.getColumnModel();

        for (int i = columns.getColumnCount() - 1; i >= 0; --i) {
            TableColumn column = columns.getColumn(i);
            int w = column.getPreferredWidth();
            
            pref.putInt(Integer.toString(i), w);
        }
    }

    public static void restoreTableDimensions(JTable table, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());
        TableColumnModel columns = table.getColumnModel();
        

        for (int i = columns.getColumnCount() - 1; i >= 0; --i) {
            TableColumn column = columns.getColumn(i);
            int w = pref.getInt(Integer.toString(i), 10);
    

            column.setPreferredWidth(w);
        }
    }
    
    
    /** Store location & size of UI */
    public static void storeFrameDimensions(Frame f, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());
       
        // restore the frame from 'full screen' first!
        f.setExtendedState(Frame.NORMAL);
        Rectangle r = f.getBounds();
        
        int x = (int)r.getX();
        int y = (int)r.getY();
        int w = (int)r.getWidth();
        int h = (int)r.getHeight();
        
        pref.putInt("x", x);
        pref.putInt("y", y);
        pref.putInt("w", w);
        pref.putInt("h", h);
    }

    /** Restore location & size of UI */
    public static void restoreFrameDimensions(Frame f, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());

        int x = pref.getInt("x", 0);
        int y = pref.getInt("y", 0);
        int w = pref.getInt("w", 1024);
        int h = pref.getInt("h", 786);

        Rectangle r = new Rectangle(x,y,w,h);
        f.setBounds(r);
    }
    

    public static void storeSplitLocation(JSplitPane jSplitPane1, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());
        pref.putInt(("location"), jSplitPane1.getDividerLocation());
    }

    public static void restoreSplitLocation(JSplitPane jSplitPane1, Object o) {
        Preferences pref = Preferences.userRoot().node(o.getClass().getName());
        jSplitPane1.setDividerLocation(pref.getInt(("location"), jSplitPane1.getDividerLocation()));
    }

    public static void storeSessions(LinkedList<SessionUser> sessionUsers) {
        Preferences pref = Preferences.userRoot().node("SessionManagerUsers");
        try {
            pref.clear();
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        for(SessionUser u: sessionUsers) {
            pref.put(u.getName(), u.getValue());
        }
    }
    
    public static void restoreSessions(LinkedList<SessionUser> sessionUsers) {
        Preferences pref = Preferences.userRoot().node("SessionManagerUsers");
    
        String[] children = null;
        try {
            children = pref.keys();
            for (String s : children) {
                String value = pref.get(s, "");
                sessionUsers.add(new SessionUser(s, value));
            }            
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    

    public static void storeSessionData(String text) {
        Preferences pref = Preferences.userRoot().node("SessionManagerData");
        pref.put("SessionVarName", text);
    }

    public static void restoreSessionData(JTextField textfieldSession) {
        Preferences pref = Preferences.userRoot().node("SessionManagerData");
        
        String s = pref.get("SessionVarName", "jsessionid");
        textfieldSession.setText(s);
    }

    public static void restoreCategories(LinkedList<CategoryEntry> categoryEntries) {
        Preferences pref = Preferences.userRoot().node("CategoryEntries");
    
        int n=0;
        int last = pref.getInt("numbers", 0);
        
        for(n=0; n<last; n++) {
            String tag = pref.get(Integer.toString(n) + "_tag", "");
            String regex = pref.get(Integer.toString(n) + "_regex", "");
            Color c = new Color (pref.getInt(Integer.toString(n) + "_color", 0));
            boolean enabled = pref.getBoolean(Integer.toString(n) + "_enabled", true);
            categoryEntries.add( new CategoryEntry (tag, regex, c, enabled));
        }
    }

    public static void storeCategories(LinkedList<CategoryEntry> categoryEntries) {
        Preferences pref = Preferences.userRoot().node("CategoryEntries");
        try {
            pref.clear();
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        int n = 0;
        for(CategoryEntry c: categoryEntries) {
            pref.put(Integer.toString(n) + "_tag", c.getTag());
            pref.put(Integer.toString(n) + "_regex", c.getRegex());
            pref.putInt(Integer.toString(n) + "_color", c.getColor().getRGB());
            pref.putBoolean(Integer.toString(n) + "_enabled", c.isEnabled());
            n++;
        }
        pref.putInt("numbers", n);
    }


    public static void storeAttackLists(LinkedList<ListManagerList> lists) {
        Preferences pref = Preferences.userRoot().node("AttackLists");
        try {
            pref.clear();
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        for(ListManagerList list: lists) {
            pref.put(list.getName(), list.getContentAsString());
        }
    }
    
    public static void restoreAttackLists(LinkedList<ListManagerList> lists) {
        Preferences pref = Preferences.userRoot().node("AttackLists");
    
        String[] children = null;
        try {
            children = pref.keys();
            for (String s : children) {
                String value = pref.get(s, "");
                lists.add( new ListManagerList(s, value));
            }            
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static boolean getListInitState() {
        Preferences pref = Preferences.userRoot().node("Initialization");
        
        return pref.getBoolean("FuzzDb", true);
    }
    
    public static void setListInitState(boolean b) {
        Preferences pref = Preferences.userRoot().node("Initialization");
        try {
            pref.clear();
        } catch (BackingStoreException ex) {
            Logger.getLogger(SettingsManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        pref.putBoolean("FuzzDb", b);
    }

    public static void storePanelLeftOptionRedirect(boolean optionEnableRedirect) {
        Preferences pref = Preferences.userRoot().node("PanelLeftOptions");
        pref.putBoolean("FollowRedirect", optionEnableRedirect);
    }
    
    public static boolean restorePanelLeftOptionRedirect() {
        Preferences pref = Preferences.userRoot().node("PanelLeftOptions");
        return pref.getBoolean("FollowRedirect", true);
    }
    

    public static void storePanelLeftOptionPosition(InsertPositions optionInsertPosition) {
        Preferences pref = Preferences.userRoot().node("PanelLeftOptions");
        pref.put("InsertPosition", optionInsertPosition.toString());
    }
    
    public static InsertPositions restorePanelLeftOptionPosition() {
        Preferences pref = Preferences.userRoot().node("PanelLeftOptions");
        String res = pref.get("InsertPosition", "REPLACE");
        
        return InsertPositions.valueOf(res);
    }
    
    public static void storeEnableRelativeResponseSize(boolean b) {
        Preferences pref = Preferences.userRoot().node("Options");
        pref.putBoolean("RelativeResponseSize", b);
    }
    
    public static boolean getEnableRelativeResponseSize() {
        Preferences pref = Preferences.userRoot().node("Options");
        boolean res = pref.getBoolean("RelativeResponseSize", true);
        return res;
    }
    
    

    public static SqlmapData getSqlmapConfig() {
        Preferences pref = Preferences.userRoot().node("Sqlmap");
        SqlmapData data = new SqlmapData();
     
        data.pythonPath = pref.get("PythonPath", "/usr/bin/python");
        data.sqlmapPath = pref.get("SqlmapPath", "/home/dobin/Downloads/sqlmapproject-sqlmap-cb1f17c/sqlmap.py");
        data.workingDir = pref.get("WorkingDir", "/tmp/sqlmap/");
        
        return data;
    }
    
    public static void storeSqlmapConfig(SqlmapData data) {
        Preferences pref = Preferences.userRoot().node("Sqlmap");
        
        pref.put("PythonPath", data.pythonPath);
        pref.put("SqlmapPath", data.sqlmapPath);
        pref.put("WorkingDir", data.workingDir);
    }

    
}
