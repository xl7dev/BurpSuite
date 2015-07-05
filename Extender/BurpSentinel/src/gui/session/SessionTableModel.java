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
package gui.session;

import java.util.Collections;
import java.util.LinkedList;
import javax.swing.table.AbstractTableModel;
import util.SettingsManager;

/**
 *
 * @author unreal
 */
public class SessionTableModel extends AbstractTableModel {

    private LinkedList<SessionUser> sessionUsers = new LinkedList<SessionUser>();

    public SessionTableModel() {
        SettingsManager.restoreSessions(sessionUsers);
    }
    
    @Override
    public String getColumnName(int columnIndex) {
        switch(columnIndex) {
            case 0:
                return "Username";
            case 1:
                return "Session ID";
            default:
                return "";
        }
    }
    
    @Override
    public int getRowCount() {
        return sessionUsers.size();
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch(columnIndex) {
            case 0:
                return sessionUsers.get(rowIndex).getName();
            case 1:
                return sessionUsers.get(rowIndex).getValue();
            default:
                return "Null";
        }
    }
    
    @Override
    public void setValueAt(Object value, int row, int column) {
        switch(column) {
            case 0:
                sessionUsers.get(row).setName( (String) value);
                break;
            case 1:
                sessionUsers.get(row).setValue( (String) value);
                break;
            default:
                return;
        }
    }

    int getUserCount() {
        return getRowCount();
    }

    SessionUser getUserAt(int newIndex) {
        return sessionUsers.get(newIndex);
    }

    
    void addLine() {
        SessionUser su = new SessionUser("User " + (sessionUsers.size() + 1), "");
        sessionUsers.add(su);
        
        this.fireTableDataChanged();
    }
    
    void addDefaultNew() {
        SessionUser su = new SessionUser("User 1", "useraaaa");
        sessionUsers.add(su);
        
        SessionUser suu = new SessionUser("User 2", "userbbb");
        sessionUsers.add(suu);
        
        this.fireTableDataChanged();
    }
    
    
    @Override
    public boolean isCellEditable(int row, int column) {
       return true;
    }

    String getSessionValueFor(String selectedSessionUser) {
        for (SessionUser u: sessionUsers) {
            if (u.getName().equals(selectedSessionUser) 
                    || u.getName().equals("<" + selectedSessionUser + ">")) {
                return u.getValue();
            }
        }
        return null;
    }

    LinkedList<SessionUser> getSessionUsers() {
        return sessionUsers;
    }

    /* Check if there are multiple entries with the same username
     * That's a no-go
     */
    boolean isSaneUserInput() {
        LinkedList<String> usernames = new LinkedList<String>();
        for(SessionUser u: sessionUsers) {
            if (u.getValue().equals("")) {
                return false;
            }
            
            usernames.add(u.getName());
        }
        
        Collections.sort(usernames);
        for (int n=0; n < usernames.size() - 1; n++) {
            if (usernames.get(n).equals(usernames.get(n+1))) {
                return false;
            }
        }
        
        return true;
    }

    void storeUiPrefs() {
        SettingsManager.storeSessions(sessionUsers);
    }

    void deleteEntry(int selectedRow) {
        sessionUsers.remove(selectedRow);
        this.fireTableDataChanged();
    }
    
}
