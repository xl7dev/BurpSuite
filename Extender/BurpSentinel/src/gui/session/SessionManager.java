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

import java.util.LinkedList;
import java.util.Observable;

/**
 *
 * @author unreal
 */
public class SessionManager extends Observable {

    private static SessionManager sessionManager;
    private SessionManagerUi sessionManagerUi;
        
    
    public SessionManager() {
        this.sessionManagerUi = new SessionManagerUi();
    }
    
    public static SessionManager getInstance() {
        if (sessionManager == null) {
            sessionManager = new SessionManager();
        }
        
        return sessionManager;
    }
    
    public SessionManagerUi getSessionManagerUi() {
        return sessionManagerUi;
    }

    public int getUserCount() {
        return sessionManagerUi.getUserCount();
    }

    public SessionUser getUserAt(int newIndex) {
        return sessionManagerUi.getUserAt(newIndex);
    }

    public String getSessionVarName() {
        return sessionManagerUi.getSessionVarName();
    }

    public String getValueFor(String selectedSessionUser) {
        return sessionManagerUi.getSessionValueFor(selectedSessionUser);
    }

    public LinkedList<SessionUser> getSessionUsers() {
        return sessionManagerUi.getSessionUsers();
    }

    public SessionUser getUserFor(String value) {
        for (int n = 0; n < getUserCount(); n++) {
            SessionUser u = getUserAt(n);

            if (value.equals(u.getValue())) {
                return u;
            }
        }
        
        return null;
    }

    void myNotify() {
        this.setChanged();
        this.notifyObservers();
    }
    
}
