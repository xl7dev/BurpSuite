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
package gui.mainTop;

import attacks.AttackData;
import gui.session.SessionManager;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Observable;
import java.util.Observer;
import javax.swing.table.AbstractTableModel;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import util.BurpCallbacks;

/**
 * The table model corresponding to PanelTopUi
 * 
 * PanelTopUi will display all HttpMessage from user/burp in a table
 * in the top part of the window.
 * 
 * Observer:
 * It observes changes in it's reference HttpMessages, to update UI accordingly
 * 
 * @author unreal
 */
public class PanelTopTableModel extends AbstractTableModel implements Observer {
    private PanelTopUi parent;
    private LinkedList<SentinelHttpMessageOrig> myMessages = new LinkedList<SentinelHttpMessageOrig>();
    
    public PanelTopTableModel(PanelTopUi parent) {
        this.parent = parent;
        SessionManager.getInstance().addObserver(this);
    }
    
    public void reset() {
        myMessages = new LinkedList<SentinelHttpMessageOrig>();
        this.fireTableDataChanged();
    }
    
    public void addMessage(SentinelHttpMessageOrig message) {
        myMessages.add(message);
        message.addObserver(this);
        message.setTableIndexMain(myMessages.size() - 1);
        
        // TODO
        //this.fireTableRowsInserted(myMessages.size() - 1, myMessages.size());
        this.fireTableDataChanged();
        //parent.setSelected(myMessages.size() - 1);
    }

    public SentinelHttpMessageOrig getMessage(int rowIndex) {
        return myMessages.get(rowIndex);
    }
    
    public void removeMessage(SentinelHttpMessageOrig removeMessage) {
        for(SentinelHttpMessageOrig msg: myMessages) {
            if (msg.getMessageNr() == removeMessage.getMessageNr()) {
                myMessages.remove(msg);
                break;
            }
        }
        this.fireTableDataChanged();
    }
    
    public int getRowForMessage(SentinelHttpMessageOrig msg) {
        return myMessages.indexOf(msg);
    }
    
    public SentinelHttpMessageOrig getMessageForRow(int n) {
        if (n >= myMessages.size()) {
            return null;
        } else {
            return myMessages.get(n);
        }
    }

    @Override
    public int getRowCount() {
        return myMessages.size();
    }

    @Override
    public int getColumnCount() {
        return 9;
    }

    
    @Override
    public Class getColumnClass(int columnIndex) {
        switch(columnIndex) {
            case 0: return Integer.class;
            default: return String.class;
        }
    }
    
    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1: 
                return "Method";
            case 2:
                return "URL";
            case 3: 
                return "Comment";
            case 4:
                return "Interesting";
            case 5:
                return "Session";
            case 6:
                return "Vulnerable";
            case 7:
                return "Created";
            case 8:
                return "Modified";
            default:
                return "hmm";
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        if (columnIndex == 3) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SentinelHttpMessageOrig httpMessage = myMessages.get(rowIndex);
        
        switch (columnIndex) {
            case 0:
                return rowIndex;
            case 1:
                return httpMessage.getReq().getMethod();
            case 2:
                URL url = null;
                try {
                    url = httpMessage.getReq().getUrl();
                } catch (Exception ex) {
                    BurpCallbacks.getInstance().print("getValueAt(): getUrl() failed on index: " + rowIndex);
                    return "<error getting url>";
                }
                return url.toString();
            case 3:
                if (httpMessage.getComment() == null) {
                    return "";
                } else {
                    return httpMessage.getComment();
                }
            case 4:
                //return httpMessage.getInterestingFact();
                return "";
            case 5:
                return httpMessage.getReq().getSessionValueTranslated();
            case 6:
                String r = getHighestVulnerabilityOf(httpMessage);
                if (r.equals("NONE")) {
                    r = "-";
                }
                return r;
            case 7:
                String s = "";
                SimpleDateFormat ft = new SimpleDateFormat ("dd.MM.YY HH:mm:ss");
                s = ft.format(httpMessage.getCreateTime());
                return  s;
            case 8:
                String ss = "";
                SimpleDateFormat fft = new SimpleDateFormat ("dd.MM.YY HH:mm:ss");
                Date d = httpMessage.getModifyTime();
                if (d == null) {
                    return "-";
                } else {
                    ss = fft.format(d);
                    return  ss;
                }
            default:
                return "";
        }
    }

    private String getHighestVulnerabilityOf(SentinelHttpMessageOrig httpMessage) {
        AttackData.AttackType attackType = AttackData.AttackType.NONE;
        
        for(SentinelHttpMessageAtk m: httpMessage.getHttpMessageChildren()) {
            if (m.getAttackResult() == null) {
                continue;
            }
            
            if (m.getAttackResult().isSuccess()) {
                if (m.getAttackResult().getAttackType().ordinal() > attackType.ordinal()) {
                    attackType = m.getAttackResult().getAttackType();
                }
            }
        }
        
        return attackType.toString();
    }

    /* Data the user is able to modify in this table:
     * - comment of initial http request
     */
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 3 && aValue instanceof String) {
            String s = (String) aValue;
            myMessages.get(rowIndex).setComment(s);
        }
    }

    /* We observe SessionManager
     * To update Session Information of requests in table (Username of session)
     */
    @Override
    public void update(Observable o, Object arg) {
        this.fireTableDataChanged();
        parent.setUpdateCurrentSelected();
    }
}
