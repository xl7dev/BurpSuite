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

import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import javax.swing.JFrame;
import model.SentinelHttpMessage;
import model.SentinelHttpParam;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SqlmapManager {

    private static SqlmapManager sqlmapManager;
    
    
    public static SqlmapManager getInstance() {
        if (sqlmapManager == null) {
            sqlmapManager = new SqlmapManager();
        }
        
        return sqlmapManager;
    }
    
    private JFrame mainFrame;
    private SqlmapUi sqlmapUi;
    
    private SentinelHttpMessage httpMessage;
    private SentinelHttpParam attackParam;
    
    public SqlmapManager() {
        sqlmapUi = new SqlmapUi();
        
        mainFrame = new JFrame();
        mainFrame.setSize(1024, 786);
        mainFrame.add(sqlmapUi);
        mainFrame.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent e) {
            }

            @Override
            public void windowClosing(WindowEvent e) {
                sqlmapUi.storeConfig();
            }

            @Override
            public void windowClosed(WindowEvent e) {
            }

            @Override
            public void windowIconified(WindowEvent e) {
            }

            @Override
            public void windowDeiconified(WindowEvent e) {
            }

            @Override
            public void windowActivated(WindowEvent e) {
            }

            @Override
            public void windowDeactivated(WindowEvent e) {
            }
            
        });
    }
    
    public void showUi() {
        mainFrame.setVisible(true);
    }

    public void setHttpRequest(SentinelHttpMessage origHttpMessage, SentinelHttpParam attackParam) {
        this.httpMessage = origHttpMessage;
        this.attackParam = attackParam; 
        sqlmapUi.setHttpMessage(origHttpMessage, attackParam);
    }
    
}
