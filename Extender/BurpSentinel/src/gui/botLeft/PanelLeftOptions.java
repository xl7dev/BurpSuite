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
package gui.botLeft;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import util.SettingsManager;

/**
 * Provides Options submenu, and handles option details
 * 
 * Will provide the options menu for panelleft. It also has state of 
 * the following options:
 *   - Follow Redirects
 *   - Attack Vector insert location
 * 
 * 
 * @author DobinRutishauser@broken.ch
 */
public class PanelLeftOptions implements ActionListener {

    private JPopupMenu menuMain;
    // Menus
    private JMenu menuFollowRedirects;
    private JMenuItem menuItemEnableRedirect;
    private JMenuItem menuItemDisableRedirect;
    
    // Options
    private boolean optionEnableRedirect;

    public PanelLeftOptions() {
        init();
    }

    private void init() {
        // Options
        optionEnableRedirect = SettingsManager.restorePanelLeftOptionRedirect();

        // Menu
        menuMain = new JPopupMenu("Options");

        menuFollowRedirects = new JMenu("Follow Redirects: ");
        menuItemDisableRedirect = new JMenuItem("Disable");
        menuItemEnableRedirect = new JMenuItem("Enable");
        menuItemDisableRedirect.addActionListener(this);
        menuItemEnableRedirect.addActionListener(this);
        menuFollowRedirects.add(menuItemEnableRedirect);
        menuFollowRedirects.add(menuItemDisableRedirect);

        menuMain.add(menuFollowRedirects);

        refresh();
    }

    private void refresh() {
        if (optionEnableRedirect) {
            menuItemEnableRedirect.setEnabled(false);
            menuItemDisableRedirect.setEnabled(true);
        } else {
            menuItemEnableRedirect.setEnabled(true);
            menuItemDisableRedirect.setEnabled(false);
        }

    }

    void storeUiPrefs() {
        SettingsManager.storePanelLeftOptionRedirect(optionEnableRedirect);
    }

    public JPopupMenu getPopupMenu() {
        return menuMain;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == menuItemEnableRedirect) {
            optionEnableRedirect = true;
        } else if (e.getSource() == menuItemDisableRedirect) {
            optionEnableRedirect = false;
        }

        refresh();
    }

    boolean getOptionRedirect() {
        return optionEnableRedirect;
    }
}
