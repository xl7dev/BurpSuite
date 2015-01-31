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

import attacks.AttackMain;
import gui.lists.ListManager;
import gui.lists.ListManagerList;
import gui.sqlmap.SqlmapManager;
import gui.sqlmap.SqlmapUi;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import model.SentinelHttpParam;
import model.SentinelHttpParamVirt;
import util.BurpCallbacks;

/**
 * Provides the popup menu for parameters.
 * 
 * When user right-clicks on an parameter in panelleft, menu will show up.
 * Menu entries:
 *   - Attack param 
 *   - Attack param with list
 *   - Add decoded param
 * 
 * Note that attack lists are in flux, and therefore the menu entries need
 * to be updated with refreshAttackList() when changed.
 * 
 *
 * @author DobinRutishauser@broken.ch
 */
public class PanelLeftPopup implements ActionListener {

    private PanelLeftUi parent;
    
    private JPopupMenu menu;
    
    private JMenu attackSubmenu;
    private JMenu attackListSubmenu;
    private JMenu decodeSubmenu;
    private JMenuItem sqlmapEntry;
    
    private LinkedList<JMenuItem> attackMenuItems;
    private LinkedList<JMenuItem> attackListMenuItems;
    
    private JMenuItem decodeURL;
    private JMenuItem decodeHTML;
    private JMenuItem decodeBase64;

    public PanelLeftPopup(PanelLeftUi parent) {
        this.parent = parent;

        menu = new JPopupMenu("Message");

        attackSubmenu = new JMenu("Attack with ");
        initAttackSubmenu();
        menu.add(attackSubmenu);

        attackListSubmenu = new JMenu("Attack with list");
        menu.add(attackListSubmenu);
        attackListMenuItems = new LinkedList<JMenuItem>();
        refreshAttackListIndex();

        decodeSubmenu = new JMenu("Decode as");
        initDecodeSubmenu();
        menu.add(decodeSubmenu);
        
        sqlmapEntry = new JMenuItem("Open with SQLMap");
        sqlmapEntry.addActionListener(this);
        menu.add(sqlmapEntry);
    }

    public JPopupMenu getPopup() {
        return menu;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Object o = e.getSource();

        testActionAttack(o);
        testActionAttackList(o);
        testActionDecode(o);
        testActionSqlmap(o);
    }

    /**
     * * SQLMap **
     */
    
    private void testActionSqlmap(Object o) {
        if (o == sqlmapEntry) {
            SqlmapManager.getInstance().setHttpRequest(parent.getOrigHttpMessage(), parent.getSelectedHttpParam());
            SqlmapManager.getInstance().showUi();
        }
    }
    
    
    /**
     * * Attack **
     */
    private void testActionAttack(Object o) {
        AttackMain.AttackTypes atkType;
        
        int n = attackMenuItems.indexOf(o);
        if (n >= 0) {
            attack(n);
        }
    }
    
    private void attack(int n) {
        AttackMain.AttackTypes attackType;
        
        String atkStr = attackMenuItems.get(n).getText();
        attackType = AttackMain.AttackTypes.valueOf(atkStr);
        
        // get current param
        SentinelHttpParam httpParam = parent.getSelectedHttpParam();

        // attack it
        parent.attackSelectedParam(httpParam, attackType, null);
    }

    private void initAttackSubmenu() {
        attackMenuItems = new LinkedList<JMenuItem>();

        JMenuItem title = new JMenuItem("Attack with:");
        title.setEnabled(false);
        attackSubmenu.add(title);

        AttackMain.AttackTypes displayTypes[] = {
            // Removed following two, as they are already available with checkboxes
//            AttackMain.AttackTypes.SQL, 
//            AttackMain.AttackTypes.XSS,
            AttackMain.AttackTypes.XSSLESSTHAN,
            AttackMain.AttackTypes.OTHER,
            AttackMain.AttackTypes.AUTHORISATION,
        };
        
        //for (AttackMain.AttackTypes atkType: AttackMain.AttackTypes.values()) {
        for (AttackMain.AttackTypes atkType: displayTypes) {
            JMenuItem menuItem = new JMenuItem(atkType.name());
            attackMenuItems.add(menuItem);
            attackSubmenu.add(menuItem);
            menuItem.addActionListener(this);
        }

    }
    

    /**
     * * Attack List **
     */
    private void testActionAttackList(Object o) {
        // Test Attack

        int n = attackListMenuItems.indexOf(o);
        if (n >= 0) {
            attackList(n);
        }
    }

    private void attackList(int n) {
        // get current param
        SentinelHttpParam httpParam = parent.getSelectedHttpParam();

        String options = Integer.toString(n);
        
        // attack it
        parent.attackSelectedParam(httpParam, AttackMain.AttackTypes.LIST, options);
    }

    void refreshAttackListIndex() {
        for (JMenuItem item : attackListMenuItems) {
            item.removeActionListener(this);
        }
        attackListMenuItems = new LinkedList<JMenuItem>();
        attackListSubmenu.removeAll();

        JMenuItem title = new JMenuItem("Attack with list:");
        title.setEnabled(false);
        attackListSubmenu.add(title);

        for (ListManagerList list : ListManager.getInstance().getModel().getList()) {
            JMenuItem menuItem = new JMenuItem(list.getName());
            attackListMenuItems.add(menuItem);
            attackListSubmenu.add(menuItem);
            menuItem.addActionListener(this);
        }

    }
    

    /**
     * * Decode **
     */
    private void testActionDecode(Object o) {

        // Test decode
        if (o == decodeBase64) {
            decodeIt(SentinelHttpParamVirt.EncoderType.Base64);
        } else if (o == decodeHTML) {
            decodeIt(SentinelHttpParamVirt.EncoderType.HTML);
        } else if (o == decodeURL) {
            decodeIt(SentinelHttpParamVirt.EncoderType.URL);
        }
    }

    private void decodeIt(SentinelHttpParamVirt.EncoderType encoderType) {
        // get current param
        SentinelHttpParam httpParam = parent.getSelectedHttpParam();

        // Create new virt param
        SentinelHttpParamVirt virtParam = new SentinelHttpParamVirt(httpParam, encoderType);

        parent.getOrigHttpMessage().getReq().addParamVirt(virtParam);

        // TODO: remove all old selections
        parent.updateModel();
    }


    private void initDecodeSubmenu() {
        decodeBase64 = new JMenuItem("Decode Base64");
        decodeHTML = new JMenuItem("Decode HTML");
        decodeURL = new JMenuItem("Decode URL");

        decodeURL.addActionListener(this);
        decodeHTML.addActionListener(this);
        decodeBase64.addActionListener(this);

        decodeSubmenu.add(decodeURL);
        decodeSubmenu.add(decodeHTML);
        decodeSubmenu.add(decodeBase64);
    }
}
