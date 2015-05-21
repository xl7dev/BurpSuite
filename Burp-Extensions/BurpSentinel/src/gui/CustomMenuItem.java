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
package gui;

import burp.IHttpRequestResponse;
import burp.IMenuItemHandler;
import javax.swing.SwingUtilities;

/**
 * Creates the menu entry for burp to send requests to sentinel
 *
 * @author Dobin
 */
public class CustomMenuItem implements IMenuItemHandler {

    // Link to parent MainUi to add messages
    private SentinelMainApi mainApi;

    public CustomMenuItem(SentinelMainApi mainGui) {
        this.mainApi = mainGui;
    }

    @Override
    public void menuItemClicked(String menuItemCaption, final IHttpRequestResponse[] messageInfo) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < messageInfo.length; i++) {
                    mainApi.addNewMessage(messageInfo[i]);
                }
            }
        });
    }
}
