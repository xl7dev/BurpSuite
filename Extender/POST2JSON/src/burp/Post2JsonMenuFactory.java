/*
 Copyright (C) 2013  Cyberis Ltd. Author geoff.jones@cyberis.co.uk

 This file is part of POST2JSON, a Burp Suite extender to convert a POST 
 request to a JSON message.

 POST2JSON is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 POST2JSON is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 * @author geoff.jones@cyberis.co.uk
 * @Copyright Cyberis Limited 2013
 *
 * Menu factory to create relevant menu items and register action listeners
 */
public class Post2JsonMenuFactory implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation context) {

        //Check we have an editable request
        if (context.getInvocationContext()
                == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {

            /**
             * As we have an editable request, we can be sure the first item in
             * the array is the message of interest
             */
            byte[] request = context.getSelectedMessages()[0].getRequest();

            //Only display menu if request is URL encoded (rather that JSON/XML etc)
            if (BurpExtender.helpers.analyzeRequest(request).getContentType()
                    == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {

                List<JMenuItem> menu = new ArrayList<>();

                JMenuItem post2Json = new JMenuItem("Change POST Request to JSON");

                //Add the action listener
                post2Json.addActionListener(new MenuActionListener(context));
                menu.add(post2Json);
                return menu;
            }
        }
        return null;
    }

    class MenuActionListener implements ActionListener {

        private IContextMenuInvocation myContext;

        private MenuActionListener(IContextMenuInvocation context) {
            myContext = context;
        }

        @Override
        public void actionPerformed(ActionEvent e) {

            //Get the selected message
            IHttpRequestResponse message = myContext.getSelectedMessages()[0];

            //Create a new JSON representation of the message
            JsonMessage jsonMessage = new JsonMessage(message);

            //Update the editor with the new JSON message
            message.setRequest(jsonMessage.getMessage());
        }
    }
}
