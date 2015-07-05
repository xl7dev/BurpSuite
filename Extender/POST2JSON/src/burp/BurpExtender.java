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

import java.io.PrintWriter;

/**
 * POST2JSON Burp extender to convert a POST request to a JSON message
 * 
 * @author geoff.jones@cyberis.co.uk
 * @Copyright Cyberis Limited 2013
 */
public class BurpExtender implements IBurpExtender {

    static IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        //Set our extension name
        callbacks.setExtensionName("Cyberis Limited - POST2JSON Burp Extension");

        //Obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        //Write a message to the Burp alerts tab
        callbacks.issueAlert("Loaded successfully.");

        //Output important information
        stdout.println("Cyberis Limited POST2JSON Burp Extension Loaded\n");
        stdout.println("Copyright Cyberis Limited 2013");
        stdout.println("\nPOST2JSON is free software: you can redistribute it "
                + "and/or modify it under the terms of the GNU General Public "
                + "License as published by the Free Software Foundation, either "
                + "version 3 of the License, or (at your option) any later version.\n");
        stdout.println("Kindly report all issues via https://www.github.com/cyberisltd/POST2JSON");

        //Load the menu item, passsing it this Extender
        callbacks.registerContextMenuFactory(new Post2JsonMenuFactory());

        helpers = callbacks.getHelpers();
    }
}
