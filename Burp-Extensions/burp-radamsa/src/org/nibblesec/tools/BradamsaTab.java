/*
 * BradamsaTab.java
 *
 * Copyright (c) 2014 Luca Carettoni
 *
 * This file is part of Bradamsa, (B)urp Suite + (Radamsa)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY.
 *
 */
package org.nibblesec.tools;

import burp.BurpExtender.OS;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

public class BradamsaTab implements ITab {

    private final BradamsaPanel bPanel;

    public BradamsaTab(final IBurpExtenderCallbacks callbacks, OS os) {

        bPanel = new BradamsaPanel(callbacks, os);
        callbacks.customizeUiComponent(bPanel);
        callbacks.addSuiteTab(BradamsaTab.this);
    }

    @Override
    public String getTabCaption() {

        return "Bradamsa";
    }

    @Override
    public Component getUiComponent() {

        return bPanel;
    }
}
