/*
 * BurpExtender.java
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
package burp;

import org.nibblesec.tools.BradamsaTab;
import org.nibblesec.tools.RadamsaPayloadGenerator;

/*
 * Bradamsa extension for Burp Suite
 *
 * Burp Suite is an integrated platform for performing web security testing (see http://www.portswigger.net/burp/)
 * Radamnsa is a test case generator for robustness testing (see https://code.google.com/p/ouspg/wiki/Radamsa)
 * Mix (B)urp Suite + (Radamsa) and you get crashes!
 */
public class BurpExtender implements IBurpExtender {

    private final String version = "v0.2";
    private IBurpExtenderCallbacks callbacks;
    private OS currentOS;
    private BradamsaTab btab;

    public enum OS {

        LINUX, MAC, WIN, UNDEF;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        callbacks.setExtensionName("Bradamsa " + version);

        //Get current platform
        String currentOSName = System.getProperty("os.name");
        if (currentOSName.toLowerCase().contains("linux")) {
            currentOS = OS.LINUX;
        } else if (currentOSName.toLowerCase().contains("mac")) {
            currentOS = OS.MAC;
        } else if (currentOSName.toLowerCase().contains("window")) {
            currentOS = OS.WIN;
        } else {
            currentOS = OS.UNDEF;
        }

        //Register Bradamsa as IntruderPayloadGenerator
        btab = new BradamsaTab(callbacks, currentOS);
        callbacks.registerIntruderPayloadGeneratorFactory((IIntruderPayloadGeneratorFactory) new RadamsaPayloadGenerator(this));
        callbacks.issueAlert("Ready to go");
    }

    public OS getPlatform() {

        return currentOS;
    }

    public IBurpExtenderCallbacks getCallbacks() {

        return callbacks;
    }

    public BradamsaTab getTab() {

        return btab;
    }

}