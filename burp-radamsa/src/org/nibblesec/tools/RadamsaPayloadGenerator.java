/*
 * RadamsaPayloadGenerator.java
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

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import javax.swing.JOptionPane;
import org.apache.commons.io.FileUtils;

public class RadamsaPayloadGenerator implements IIntruderPayloadGenerator, IIntruderPayloadGeneratorFactory {

    private final IBurpExtenderCallbacks callbacks;
    private boolean firstInvoke;
    private ArrayList<File> samples;
    private Iterator<File> samplesIte;
    private BradamsaPanel panel;

    public RadamsaPayloadGenerator(BurpExtender burpExt) {

        callbacks = burpExt.getCallbacks();
        panel = (BradamsaPanel) burpExt.getTab().getUiComponent();
        firstInvoke = true;
        samples = new ArrayList<>();
        samplesIte = samples.iterator();
    }

    @Override
    public boolean hasMorePayloads() {

        if (firstInvoke) {
            return true;
        }
        return samplesIte.hasNext();
    }

    @Override
    public byte[] getNextPayload(byte[] basePayload) {

        byte[] result = null;

        if(basePayload == null){
            //Display warning. Battering ram attack type was selected
            JOptionPane.showMessageDialog(null, "Bradamsa can only be used in a sniper attack", "Abort", JOptionPane.ERROR_MESSAGE);
            firstInvoke = false;
        }
        
        try {
            if (firstInvoke) {
                //Generate samples from Burp's payload
                String cmdLine = panel.getRadamsaCmdLine();
                if (!cmdLine.isEmpty()) {
                    if (panel.getCount() > 9999) {
                        JOptionPane.showMessageDialog(null, "<html>As you've selected an high count number,"
                                + " generating all Radamsa samples may take some time.<br>Your intruder "
                                + "attack will start once all samples are successfully generated.</html>", "Radamsa Samples Generation", JOptionPane.INFORMATION_MESSAGE);
                    }

                    BurpUtils.executeAndPipe(cmdLine, basePayload, callbacks, true);

                    //If enabled, mark all files for deletion before JVM shutdown 
                    if (panel.deleteFiles()) {
                        for (File file : panel.getOutputDir().listFiles()) {
                            file.deleteOnExit();
                        }
                    }
                } else {
                    //Display warning. Invalid user input 
                    JOptionPane.showMessageDialog(null, "Invalid command line arguments", "Check the 'Bradamsa' tab...", JOptionPane.WARNING_MESSAGE);
                }
                //create samples index
                samples.addAll(Arrays.asList(panel.getOutputDir().listFiles()));
                samplesIte = samples.iterator();
                //prevent further initialization
                firstInvoke = false;
            }

            if (samplesIte.hasNext()) {
                File currentSample = samplesIte.next();
                result = FileUtils.readFileToByteArray(currentSample);
                //If enabled, remove the sample as it has been already used
                if (panel.deleteFiles()) {
                    currentSample.delete();
                }
            }
        } catch (IOException | InterruptedException ex) {
            new PrintWriter(callbacks.getStdout()).println("[!] Bradamsa Exception: RadamsaPayloadGenerator.getNextPayload()");
        }
        return result;
    }

    @Override
    public void reset() {

        samples.clear();
        samplesIte = samples.iterator();
        firstInvoke = true;
    }

    @Override
    public String getGeneratorName() {
    
        return "Bradamsa";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack iia) {

        //Delete previous samples, if applicable
        if (panel.deleteFiles()) {
            for (File file : panel.getOutputDir().listFiles()) {
                file.delete();
            }
        }

        samples.clear();
        samplesIte = samples.iterator();
        firstInvoke = true;
        return this;
    }
}
