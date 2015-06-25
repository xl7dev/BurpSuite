/*
 * BradamsaPanel.java
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
import burp.BurpExtender.OS;
import burp.IBurpExtenderCallbacks;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;

public final class BradamsaPanel extends javax.swing.JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final OS os;

    public BradamsaPanel(IBurpExtenderCallbacks callbacks, OS os) {

        initComponents();
        this.callbacks = callbacks;
        this.os = os;

        //Initialize Radamsa options
        resetSettings();
        
        JOptionPane.showMessageDialog(null, "<html><b>Bradamsa</b> allows to generate Intruder payloads using <i>Radamsa</i>. "
                + "<br>The current version supports <u>sniper</u> attack type only!</html>", ":: Welcome to Bradamsa ::", JOptionPane.INFORMATION_MESSAGE);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        binary = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        count = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        output = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        seed = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        mutations = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();
        patterns = new javax.swing.JTextField();
        jLabel9 = new javax.swing.JLabel();
        meta = new javax.swing.JTextField();
        deleteAll = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        cmdline = new javax.swing.JTextArea();
        resetButton = new javax.swing.JButton();

        jLabel1.setForeground(new java.awt.Color(255, 102, 0));
        jLabel1.setText("Radamsa command line options");

        jLabel2.setText("Binary:");

        binary.setToolTipText("");
        binary.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
        binary.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                binaryFocusLost(evt);
            }
        });

        jLabel3.setText("<html>For more details, please refer to the official Radamsa homepage (<a href='https://code.google.com/p/ouspg/'>https://code.google.com/p/ouspg/</a>)</html>");

        jLabel4.setText("Count:");

        count.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
        count.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                countFocusLost(evt);
            }
        });

        jLabel5.setText("Output:");

        output.setToolTipText("");
        output.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
        output.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                outputFocusLost(evt);
            }
        });

        jLabel6.setText("Seed:");

        seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
        seed.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                seedFocusLost(evt);
            }
        });

        jLabel7.setText("Mutations:");

        mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
        mutations.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                mutationsFocusLost(evt);
            }
        });

        jLabel8.setText("Patterns:");

        patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
        patterns.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                patternsFocusLost(evt);
            }
        });

        jLabel9.setText("Meta:");

        meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
        meta.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                metaFocusLost(evt);
            }
        });

        deleteAll.setSelected(true);
        deleteAll.setText("Delete sample files after execution");

        cmdline.setEditable(false);
        cmdline.setBackground(getBackground());
        cmdline.setColumns(20);
        cmdline.setForeground(new java.awt.Color(0, 153, 102));
        cmdline.setLineWrap(true);
        cmdline.setRows(3);
        cmdline.setText("$");
        cmdline.setToolTipText("");
        cmdline.setBorder(javax.swing.BorderFactory.createTitledBorder("Resulting Command Line:"));
        jScrollPane1.setViewportView(cmdline);

        resetButton.setText("Reset Settings");
        resetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                resetButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(17, 17, 17)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 709, Short.MAX_VALUE)
                        .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(deleteAll)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(resetButton))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel4)
                            .addComponent(jLabel5)
                            .addComponent(jLabel9)
                            .addComponent(jLabel8)
                            .addComponent(jLabel7)
                            .addComponent(jLabel6))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(patterns)
                            .addComponent(mutations, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(seed, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(output, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(count, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(binary, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(meta, javax.swing.GroupLayout.PREFERRED_SIZE, 779, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jScrollPane1))
                .addContainerGap(19, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(binary, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(count, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(output, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(seed, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(mutations, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(patterns, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(meta, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel9))
                .addGap(13, 13, 13)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(deleteAll)
                    .addComponent(resetButton))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(14, 14, 14))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void binaryFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_binaryFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_binaryFocusLost

    private void countFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_countFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_countFocusLost

    private void outputFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_outputFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_outputFocusLost

    private void seedFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_seedFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_seedFocusLost

    private void mutationsFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_mutationsFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_mutationsFocusLost

    private void patternsFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_patternsFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_patternsFocusLost

    private void metaFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_metaFocusLost

        getRadamsaCmdLine();
    }//GEN-LAST:event_metaFocusLost

    private void resetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_resetButtonActionPerformed
        resetSettings();
    }//GEN-LAST:event_resetButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField binary;
    private javax.swing.JTextArea cmdline;
    private javax.swing.JTextField count;
    private javax.swing.JCheckBox deleteAll;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField meta;
    private javax.swing.JTextField mutations;
    private javax.swing.JTextField output;
    private javax.swing.JTextField patterns;
    private javax.swing.JButton resetButton;
    private javax.swing.JTextField seed;
    // End of variables declaration//GEN-END:variables

    /*
     * Validate and return Radamsa command line 
     * @return the full command string or an empty string (in case of invalid input)
     */
    protected String getRadamsaCmdLine() {

        StringBuilder cmdSB = new StringBuilder();

        //Radamsa binary path - mandatory
        if (validateBinary()) {
            binary.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(binary.getText().toLowerCase().trim());
        } else {
            binary.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid Radamsa binary path. Have you installed it? Where?");
            return "";
        }
        //Samples count - mandatory
        if (validateCount()) {
            count.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(" -n ");
            cmdSB.append(count.getText().toLowerCase().trim());
        } else {
            count.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Count option is not 'number'");
            return "";
        }
        //Output directory - mandatory
        if (validateOutput()) {
            output.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
            cmdline.setForeground(new java.awt.Color(0, 153, 102));
            cmdSB.append(" -o ");
            cmdSB.append(output.getText().toLowerCase().trim());
        } else {
            output.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Missing output directory or incorrect permissions");
            return "";
        }
        //Seed - optional
        if (validateSeed()) {
            if (!seed.getText().toLowerCase().trim().isEmpty()) {
                seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -s ");
                cmdSB.append(seed.getText().toLowerCase().trim());
            } else {
                seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            seed.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Seed is not 'number'");
            return "";
        }
        //Mutations - optional
        if (validateMutations()) {
            if (!mutations.getText().toLowerCase().trim().isEmpty()) {
                mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -m ");
                cmdSB.append(mutations.getText().toLowerCase().trim());
            } else {
                mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            mutations.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid mutations [ft=2,fo=2,fn,num=3,td,tr2,ts1,tr,ts2,ld,lr2,li,ls,lp,lr,sr,bd,bf,bi,br,bp,bei,bed,ber,uw,ui]");
            return "";
        }
        //Patterns - optional
        if (validatePatterns()) {
            if (!patterns.getText().toLowerCase().trim().isEmpty()) {
                patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -p ");
                cmdSB.append(patterns.getText().toLowerCase().trim());
            } else {
                patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            patterns.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Invalid mutations pattern [od,nd,bu]");
            return "";
        }
        //Meta - optional
        if (validateMeta()) {
            if (!meta.getText().toLowerCase().trim().isEmpty()) {
                meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 153, 102), 2));
                cmdline.setForeground(new java.awt.Color(0, 153, 102));
                cmdSB.append(" -M ");
                cmdSB.append(meta.getText().toLowerCase().trim());
            } else {
                meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153), 2));
            }
        } else {
            meta.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(240, 0, 0), 2));
            cmdline.setForeground(new java.awt.Color(240, 0, 0));
            cmdline.setText("Missing metadata directory or incorrect permissions");
            return "";
        }

        cmdline.setText(cmdSB.toString());
        return cmdSB.toString();
    }

    protected boolean validateBinary() {

        if (binary.getText().toLowerCase().trim().isEmpty()) {
            return false;
        }
        File f = new File(binary.getText().toLowerCase().trim());
        return f.exists() && !f.isDirectory();

        //This method could verify the actual binary, but we would need to execute it. Potentially unsafe!
        // try {
        //  String stdOut = BurpUtils.execute(f.getAbsolutePath().concat(" -V"), callbacks, true);
        //  return stdOut.contains("Radamsa"); //expect "Radamsa 0.3"
        // } catch (IOException | InterruptedException cmdEx) {
        //  return false;
        // }
    }

    protected boolean validateCount() {

        try {
            Long.valueOf(count.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return false;
        }
        return true;
    }

    protected boolean validateOutput() {

        String outputStr = output.getText().toLowerCase().trim();
        if (outputStr.isEmpty()) {
            return false;
        }

        File f = new File(outputStr.substring(0, outputStr.lastIndexOf(File.separatorChar)));
        return f.exists() && f.isDirectory();
    }

    protected boolean validateSeed() {

        if (seed.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        try {
            Long.valueOf(seed.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return false;
        }

        return true;
    }

    protected boolean validateMutations() {

        if (mutations.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        return Pattern.matches("(\\p{Alnum}+)(=\\p{Digit}+)?(,(\\p{Alnum}+)(=\\p{Digit}+)?)*", mutations.getText().toLowerCase().trim());
    }

    protected boolean validatePatterns() {

        if (patterns.getText().toLowerCase().trim().isEmpty()) {
            return true;
        }

        return Pattern.matches("(od|nd|bu)+(,(od|nd|bu))*", patterns.getText().toLowerCase().trim());
    }

    protected boolean validateMeta() {

        String metaStr = meta.getText().toLowerCase().trim();
        if (metaStr.isEmpty()) {
            return true;
        }

        if (!metaStr.contains(String.valueOf(File.separatorChar))) {
            return false;
        }
        
        if (metaStr.charAt(metaStr.length()-1) == File.separatorChar) {
            return false;
        }

        File f = new File(metaStr.substring(0, metaStr.lastIndexOf(File.separatorChar)));
        return f.exists() && f.isDirectory();
    }

    protected File getOutputDir() {

        String outputStr = output.getText().toLowerCase().trim();
        File fout = new File(outputStr.substring(0, outputStr.lastIndexOf(File.separatorChar)));

        return fout;
    }

    protected Long getCount() {

        try {
            return Long.valueOf(count.getText().toLowerCase().trim());
        } catch (NumberFormatException numExc) {
            return (long) 0;
        }
    }

    protected boolean deleteFiles() {

        return deleteAll.isSelected();
    }

    private void resetSettings() {

        //Radamsa binary path
        if (os.equals(BurpExtender.OS.LINUX)) {
            binary.setText("/usr/bin/radamsa");
        } else if (os.equals(BurpExtender.OS.MAC)) {
            binary.setText("/usr/bin/radamsa");
        } else if (os.equals(BurpExtender.OS.WIN)) {
            binary.setText("Add here radamsa-0.3.exe filepath");
        } else {
            binary.setText("Add here the Radamsa binary path");
        }

        //Samples count
        count.setText("10");

        //Output directory
        try {
            //Create default temporary directory for samples
            Path tmpDirectory = Files.createTempDirectory("radamsa");
            tmpDirectory.toFile().deleteOnExit();
            output.setText(tmpDirectory.toFile().getAbsolutePath() + File.separatorChar + "%n.out");
        } catch (IOException ex) {
            new PrintWriter(callbacks.getStdout()).println("[!] Bradamsa Exception: BradamsaPanel IOException");
        }

        seed.setText("");
        mutations.setText("");
        patterns.setText("");
        meta.setText("");
        deleteAll.setSelected(true);
        cmdline.setText(getRadamsaCmdLine());
    }
}
