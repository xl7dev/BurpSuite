/*
 * BurpUtils.java
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

import burp.IBurpExtenderCallbacks;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import org.apache.commons.io.IOUtils;

public class BurpUtils {

    /*
     * Retrieve the HTTP message body from a request/response
     */
    public static byte[] getBody(byte[] request) {

        int offset = 0;
        byte[] body = null;

        for (int i = 0; i < request.length; i++) {
            if (i + 3 <= request.length) {
                if (request[i] == 13 && request[i + 1] == 10 && request[i + 2] == 13 && request[i + 3] == 10) {
                    offset = i + 4; //Got a \r\n\r\n
                }
            }
        }

        if (offset != 0 && offset < request.length) {
            body = new byte[request.length - offset];
            int cont = 0;
            for (int i = offset; i < request.length; i++) {
                body[cont] = request[i];
                cont++;
            }
        }
        return body;
    }

    /*
     * Retrieve the cookies header field from a request/response
     */
    public static String getCookies(byte[] request) {

        String requestStr = new String(request);
        String cookies = "";

        if (requestStr.contains("Cookie:")) {
            cookies = requestStr.substring(requestStr.indexOf("Cookie:"));
            cookies = cookies.substring(7, cookies.indexOf("\r\n")).trim();
        }
        return cookies;
    }

    /*
     * Retrieve the host header field from a request/response
     */
    public static String getHost(byte[] request) {

        String requestStr = new String(request);
        String cookies = "";

        if (requestStr.contains("Host:")) {
            cookies = requestStr.substring(requestStr.indexOf("Host:"));
            cookies = cookies.substring(5, cookies.indexOf("\r\n")).trim();
        }
        return cookies;
    }

    /*
     * Execute a system command and return stdOut as a String
     */
    public static String execute(String cmdLine, IBurpExtenderCallbacks callbacks, boolean waitFor) throws IOException, InterruptedException {

        ProcessBuilder pb = new ProcessBuilder(cmdLine.split(" "));
        callbacks.issueAlert("Executing: " + cmdLine);
        final Process process;

        process = pb.start();

        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

        if (waitFor) {
            process.waitFor();
        }

        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            builder.append(line);
            builder.append(System.getProperty("line.separator"));
        }
        return builder.toString();
    }

    /*
     * Execute a system command, pipe stdOut and stdErr to Burp's stream and allow stdIn data
     */
    public static void executeAndPipe(String cmdLine, byte[] stdInputData, IBurpExtenderCallbacks callbacks, boolean waitFor) throws IOException, InterruptedException {

        ProcessBuilder pb = new ProcessBuilder(cmdLine.split(" "));
        callbacks.issueAlert("Executing: " + cmdLine);
        final Process process;

        process = pb.start();

        pipe(process.getErrorStream(), new PrintStream(callbacks.getStderr()));
        pipe(process.getInputStream(), new PrintStream(callbacks.getStdout()));

        if (stdInputData != null) {
            //Stream more data to stdIn
            OutputStream stdin = process.getOutputStream();
            IOUtils.write(stdInputData, stdin);
            IOUtils.closeQuietly(stdin);
        }

        if (waitFor) {
            process.waitFor();
        }
    }

    private static void pipe(final InputStream src, final PrintStream dest) {

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] buffer = new byte[1024];
                    for (int n = 0; n != -1; n = src.read(buffer)) {
                        dest.write(buffer, 0, n);
                    }
                } catch (IOException e) {
                }
            }
        }).start();
    }

    /*
     * Basic implementation of String repeat 
     */
    public static String repeat(String str, int times) {

        if (str == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) {
            sb.append(str);
        }
        return sb.toString();
    }
}
