package burp.j2ee.issues.impl;

import burp.HTTPMatcher;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * Detection of the Jetty Remote Leak Shared Buffers research of GDS Security
 * 
 * References:
 * 
 * http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html
 * https://github.com/GDSSecurity/Jetleak-Testing-Script 
 * https://twitter.com/gdssecurity
 *
 */
public class JettyRemoteLeakage implements IModule {

    private static final String TITLE = "Jetty Remote Leak Shared Buffers";
    private static final String DESCRIPTION = "J2EEScan identified a vulnerable Jetty instance; "
            + "remote unauthenticated users are able to read arbitrary data from other HTTP sessions<br /><br />"
            + "<b>References</b>:<br />"
            + "http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html<br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2080";

    private static final String REMEDY = "Update the Jetty component with the last stable release";
    private static final byte[] INJ_TEST = {(byte) 0};
    private static final byte[] GREP_STRING = "400 Illegal character 0x0 in state".getBytes();

    private PrintWriter stderr;

    
    private Boolean isJettyDetected(IBurpExtenderCallbacks callbacks) {
        Boolean hasJettyBeenDetected = false;

        String jettyIssue = "Information Disclosure - Jetty";

        IScanIssue[] allIssues;
        allIssues = callbacks.getScanIssues(null);
        for (IScanIssue a : allIssues) {
            if (a.getIssueName().contains(jettyIssue)) {
                return true;
            }
        }

        return hasJettyBeenDetected;
    }

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();
        IExtensionHelpers helpers = callbacks.getHelpers();

        stderr = new PrintWriter(callbacks.getStderr(), true);

        IHttpRequestResponse jettyResponse;

        // Execute the test only if Burpsuite detected a Jetty Servlet container
        // to limitate unnecessary HTTP requests
        if (!isJettyDetected(callbacks)) {
            return issues;
        }

        if (!"Referer".equals(insertionPoint.getInsertionPointName())) {
            return issues;
        }

        // make a request containing null byte to trigger the HTTP response code 400
        byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);

        jettyResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);

        try {
            byte[] response = jettyResponse.getResponse();

            if (response != null) {

                List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                if (matches.size() > 0) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            jettyResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }
            }

        } catch (Exception ex) {
            stderr.println(ex);
        }

        return issues;

    }
}
