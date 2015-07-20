package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * This module tries to identify snoop resources to identify
 * possible information disclosure vulnerabilities and XSS issues
 * 
 */
public class SnoopResource implements IModule{

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host  port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();
    private PrintWriter stderr;

    private static final String XSS_PAYLOAD = "<h1>j2eescan"; 
    
    private static final List<String> SNOOP_PATHS = Arrays.asList(
            "/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/jsp/snp/snoop.jsp?" + XSS_PAYLOAD,
            "/examples/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/j2ee/servlet/SnoopServlet?" + XSS_PAYLOAD,
            "/jsp-examples/snp/snoop.jsp?" + XSS_PAYLOAD
    );

    // JSP snoop page</TITLE>
    // <TITLE>JSP snoop page</TITLE>
    // <TITLE>JBossEAP6.0 JSP snoop page</TITLE>
    // Path translated:
    private static final byte[] GREP_STRING = "Path translated".getBytes();

    private static final String TITLE = "Information Disclosure - Snoop";
    private static final String DESCRIPTION = "J2EEscan identified an information "
            + "disclosure vulnerability; the snoop resource/servlet contains "
            + "information regarding internal paths of the file system, and other "
            + "information that could be used for further attacks. ";
    private static final String REMEDY = "Restrict access to the resource only from trusted host/networks";
    
    private static final String TITLE_SNOOP_XSS = "XSS - Snoop";
    private static final String DESCRIPTION_SNOOP_XSS = "J2EEscan identified a XSS vulnerability on the Snoop resource";
    

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();

        String system = host.concat(Integer.toString(port));

        /**
         * Attempt on the web root
         *
         * http://www.example.com/snoop.jsp
         */
        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String SNOOP_PATH : SNOOP_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), SNOOP_PATH);
                    byte[] snoopTest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, snoopTest);

                    IResponseInfo snoopInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (snoopInfo.getStatusCode() == 200)) {
                           
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SNOOP_PATH),
                                new CustomHttpRequestResponse(snoopTest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.Low,
                                Confidence.Certain
                        ));

                        // Check XSS
                        List<int[]> matchesXSS = getMatches(response, XSS_PAYLOAD.getBytes(), helpers);
                        if (matchesXSS.size() > 0) {
                            issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SNOOP_PATH),
                                new CustomHttpRequestResponse(snoopTest, response, baseRequestResponse.getHttpService()),
                                TITLE_SNOOP_XSS,
                                DESCRIPTION_SNOOP_XSS,
                                REMEDY,    
                                Risk.Medium,
                                Confidence.Certain
                            ));
                        }
                        
                        
                        return issues;

                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        /**
         * Attempt on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test it
         *
         * Ex: http://www.example.com/myapp/snoop.jsp
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            return issues;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String SNOOP_PATH : SNOOP_PATHS) {

                try {
               
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + SNOOP_PATH);
                    byte[] snoopTest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, snoopTest);

                    IResponseInfo snoopInfo = helpers.analyzeResponse(response);

   
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (snoopInfo.getStatusCode() == 200)) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SNOOP_PATH),
                                new CustomHttpRequestResponse(snoopTest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.Low,
                                Confidence.Certain
                        ));

                        // Check XSS
                        List<int[]> matchesXSS = getMatches(response, XSS_PAYLOAD.getBytes(), helpers);
                        if (matchesXSS.size() > 0) {
                            issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), SNOOP_PATH),
                                new CustomHttpRequestResponse(snoopTest, response, baseRequestResponse.getHttpService()),
                                TITLE_SNOOP_XSS,
                                DESCRIPTION_SNOOP_XSS,
                                REMEDY,
                                Risk.Medium,
                                Confidence.Certain));
                        }
                        
                        return issues;

                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}
