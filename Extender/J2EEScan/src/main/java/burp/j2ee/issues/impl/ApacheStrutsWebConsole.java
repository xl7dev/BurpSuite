package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
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



public class ApacheStrutsWebConsole implements IModule {

    private static final String TITLE = "Apache Struts - OGNL Console";
    private static final String DESCRIPTION = "J2EEscan identified the Apache Struts Web Console. <br />"
            + "This development console allows the evaluation of OGNL expressions that could lead to Remote Command Execution";
    private static final String REMEDY = "Restrict access to the struts console on the production server";

    private static final byte[] GREP_STRING = "title>OGNL Console".getBytes();
    private static final List<String> STRUTS_WEBCONSOLE_PATHS = Arrays.asList(
            "/struts/webconsole.html?debug=console"
    );

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();

    private PrintWriter stderr;

    
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        List<IScanIssue> issues = new ArrayList<>();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();
        String protocol = url.getProtocol();


        String system = host.concat(Integer.toString(port));

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            for (String webconsole_path : STRUTS_WEBCONSOLE_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
                    if (matches.size() > 0) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                checkRequestResponse,
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }
            }
        }

        /**
         * Test on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test the issue
         *
         * Ex: http://www.example.com/myapp/struts/webconsole.html
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            return issues;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);

            for (String webconsole_path : STRUTS_WEBCONSOLE_PATHS) {

                try {
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + webconsole_path);
                    byte[] webconsoleRequest = helpers.buildHttpRequest(urlToTest);

                    // make a request containing our injection test in the insertion point
                    IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                            baseRequestResponse.getHttpService(), webconsoleRequest);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
                    if (matches.size() > 0) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                checkRequestResponse,
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));
                    }
                } catch (MalformedURLException ex) {
                    stderr.println("Error creating URL " + ex.getMessage());
                }
            }

        }

        return issues;
    }
}
