package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.HTTPMatcher;
import static burp.HTTPMatcher.getApplicationContext;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.J2EELFIRetriever;
import static burp.J2EELocalAssessment.analyzeWEBXML;
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
 * This module tries to retrieve configuration files under the WEB-INF folder
 * with a direct GET request.
 *
 * Sometimes "misconfigured" or vulnerable components allow direct download of
 * WEB-INF/ folder resources
 *
 */
public class WebInfInformationDisclosure implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host  port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();
    private PrintWriter stderr;

    private static final List<String> WEBINF_PATHS = Arrays.asList(
            "/WEB-INF./web.xml",
            "//WEB-INF/web.xml",
            "/WEB-INF/web.xml",
            "/static/WEB-INF/web.xml", // CVE-2014-0053 
            "/forward:/WEB-INF/web.xml" // spring issue
    );

    private static final byte[] GREP_STRING = "<web-app".getBytes();

    private static final String TITLE = "Java Application WEB-INF Content Retrieved";
    private static final String REMEDY = "Identify and update the vulnerable component<br />"
                + "<b>References</b>:<br /><br />"
                + "http://www.hpenterprisesecurity.com/vulncat/en/vulncat/java/file_disclosure_spring_webflow.html<br />"
                + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0053<br />"
                + "https://o2platform.files.wordpress.com/2011/07/ounce_springframework_vulnerabilities.pdf<br />";
               
    private static final String DESCRIPTION = "J2EEscan retrieved files located under "
            + "the '<i>WEB-INF</i>' folder. <br /><br />This vulnerability could be "
            + "used to disclose any file under the web app root (example: Java classes and source code, "
            + "j2ee jar libraries, properties files with sensitive credentials)."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2002-1859<br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2002-1858<br />"
            + "http://www.pivotal.io/security/cve-2014-0053<br />"
            + "http://www.springsource.com/securityadvisory";

    @Override
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
         * http://www.example.com/WEB-INF/web.xml
         */
        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String WEBINF_PATH : WEBINF_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), WEBINF_PATH);
                    byte[] webinfRootRequest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, webinfRootRequest);

                    IResponseInfo webInfInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (webInfInfo.getStatusCode() == 200)) {

                        // Retrieve servlet classes                                
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), WEBINF_PATH),
                                new CustomHttpRequestResponse(webinfRootRequest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION + " " + HTTPMatcher.getServletsDescription(helpers.bytesToString(response)),
                                REMEDY,
                                Risk.High,
                                Confidence.Firm
                        ));

                        // Security Audit web.xml
                        analyzeWEBXML(response, 
                                      callbacks, 
                                      new CustomHttpRequestResponse(webinfRootRequest, 
                                      response, 
                                      baseRequestResponse.getHttpService())
                        );
                        
                        
                        // Try to retrieve more configuration files from the this vulnerability
                        J2EELFIRetriever.download(callbacks,
                                new CustomHttpRequestResponse(webinfRootRequest, response, baseRequestResponse.getHttpService()),
                                webinfRootRequest,
                                "/WEB-INF/web.xml");

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
         * Ex: http://www.example.com/myapp/WEB-INF/web.xml
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

            for (String WEBINF_PATH : WEBINF_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + WEBINF_PATH);
                    byte[] webinfCtxRequest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, webinfCtxRequest);

                    IResponseInfo webInfInfo = helpers.analyzeResponse(response);

                    // look for matches of our active check grep string
                    List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                    if ((matches.size() > 0) && (webInfInfo.getStatusCode() == 200)) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), WEBINF_PATH),
                                new CustomHttpRequestResponse(webinfCtxRequest, response, baseRequestResponse.getHttpService()),
                                TITLE,
                                DESCRIPTION + " " + HTTPMatcher.getServletsDescription(helpers.bytesToString(response)),
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));

                        // Security Audit web.xml
                        analyzeWEBXML(response, 
                                callbacks, 
                                new CustomHttpRequestResponse(
                                        webinfCtxRequest, 
                                        response, 
                                        baseRequestResponse.getHttpService()));

                        // Try to retrieve more configuration files from the this vulnerability
                        J2EELFIRetriever.download(callbacks,
                                new CustomHttpRequestResponse(webinfCtxRequest, 
                                         response, 
                                         baseRequestResponse.getHttpService()),
                                webinfCtxRequest,
                                "/WEB-INF/web.xml");

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
