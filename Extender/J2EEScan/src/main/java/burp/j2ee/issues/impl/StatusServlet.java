package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
import burp.HTTPParser;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import static burp.WeakPasswordBruteforcer.HTTPBasicBruteforce;
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

public class StatusServlet implements IModule {

    private static final String TITLE = "Apache/Jboss Status Servlet - Information Disclosure";
    private static final String DESCRIPTION = "J2EEscan identified the status servlet "
            + " on the remote system. It's possible to retrive information regarding installed applications and/or "
            + "recent accessed URLs (with valid JSessionIDs)."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=457757<br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=585900<br />"
            + "https://docs.jboss.org/author/display/AS72/Hardening+Guidelines<br />"
            + "http://carnal0wnage.attackresearch.com/2012/04/from-low-to-pwned-3-jbosstomcat-server.html<br />"
            + "http://tomcat.apache.org/tomcat-7.0-doc/security-howto.html<br />";
    private static final String REMEDY = "Restrict access to the resource only from trusted host/networks";
    
    
    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> STATUS_SERVLET_PATHS = Arrays.asList(
            "/status?full=true",
            "/web-console/status?full=true",
            "/server-status?full=true"
    );

    private PrintWriter stderr;
    private static final byte[] GREP_STRING_J2EE = "Status Servlet".getBytes();
    private static final byte[] GREP_STRING_HTTPD = "Apache Server Status".getBytes();

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

        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            String protocol = url.getProtocol();
            Boolean isSSL = (protocol.equals("https"));

            for (String STATUS_SERVLET_PATH : STATUS_SERVLET_PATHS) {

                try {
                    // Test the presence of tomcat console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), STATUS_SERVLET_PATH);
                    byte[] statustest = helpers.buildHttpRequest(urlToTest);

                    byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, statustest);

                    // look for matches of our active check grep string in the response body
                    IResponseInfo statusInfo = helpers.analyzeResponse(responseBytes);

                    /*
                     *  Try basic HTTP Authentication Bruteforcing
                     */
                    if (statusInfo.getStatusCode() == 401) {

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                urlToTest,
                                new CustomHttpRequestResponse(statustest, responseBytes, baseRequestResponse.getHttpService()),
                                "HTTP Basic Authentication - Status Servlet",
                                "A status servlet is protected using HTTP Basic authentication",
                                REMEDY,
                                Risk.Low,
                                Confidence.Certain
                        ));

                        // Test Weak Passwords
                        CustomHttpRequestResponse httpWeakPasswordResult;
                        httpWeakPasswordResult = HTTPBasicBruteforce(callbacks, urlToTest);

                        if (httpWeakPasswordResult != null) {
                            
                                 // Retrieve the weak credentials
                                String weakCredential = null;
                                String weakCredentialDescription = "";
                                try {

                                    IRequestInfo reqInfoPwd = callbacks.getHelpers().analyzeRequest(baseRequestResponse.getHttpService(), httpWeakPasswordResult.getRequest());
                                    weakCredential = new String(helpers.base64Decode(HTTPParser.getHTTPBasicCredentials(reqInfoPwd)));
                                } catch (Exception ex) {
                                    stderr.println("Error during Authorization Header parsing " + ex);
                                }

                                if (weakCredential != null) {
                                    weakCredentialDescription += String.format("<br /><br /> The weak credentials are "
                                            + "<b>%s</b><br /><br />", weakCredential);
                                }
                                
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    httpWeakPasswordResult,
                                    "Status Servlet Weak Password",
                                    "Status Servlet is installed on the remote system with a default password" + weakCredentialDescription,
                                    "Change default/weak password and/or restrict access to the console only from trusted hosts/networks",
                                    Risk.Medium,
                                    Confidence.Certain));

                            return issues;
                        }
                    }

                    if (statusInfo.getStatusCode() == 200) {

                        List<int[]> matches_j2ee = getMatches(responseBytes, GREP_STRING_J2EE, helpers);
                        if (matches_j2ee.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new CustomHttpRequestResponse(statustest, responseBytes, baseRequestResponse.getHttpService()),
                                    StatusServlet.TITLE,
                                    StatusServlet.DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));

                            return issues;
                        }

                        List<int[]> matches_httpd = getMatches(responseBytes, GREP_STRING_HTTPD, helpers);
                        if (matches_httpd.size() > 0) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new CustomHttpRequestResponse(statustest, responseBytes, baseRequestResponse.getHttpService()),
                                    StatusServlet.TITLE,
                                    StatusServlet.DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));

                            return issues;
                        }

                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }
        }

        return issues;
    }

}
