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

/**
 *
 * Test for Weblogic UDDI Explorer and SSRF vulnerability
 * 
 * Reference:
 * https://blog.gdssecurity.com/labs/2015/3/30/weblogic-ssrf-and-xss-cve-2014-4241-cve-2014-4210-cve-2014-4.html
 * 
 * 
 */
public class WeblogicUDDIExplorer implements IModule {

    private static final String TITLE = "Weblogic - UDDI Explorer";
    private static final String DESCRIPTION = "J2EEscan identified the UDDI weblogic console. <br />"
            + "Universal Description, Discovery and Integration is an xml based registry to locate and regiester web services."
            + "installed on the remote system with a weak password.";

    private static final String TITLE_SSRF = "Weblogic - UDDI Explorer SSRF Vulnerability";
    private static final String DESCRIPTION_SSRF = "J2EEscan identified a SSRF vulnerability in the UDDI Explorer console.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4210<br />"
            + "https://cwe.mitre.org/data/definitions/918.html<br />"
            + "https://blog.gdssecurity.com/labs/2015/3/30/weblogic-ssrf-and-xss-cve-2014-4241-cve-2014-4210-cve-2014-4.html";

    private static final String REMEDY = "-";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;

    private static final byte[] GREP_STRING = "<title>BEA WebLogic UDDI Explorer Home</title>".getBytes();

    private static final List<byte[]> GREP_SSRF_STRINGS = Arrays.asList(
            "could not connect over HTTP to server:".getBytes(),
            "XML_SoapException: Connection refused".getBytes(),
            "XML_SoapException: Received a response from url".getBytes()
    );

    private static final List<String> UDDI_PATHS = Arrays.asList(
            "/uddiexplorer/"
    );

    @SuppressWarnings("empty-statement")
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

            for (String UDDI_PATH : UDDI_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), UDDI_PATH);
                    byte[] udditest = helpers.buildHttpRequest(urlToTest);
                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, udditest);

                    IResponseInfo uddiInfo = helpers.analyzeResponse(response);

                    // UDDI Console available
                    if (uddiInfo.getStatusCode() == 200) {
                        List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                        if (matches.size() > 0) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new CustomHttpRequestResponse(udditest, response, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Information,
                                    Confidence.Certain
                            ));
                        }

                        // Test for SSRF vulnerability
                        String SSRF_PATH = "/uddiexplorer/SearchPublicRegistries.jsp?operator=http://localhost:22&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search";
                        URL ssrfUrlToTest = new URL(protocol, url.getHost(), url.getPort(), SSRF_PATH);
                        byte[] ssrfRootRequest = helpers.buildHttpRequest(ssrfUrlToTest);

                        byte[] ssrfResponse = callbacks.makeHttpRequest(url.getHost(),
                                url.getPort(), isSSL, ssrfRootRequest);

                        for (byte[] GREP_SSRF_STRING : GREP_SSRF_STRINGS) {
                            List<int[]> matches_ssrf = getMatches(ssrfResponse, GREP_SSRF_STRING, helpers);
                            if (matches_ssrf.size() > 0) {

                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new CustomHttpRequestResponse(ssrfRootRequest, ssrfResponse, baseRequestResponse.getHttpService()),
                                        TITLE_SSRF,
                                        DESCRIPTION_SSRF,
                                        REMEDY,
                                        Risk.Medium,
                                        Confidence.Certain
                                ));
                            }
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
