package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
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
 *
 * Detection Oracle Database sqlnet.log file disclosure
 *
 *
 */
public class OASSqlnetLogDisclosure implements IModule {

    private static final String TITLE = "Information Disclosure - Oracle Log Database Accessible";
    private static final String DESCRIPTION = "J2EEscan identified an information disclosure issue. "
            + "Application log <i>sqlnet.log</i> is publicly available, and may "
            + "contain sensitive internal information (es: internal paths, usernames, internal IP) "
            + "not intended for public viewing."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://docs.oracle.com/cd/A57673_01/DOC/net/doc/NWTR23/apa.htm<br />"
            + "http://www.stigviewer.com/stig/oracle_database_10g_installation/2014-04-02/finding/V-2612";
    private static final String REMEDY = "Update the OAS with the last security patches, "
            + "and restrict access to the resource <i>sqlnet.log</i>";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> SQLNETLOG_PATHS = Arrays.asList(
            "/sqlnet.log"
    );

    private PrintWriter stderr;
    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "VERSION INFORMATION".getBytes()
    );

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

            for (String SQLLOG_PATH : SQLNETLOG_PATHS) {

                try {
                    // Test the presence of tomcat console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), SQLLOG_PATH);
                    byte[] oastest = helpers.buildHttpRequest(urlToTest);

                    byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, oastest);

                    // look for matches of our active check grep string in the response body
                    IResponseInfo statusInfo = helpers.analyzeResponse(responseBytes);

                    if (statusInfo.getStatusCode() == 200) {

                        for (byte[] GREP_STRING : GREP_STRINGS) {
                            List<int[]> matches_j2ee = getMatches(responseBytes, GREP_STRING, helpers);
                            if (matches_j2ee.size() > 0) {

                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new CustomHttpRequestResponse(oastest, responseBytes, baseRequestResponse.getHttpService()),
                                        TITLE,
                                        DESCRIPTION,
                                        REMEDY,
                                        Risk.Low,
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
