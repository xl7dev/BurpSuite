package burp.j2ee.issues.impl;

import burp.j2ee.CustomScanIssue;
import burp.CustomHttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import static burp.WeakPasswordBruteforcer.HTTPBasicBruteforce;
import burp.j2ee.Confidence;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Retrieve the list of Web Services installed on the remote system through the
 * JBoss Web Service Console
 *
 *
 */
public class JBossWS implements IModule{

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> JBOSS_WS = Arrays.asList(
            "/jbossws/services"
    );

    private static final Pattern JBOSSWS_RE = Pattern.compile("JBossWS/Services</div>",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    private static final String TITLE = "JBoss Web Service Console";
    private static final String DESCRIPTION = "J2EEscan identifie the JBoss Web Service console "
            + "on the remote system. The console displays all the web services "
            + "exposed by the system leading to a potential information disclosure "
            + "vulnerability. <br /><br />";
    
    private static final String REMEDY = "Restrict access to the ws service";
    
    private PrintWriter stderr;

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

            for (String JBOSS_WS_PATH : JBOSS_WS) {

                try {
                    // Test the presence of JBossWS console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_WS_PATH);
                    byte[] jbosswstest = helpers.buildHttpRequest(urlToTest);

                    byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosswstest);

                    IResponseInfo jbosswsInfo = helpers.analyzeResponse(responseBytes);

                    if (jbosswsInfo.getStatusCode() == 200) {

                        String response = helpers.bytesToString(responseBytes);

                        Matcher matcher = JBOSSWS_RE.matcher(response);
                        if (matcher.find()) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    urlToTest,
                                    new CustomHttpRequestResponse(jbosswstest, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                            return issues;
                        }
                    }
                    
                    if (jbosswsInfo.getStatusCode() == 401) {
                        // Test Weak Passwords
                        CustomHttpRequestResponse httpWeakPasswordResult;
                        httpWeakPasswordResult = HTTPBasicBruteforce(callbacks, urlToTest);

                        if (httpWeakPasswordResult != null) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), urlToTest.getPath()),
                                    httpWeakPasswordResult,
                                    TITLE,
                                    DESCRIPTION,
                                    REMEDY,
                                    Risk.Medium,
                                    Confidence.Certain
                            ));

                            return issues;
                        }
                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URI exception " + ex);
                }
            }
        }

        return issues;
    }
}