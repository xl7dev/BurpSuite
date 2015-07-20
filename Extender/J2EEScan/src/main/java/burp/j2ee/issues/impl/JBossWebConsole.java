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

public class JBossWebConsole implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE_JBOSS_UNPROTECTED = "JBoss Web Console Not Password Protected";
    private static final String DESCRIPTION_JBOSS_UNPROTECTED = "J2EEscan identified an"
            + "unauthenticated access to the Jboss jmx/web console. A remote attacker could be able to install"
            + "malicious applications to backdoor the remote system<br /><br />"
            + "<b>References:</b><br /><br />"
            + "http://www.jboss.org/community/wiki/SecureTheJmxConsole<br />"
            + "http://www.jboss.org/community/wiki/SecureJBoss";

    private static final String TITLE_JBOSS_WEAK_PASSWORD = "JBoss Web Console Weak Password";
    private static final String DESCRIPTION_JBOSS_WEAK_PASSWORD = "J2EEscan identified a default password"
            + "for the jmx/web console. A remote attacker could be able to install"
            + "malicious applications to backdoor the remote system<br /><br />"
            + "<b>References:</b><br /><br />"
            + "http://www.jboss.org/community/wiki/SecureTheJmxConsole<br />"
            + "http://www.jboss.org/community/wiki/SecureJBoss";

    private static final String REMEDY = "Change default/weak password and/or restrict access to the management console only from trusted hosts/networks";

    private static final String TITLE_JBOSS_CONSOLE = "JBoss Web Console";
    private static final String DESCRIPTION_JBOSS_CONSOLE = "J2EEscan identifie the JBoss JMX/WEB Console available"
            + " on the remote system.";

    private static final List<String> JBOSS_ADMIN_PATHS = Arrays.asList(
            "/web-console/",
            "/jmx-console/"
    );

    private static final byte[] GREP_STRING_JMX = "HtmlAdaptor?action=displayMBeans".getBytes();
    private static final byte[] GREP_STRING_WEB = "ServerInfo.jsp\"".getBytes();
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

            for (String JBOSS_ADMIN_PATH : JBOSS_ADMIN_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossAdminInfo = helpers.analyzeResponse(response);

                    if (jbossAdminInfo.getStatusCode() == 200) {

                        List<int[]> matcheJMX = getMatches(response, GREP_STRING_JMX, helpers);
                        List<int[]> matcheWEB = getMatches(response, GREP_STRING_WEB, helpers);
                        if ((matcheJMX.size() > 0) || (matcheWEB.size() > 0)) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                    new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                    TITLE_JBOSS_UNPROTECTED,
                                    DESCRIPTION_JBOSS_UNPROTECTED,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));
                        }
                    }

                    if (jbossAdminInfo.getStatusCode() == 401) {
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                TITLE_JBOSS_CONSOLE,
                                DESCRIPTION_JBOSS_CONSOLE,
                                REMEDY,
                                Risk.Low,
                                Confidence.Certain
                        ));

                        // Test Weak Passwords
                        CustomHttpRequestResponse httpWeakPasswordResult;
                        httpWeakPasswordResult = HTTPBasicBruteforce(callbacks, urlToTest);

                        if (httpWeakPasswordResult != null) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                    httpWeakPasswordResult,
                                    TITLE_JBOSS_WEAK_PASSWORD,
                                    DESCRIPTION_JBOSS_WEAK_PASSWORD,
                                    REMEDY,
                                    Risk.High,
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
