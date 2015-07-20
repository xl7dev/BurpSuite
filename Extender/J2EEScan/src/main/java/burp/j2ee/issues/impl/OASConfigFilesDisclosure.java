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
 * Detection of known File Disclosure issues related Oracle Application Server
 *
 * References: 
 * http://www.nextgenss.com/papers/hpoas.pdf 
 * http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf
 *
 */
public class OASConfigFilesDisclosure implements IModule {

    private static final String TITLE = "Information Disclosure - Oracle Application Server Default Resources";
    private static final String DESCRIPTION = "J2EEscan identified one ore more Oracle "
            + "Application Server issues. Some resources are publicly available, and may "
            + "contain sensitive internal information (es: internal paths, credentials) "
            + "not intended for public viewing."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.blackhat.com/presentations/win-usa-02/litchfield-winsec02.pdf<br />"
            + "http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf<br />"
            + "http://www.nextgenss.com/papers/hpoas.pdf<br />"
            + "http://www.kb.cert.org/vuls/id/698467<br />"
            + "http://docs.oracle.com/cd/A95432_01/relnotes/xdk/java/xsql/relnotes.html<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0569<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0568<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0565";
    private static final String REMEDY = "Update the OAS with the last security patches, "
            + "and restrict access to the resources";

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private static final List<String> OAS_PATHS = Arrays.asList(
            "/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml",
            "/servlet/oracle.xml.xsql.XSQLServlet/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml",
            "/xsql/lib/XSQLConfig.xml",
            "/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml",
            "/globals.jsa",
            "/demo/ojspext/events/globals.jsa",
            // Dynamic Monitoring Services 
            "/dms/AggreSpy",
            "/soap/servlet/Spy",
            "/servlet/Spy",
            "/servlet/DMSDump",
            "/dms/DMSDump",
            // Oracle Java Process Manager 
            "/oprocmgr-status",
            "/oprocmgr-service",
            "/soap/servlet/soaprouter",
            "/fcgi-bin/echo",
            "/fcgi-bin/echo2",
            "/fcgi-bin/echo.exe",
            "/fcgi-bin/echo2.exe",
            // BC4J Runtime Parameters            
            "/webapp/wm/runtime.jsp"
            
            //TODO CVE-2002-0565
//            "/_pages/_webapp/_admin/_showpooldetails.java",
//            "/_pages/_webapp/_admin/_showjavartdetails.java",
//            "/_pages/_webapp/_jsp/",
//            "/_pages/_demo/",
//            "/_pages/_demo/_sql/_pages/",
//            "/OA_HTML/AppsLocalLogin.jsp"
    );

    private PrintWriter stderr;
    private static final List<byte[]> GREP_STRINGS = Arrays.asList(
            "SOAP configuration file".getBytes(),
            "On a PRODUCTION system".getBytes(),
            "<%".getBytes(),
            "<DMSDUMP version".getBytes(),
            "DMS Metrics".getBytes(),
            "Current Metric Values".getBytes(),
            "Process Status".getBytes(),
            "SOAP Server".getBytes(),
            "DOCUMENT_ROOT=".getBytes(),
            "BC4J Runtime Parameters".getBytes()
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

            for (String OAS_PATH : OAS_PATHS) {

                try {
                    // Test the presence of tomcat console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), OAS_PATH);
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
                                        DESCRIPTION + "<br /><br /><b>Path: " + OAS_PATH + "</b><br />",
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
