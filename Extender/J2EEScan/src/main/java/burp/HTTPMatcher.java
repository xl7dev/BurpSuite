package burp;

import static burp.HTTPParser.getResponseHeaderValue;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HTTPMatcher {

    /**
     * Parse the web.xml J2EE resource, and pretty print servlet classes into
     * the burp report
     *
     * @param webxml content of the web.xml configuration file
     * @return a user friendly list with HTML formatted code, of all servlet
     * classes defined into the web.xml file
     */
    public static String getServletsDescription(String webxml) {
        List<String> servlets = getServletsFromWebDescriptors(webxml);
        String description = "";
        if (servlets.isEmpty()) {
            return description;
        }

        description += "<br /><br />List of remote Java classes used by the application:<br /><ul>";

        for (String servlet : servlets) {
            description += "<li><b>" + servlet + "</b></li>";
        }
        description += "</ul><br /><br />It's possible to download the above classes "
                + "located in <i>WEB-INF/classes/</i> folder";
        return description;
    }

    /**
     * Parse the servlet classes from a web.xml file
     *
     * @param webxml content of the web.xml configuration file
     * @return list of servlet classes defined into the web.xml file
     */
    public static List<String> getServletsFromWebDescriptors(String webxml) {
        List<String> servlets = new ArrayList();

        Pattern servletMatcher = Pattern.compile("<servlet-class>(.*?)</servlet-class>", Pattern.DOTALL | Pattern.MULTILINE);

        Matcher matcher = servletMatcher.matcher(webxml);
        while (matcher.find()) {
            int numEntries = matcher.groupCount();
            for (int i = 1; i <= numEntries; i++) {
                servlets.add(matcher.group(i).trim().replace("\n", "").replace("\r", ""));
            }
        }

        return servlets;
    }

    /**
     * From the Apache Axis Service Page, parse and retrieve the available web
     * services installed on the remote system
     *
     * @param axisServiceListPage the content of Apache Axis Services page
     * @return a list with the names of all Apache Axis Services
     */
    public static List<String> getServicesFromAxis(String axisServiceListPage) {
        List<String> wsName = new ArrayList();

        Pattern servletMatcher = Pattern.compile("services/(.*?)\\?wsdl", Pattern.MULTILINE);

        Matcher matcher = servletMatcher.matcher(axisServiceListPage);
        while (matcher.find()) {
            int numEntries = matcher.groupCount();
            for (int i = 1; i <= numEntries; i++) {
                wsName.add(matcher.group(i).trim().replace("\n", "").replace("\r", ""));
            }
        }

        return wsName;
    }

    public static Boolean isXML(String value) {
        if (value == null) {
            return false;
        }
        return value.trim().startsWith("<");
    }

    /**
     * Helper method to search a response for occurrences of a literal match
     * string and return a list of start/end offsets
     */
    public static List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helpers) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static boolean isEtcPasswdFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] PASSWD_PATTERN = "root:".getBytes();
        List<int[]> matchesPasswd = getMatches(response, PASSWD_PATTERN, helpers);

        return (matchesPasswd.size() > 0);
    }

    public static boolean isEtcShadowFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] SHADOW_PATTERN = "root:".getBytes();
        List<int[]> matchesShadow = getMatches(response, SHADOW_PATTERN, helpers);

        return (matchesShadow.size() > 0);
    }

    public static boolean isWinINI(byte[] response, IExtensionHelpers helpers) {
        final byte[] WIN_INI_PATTERN = "for 16-bit app support".getBytes();
        List<int[]> matchesShadow = getMatches(response, WIN_INI_PATTERN, helpers);

        return (matchesShadow.size() > 0);
    }

    /**
     * WEB-INF/ibm-web-ext.xmi
     */
    public static boolean isIBMWebExtFileWAS6(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<webappext".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    /**
     * WEB-INF/ibm-web-ext.xml
     */
    public static boolean isIBMWebExtFileWAS7(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<web-ext".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    /**
     * WEB-INF/ibm-ws-bnd.xml
     */
    public static boolean isIBMWSBinding(byte[] response, IExtensionHelpers helpers) {
        final byte[] IBMWEB_PATTERN = "<webservices-bnd".getBytes();
        List<int[]> matchesIbmweb = getMatches(response, IBMWEB_PATTERN, helpers);

        return (matchesIbmweb.size() > 0);
    }

    public static boolean isApacheStrutsConfigFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] STRUTS_PATTERN = "<struts".getBytes();
        List<int[]> matchesStruts = getMatches(response, STRUTS_PATTERN, helpers);

        return (matchesStruts.size() > 0);
    }

    public static boolean isSpringContextConfigFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] SPRING_PATTERN = "<beans".getBytes();
        List<int[]> matchesStruts = getMatches(response, SPRING_PATTERN, helpers);

        return (matchesStruts.size() > 0);
    }

    public static boolean isWebLogicFile(byte[] response, IExtensionHelpers helpers) {
        final byte[] WEBLOGIC_PATTERN = "<weblogic-web-app".getBytes();
        List<int[]> matchesWebLogic = getMatches(response, WEBLOGIC_PATTERN, helpers);

        return (matchesWebLogic.size() > 0);
    }

    public static boolean isWebDescriptor(byte[] response, IExtensionHelpers helpers) {
        final byte[] WEBXML_PATTERN = "<web-app".getBytes();
        List<int[]> matchesWebDescriptor = getMatches(response, WEBXML_PATTERN, helpers);

        return (matchesWebDescriptor.size() > 0);
    }

    /**
     * Detect the application context of the given URL
     *
     * Ex: http://www.example.org/myapp/test.jsf
     *
     * returns myapp
     */
    public static String getApplicationContext(URL url) {

        String host = url.getHost();
        String protocol = url.getProtocol();
        String path = url.getPath();
        int port = url.getPort();

        int i = path.indexOf("/", 1);
        String context = path.substring(0, i + 1);

        return context;
    }

    public static void getVulnerabilityByPageParsing(IHttpRequestResponse baseRequestResponse,
            IBurpExtenderCallbacks callbacks) {

        IExtensionHelpers helpers = callbacks.getHelpers();

        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] rawResponse = baseRequestResponse.getResponse();

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = helpers.analyzeResponse(rawResponse);

        String httpServerHeader = getResponseHeaderValue(respInfo, "Server");

        String contentTypeResponse = getResponseHeaderValue(respInfo, "Content-Type");

        String req = helpers.bytesToString(rawRequest);
        String reqBody = req.substring(reqInfo.getBodyOffset());
        String respBody = helpers.bytesToString(rawResponse);

        String REMEDY_J2EE_ERROR_HANDLING = "Implement a standard exception handling mechanism to intercept all errors<br /><br />"
                + "http://cwe.mitre.org/data/definitions/388.html<br />"
                + "https://www.owasp.org/index.php/Error_Handling<br />";

        /**
         * Java Server Faces Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            List<byte[]> jsfExceptions = Arrays.asList(
                    "<pre><code>com.sun.facelets.FaceletException".getBytes(),
                    "<title>Error - org.apache.myfaces".getBytes());

            for (byte[] jsfException : jsfExceptions) {

                List<int[]> matchesJsf = getMatches(rawResponse, jsfException, helpers);
                if (matchesJsf.size() > 0) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            baseRequestResponse,
                            "Incorrect Error Handling - JSF",
                            "J2EEScan identified a Java exception. The remote application does not properly handle application errors, "
                            + "and application stacktraces are dispalyed to the end user "
                            + "leading to information disclosure vulnerability",
                            REMEDY_J2EE_ERROR_HANDLING,
                            Risk.Low,
                            Confidence.Certain
                    ));
                }
            }
        }

        /**
         * Apache Struts Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] strutsDevMode = "<title>Struts Problem Report</title>".getBytes();
            List<int[]> matchesStrutsDev = getMatches(rawResponse, strutsDevMode, helpers);
            if (matchesStrutsDev.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Apache Struts - DevMode Enabled",
                        "J2EEScan identified an Apache Struts exception. The remote application  is configured for"
                        + " a development enviroment; development mode, or devMode, enables extra\n"
                        + "debugging behaviors and reports to assist developers.",
                        "Disable development mode in production enviroments using "
                        + "the property <i>struts.devMode=false</i><br /><br />"
                        + "http://struts.apache.org/docs/devmode.html",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Apache Tapestry Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] tapestryException = "<h1 class=\"t-exception-report\">An unexpected application exception has occurred.</h1>".getBytes();
            List<int[]> matchesTapestry = getMatches(rawResponse, tapestryException, helpers);
            if (matchesTapestry.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - Apache Tapestry",
                        "J2EEScan identified an Apache Tapestry exception."
                        + "The remote application does not properly handle application errors, "
                        + "and application stacktraces are dispalyed to the end user "
                        + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                        + "http://tapestry.apache.org/overriding-exception-reporting.html<br />"
                        + "http://tapestry.apache.org/tapestry4.1/developmentguide/exceptionpages.html",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Grails Exceptions
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] grailsException = "<h1>Grails Runtime Exception</h1>".getBytes();
            List<int[]> matchesGrails = getMatches(rawResponse, grailsException, helpers);
            if (matchesGrails.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - Grails",
                        "J2EEScan identified a Grails exception."
                        + "The remote application does not properly handle application errors, "
                        + "and application stacktraces are dispalyed to the end user "
                        + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                        + "http://grails.org/plugin/errors",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * GWT Exception
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            byte[] gwtException = "com.google.gwt.http.client.RequestException".getBytes();
            List<int[]> matchesGWT = getMatches(rawResponse, gwtException, helpers);
            if (matchesGWT.size() > 0) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Incorrect Error Handling - GWT",
                        "J2EEScan identified a GWT exception."
                        + "The remote application does not properly handle application errors, "
                        + "and application stacktraces are dispalyed to the end user "
                        + "leading to information disclosure vulnerability.<br /><br /><b>References</b><br />"
                        + "http://www.gwtproject.org/doc/latest/tutorial/RPC.html",
                        REMEDY_J2EE_ERROR_HANDLING,
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * J2EE Exception
         *
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {
            List<byte[]> javaxServletExceptions = Arrays.asList(
                    "javax.servlet.ServletException".getBytes(),
                    "onclick=\"toggle('full exception chain stacktrace".getBytes(),
                    "at org.apache.catalina".getBytes(),
                    "at org.apache.coyote.".getBytes(),
                    "at org.jboss.seam.".getBytes(),
                    "at org.apache.tomcat.".getBytes(),
                    "The full stack trace of the root cause is available in".getBytes());

            for (byte[] exc : javaxServletExceptions) {

                List<int[]> matchesJavax = getMatches(rawResponse, exc, helpers);
                if (matchesJavax.size() > 0) {

                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            baseRequestResponse,
                            "Incorrect Error Handling - Java",
                            "J2EEScan identified a Java exception. The remote application does not properly handle application errors, "
                            + "and application stacktraces are dispalyed to the end user "
                            + "leading to information disclosure vulnerability",
                            REMEDY_J2EE_ERROR_HANDLING,
                            Risk.Low,
                            Confidence.Certain
                    ));
                }

            }
        }

        /**
         * SQL statements in URL
         *
         * Improved detection for SQL statements in HTTP POST requests.
         */
        if (reqBody != null) {

            List<Pattern> sqlQueriesRe = new ArrayList();
            sqlQueriesRe.add(Pattern.compile("select ", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
            sqlQueriesRe.add(Pattern.compile("IS NOT NULL", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

            // check the pattern on response reqBody
            for (Pattern sqlQueryRule : sqlQueriesRe) {

                Matcher matcher = sqlQueryRule.matcher(helpers.urlDecode(reqBody));

                if (matcher.find()) {
                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            baseRequestResponse,
                            "SQL Statements in HTTP Request",
                            "J2EEScan potentially identified SQL statements in HTTP POST requests.<br />"
                            + "If SQL queries are passed from client to server in HTTP requests, a malicious user "
                            + "could be able to alter the SQL statement executed on the remote database.",
                            "Analyse the issue and modify the application behaviour, removing the SQL queries from the HTTP requests.",
                            Risk.Medium,
                            Confidence.Tentative
                    ));
                }
            }
        }

        /**
         *
         * JVM Remote Release Detection
         *
         * Tomcat Manager JVM info
         *
         * <tr>
         * <td class="row-center"><small>Apache Tomcat/6.0.26</small></td>
         * <td class="row-center"><small>1.6.0_18-b18</small></td>
         * <td class="row-center"><small>Sun Microsystems Inc.</small></td>
         * <td class="row-center"><small>Linux</small></td>
         * <td
         * class="row-center"><small>2.6.30.10-105.2.23.fc11.i686.PAE</small></td>
         * <td class="row-center"><small>i386</small></td
         */
        if (respBody != null && reqInfo.getUrl().getPath().contains("manager/html")) {

            Pattern jvmRule = Pattern.compile("\"><small>(1\\.\\d\\.[\\w\\-\\_\\.]+)<", Pattern.DOTALL | Pattern.MULTILINE);
            Matcher matcher = jvmRule.matcher(respBody);

            if (matcher.find()) {

                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - JVM Remote Release Detection",
                        "J2EEscan identified the remote JVM release <b>" + matcher.group(1) + "</b>",
                        "Verify the Java updates for the release:<ul>"
                        + "<li>Java 1.7 http://www.oracle.com/technetwork/java/javase/7u-relnotes-515228.html</li>"
                        + "<li>Java 1.6 http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html</li>"
                        + "<li>Java 1.5 http://www.oracle.com/technetwork/articles/javase/overview-137139.html</li>"
                        + "</ul>",
                        Risk.Information,
                        Confidence.Certain
                ));
            }
        }

        /* HTTP Server Header examples 
         * Server: Jetty/5.1.x (Linux/2.6.33.5-iR4-1.0.4.3 arm java/1.6.0_21 
         * Server: Jetty/5.1.12 (Linux/2.6.18-371.11.1.el5.centos.plus amd64 java/1.6.0_34 
         * Server: Jetty/5.1.3 (Windows 2003/5.2 x86 java/1.5.0_09
         */
        if (httpServerHeader != null) {
            Pattern javaRule = Pattern.compile("java\\/([\\d\\.\\_]+)", Pattern.DOTALL);
            Matcher javaMatcher = javaRule.matcher(httpServerHeader);
            if (javaMatcher.find()) {
                String version = javaMatcher.group(1);
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - JVM Remote Release Detection",
                        "J2EEscan identified the remote JVM release <b>" + version + "</b>",
                        "Verify the Java updates for the release:<ul>"
                        + "<li>Java 1.7 http://www.oracle.com/technetwork/java/javase/7u-relnotes-515228.html</li>"
                        + "<li>Java 1.6 http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html</li>"
                        + "<li>Java 1.5 http://www.oracle.com/technetwork/articles/javase/overview-137139.html</li>"
                        + "</ul>",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Detect Apache Tomcat
         */
        if (respBody != null && contentTypeResponse != null
                && (contentTypeResponse.contains("text/html") || (contentTypeResponse.contains("text/plain")))) {

            Pattern tomcatRule = Pattern.compile("Apache Tomcat/([\\d\\.]+)", Pattern.DOTALL | Pattern.MULTILINE);
            Matcher matcher = tomcatRule.matcher(respBody);

            if (matcher.find()) {
                String version = matcher.group(1);

                SoftwareVersions.getIssues("Apache Tomcat", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Aapache%3Atomcat%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Apache Tomcat " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                        + "Apache Tomcat  version <b>" + version + "</b>.<br />"
                        + "The potential vulnerabilities for this release are available at:<br />"
                        + "<ul><li>" + nistLink + "</li></ul><br /><br />"
                        + "<b>References</b><br />"
                        + "http://tomcat.apache.org/security.html",
                        "Configure the remote application to correctly manage error pages to avoid information disclosure issues",
                        Risk.Low,
                        Confidence.Certain
                ));
            }

        }

        /**
         * Detect Jetty
         *
         * HTTP Server Header examples Server: Jetty(6.1.1) Server:
         * Jetty(9.0.4.v20130625) Server: Jetty/5.1.x
         * (Linux/2.6.33.5-iR4-1.0.4.3 arm java/1.6.0_21 Server: Jetty/5.1.12
         * (Linux/2.6.18-371.11.1.el5.centos.plus amd64 java/1.6.0_34 Server:
         * Jetty/5.1.3 (Windows 2003/5.2 x86 java/1.5.0_09
         */
        if (httpServerHeader != null) {
            Pattern jettyRule = Pattern.compile("Jetty.([\\d\\.]+)", Pattern.DOTALL);
            Matcher jettyMatcher = jettyRule.matcher(httpServerHeader);
            if (jettyMatcher.find()) {
                String version = jettyMatcher.group(1);

                SoftwareVersions.getIssues("Jetty", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cpe=cpe%3A%2Fa%3Amortbay%3Ajetty%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Jetty " + version,
                        "J2EEscan identified the remote Servlet Container release; "
                        + "Jetty  version <b>" + version + "</b>.<br />"
                        + "The potential vulnerabilities for this release are available at:<br />"
                        + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote servlet container to suppress the HTTP Server header using the <i>sendServerVersion</i> directive<br />"
                        + "http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Detect Glassfish
         *
         * HTTP Server Header examples
         *
         * Server: GlassFish Server Open Source Edition 3.1.1 Server: GlassFish
         * Server Open Source Edition 4.0 Server: GlassFish Server Open Source
         * Edition 4.1
         */
        if (httpServerHeader != null) {
            Pattern glassfishRule = Pattern.compile("GlassFish Server Open Source Edition ([\\d\\.]+)", Pattern.DOTALL);
            Matcher glassfishMatcher = glassfishRule.matcher(httpServerHeader);
            if (glassfishMatcher.find()) {
                String version = glassfishMatcher.group(1);

                SoftwareVersions.getIssues("GlassFish", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aglassfish_server%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - Glassfish " + version,
                        "J2EEscan identified the remote Application Server release; "
                        + "Glassfish  version <b>" + version + "</b>.<br />"
                        + "The potential vulnerabilities for this release are available at:<br />"
                        + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote application server to suppress the HTTP Server header<br />"
                        + "http://blog.eisele.net/2011/05/securing-your-glassfish-hardening-guide.html<br />"
                        + "https://javadude.wordpress.com/2013/12/06/hide-glassfish-server-information/",
                        Risk.Low,
                        Confidence.Certain
                ));
            }
        }

        /**
         * Detect WebLogic
         *
         * HTTP Server Header examples
         *
         * Server: WebLogic 5.1.0 Service Pack 13 12/12/2002 22:13:10 #228577
         * Server: WebLogic Server 7.0 SP4 Tue Aug 12 11:22:26 PDT 2003 284033
         * Server: WebLogic Server 8.1 SP3 Tue Jun 29 23:11:19 PDT 2004 404973
         * Server: WebLogic WebLogic Server 7.0 SP2 Sun Jan 26 23:09:32 PST 2003
         * Server: WebLogic WebLogic Server 6.1 SP2 12/18/2001 11:13:46
         *
         */
        if (httpServerHeader != null) {
            Pattern weblogicRule = Pattern.compile("WebLogic (:?Server )?([\\d\\.]+)", Pattern.DOTALL);
            Matcher weblogicMatcher = weblogicRule.matcher(httpServerHeader);
            if (weblogicMatcher.find()) {
                String version = weblogicMatcher.group(2);

                SoftwareVersions.getIssues("WebLogic", version, callbacks, baseRequestResponse);

                String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aweblogic_server%3A" + version;
                callbacks.addScanIssue(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        baseRequestResponse,
                        "Information Disclosure - WebLogic " + version,
                        "J2EEscan identified the remote Application Server release; "
                        + "WebLogic  version <b>" + version + "</b>.<br />"
                        + "The potential vulnerabilities for this release are available at:<br />"
                        + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                        "Configure the remote application server to suppress the HTTP Server header<br />",
                        Risk.Information,
                        Confidence.Certain
                ));
            }
        }

        /**
         *
         * Detect Oracle Application Server
         *
         * HTTP Server Header examples
         *
         * Server: Oracle Application Server Containers for J2EE 10g (9.0.4.1.0)
         * Server: Oracle-Application-Server-10g/10.1.2.2.0 Oracle-HTTP-Server
         * Server: Oracle-Application-Server-10g/10.1.3.1.0 Oracle-HTTP-Server
         * Server: Oracle Application Server/10.1.2.3.1
         *
         */
        if (httpServerHeader != null) {
            List<Pattern> oracleApplicationServerRe = new ArrayList();

            oracleApplicationServerRe.add(Pattern.compile("Oracle Application Server Containers for J2EE 10g \\(([\\d\\.]+)\\)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle.Application.Server.10g\\/([\\d\\.]+)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle Application Server\\/([\\d\\.]+)", Pattern.DOTALL));
            oracleApplicationServerRe.add(Pattern.compile("Oracle9iAS\\/([\\d\\.]+)", Pattern.DOTALL));

            // check the pattern
            for (Pattern oracleRe : oracleApplicationServerRe) {

                Matcher oracleMatcher = oracleRe.matcher(httpServerHeader);
                if (oracleMatcher.find()) {
                    String version = oracleMatcher.group(1);

                    SoftwareVersions.getIssues("Oracle Application Server", version, callbacks, baseRequestResponse);

                    String nistLink = "http://web.nvd.nist.gov/view/vuln/search-results?cpe=cpe%3A%2Fa%3Aoracle%3Aapplication_server%3A" + version;
                    callbacks.addScanIssue(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            baseRequestResponse,
                            "Information Disclosure - Oracle Application Server " + version,
                            "J2EEscan identified the remote Application Server release; "
                            + "Oracle Application Server  version <b>" + version + "</b>.<br />"
                            + "The potential vulnerabilities for this release are available at:<br />"
                            + "<ul><li>" + nistLink + "</li></ul><br /><br />",
                            "Configure the remote application server to suppress the HTTP Server header<br />"
                            + "http://docs.oracle.com/cd/E23943_01/web.1111/e10144/faq.htm#HSADM939<br />"
                            + "https://oamidam.wordpress.com/2011/06/01/controlling-the-server-header-with-oracle-http-server-and-oracle-web-cache-11g/",
                            Risk.Low,
                            Confidence.Certain
                    ));

                    break;
                }
            }

        }

    }

}
