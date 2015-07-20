package burp;

import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * If Burp was able to retrieve remote configuration files, execute some policy
 * checks on these files to identify further security issues or not recommended
 * configurations.
 *
 */
public class J2EELocalAssessment {

    public static void analyzeWEBXML(byte[] webxmlFile, IBurpExtenderCallbacks cb,
            IHttpRequestResponse baseRequestResponse) {

        IExtensionHelpers helpers = cb.getHelpers();

        PrintWriter stderr = new PrintWriter(cb.getStderr(), true);

        Pattern pattern = Pattern.compile("(<web-app.*?</web-app>)", Pattern.DOTALL | Pattern.MULTILINE);
        String webxml = helpers.bytesToString(webxmlFile);

        Matcher matcher = pattern.matcher(webxml);

        if (matcher.find()) {

            try {

                String webxmlContent = matcher.group(1);

                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder dBuilder;

                dBuilder = dbFactory.newDocumentBuilder();
                InputSource is = new InputSource(new StringReader(webxmlContent));
                Document doc = dBuilder.parse(is);

                /**
                 * HTTP VERB Tampering
                 *
                 * http://docs.oracle.com/cd/E14571_01/web.1111/e13712/web_xml.htm#WBAPP502
                 * https://weblogs.java.net/blog/swchan2/archive/2013/04/19/deny-uncovered-http-methods-servlet-31
                 * http-method should not be defined, to restrict access to a
                 * resources using HTTP verbs In Servlet 3.1 spec, the attribute
                 * "deny-uncovered-http-methods" could be used to deny uncovered
                 * HTTP verbs
                 *
                 */
                try {
                    NodeList httpMethods = doc.getElementsByTagName("http-method");

                    if ((httpMethods != null) && (httpMethods.getLength() >= 1)) {
                        cb.addScanIssue(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                baseRequestResponse,
                                "Compliance Checks - web.xml - HTTP Verb Tampering",
                                "J2EEScan identified a potential HTTP Verb Tampering vulnerability inspecting"
                                + " the remote web.xml resource.<br /><br />"
                                + "One or more resources defined into the web.xml uses some definitions to restrict "
                                + "access based on the HTTP Verb used with requests; based on this context, in some scenarios "
                                + "it's possible to bypass these resctrictions providing a different HTTP verb to access to the remote resource."
                                + "<br /> This allows the attacker to access data that should otherwise be protected."
                                + "<br /><br />An example of vulnerable configuration that could lead to Authentication Bypass vulnerabilities:<br /><br />"
                                + "<div style=\"font: courier;\"><pre>"
                                + "&lt;security-constraint&gt;\n"
                                + "    &lt;display-name&gt;\n"
                                + "        Protect GET only, leave all other methods unprotected\n"
                                + "    &lt;/display-name&gt;\n"
                                + "    &lt;web-resource-collection&gt;\n"
                                + "        &lt;url-pattern&gt;/company/*&lt;/url-pattern&gt;\n"
                                + "        &lt;http-method&gt;GET&lt;/http-method&gt;\n"
                                + "    &lt;/web-resource-collection&gt;\n"
                                + "    &lt;auth-constraint&gt;\n"
                                + "        &lt;role-name&gt;sales&lt;/role-name&gt;\n"
                                + "    &lt;/auth-constraint&gt;\n"
                                + "&lt;/security-constraint&gt;"
                                + "</pre></div> "
                                + "<br />"
                                + "<br /><b>References:</b><br />"
                                + "https://www.owasp.org/index.php/Testing_for_HTTP_Verb_Tampering_(OTG-INPVAL-003)<br />"
                                + "http://www.aspectsecurity.com/research-presentations/bypassing-vbaac-with-http-verb-tampering<br />"
                                + "http://capec.mitre.org/data/definitions/274.html<br />"
                                + "http://jeremiahgrossman.blogspot.it/2008/06/what-you-need-to-know-about-http-verb.html",
                                "Remove <i>http-method</i> elements to avoid possible HTTP Verb Tampering attacks",
                                Risk.Medium,
                                Confidence.Tentative));
                    }

                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }

                /**
                 * URL Parameters for Session Tracking
                 * http://docs.oracle.com/javaee/6/api/javax/servlet/SessionTrackingMode.html
                 *
                 */
                try {

                    NodeList sessionTracking = doc.getElementsByTagName("tracking-mode");

                    if ((sessionTracking != null) && (sessionTracking.getLength() >= 1)) {
                        String value = sessionTracking.item(0).getTextContent();
                        if (value.equalsIgnoreCase("URL")) {

                            cb.addScanIssue(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    baseRequestResponse,
                                    "Compliance Checks- web.xml - URL Parameters for Session Tracking",
                                    "J2EEScan identified a potential Information Disclosure vulnerabilitiy inspecting"
                                    + " the remote web.xml resource.<br /><br />"
                                    + "The remote applications seems to put the JSESSIONID into the URL using the directive <i>tracking-mode</i> with the URL value;<br />"
                                    + "the tracking-mode element in the Servlet 3.0 specification allows to define whether the JSESSIONID should be stored in a cookie or in a URL parameter. <br />"
                                    + "If the session id is stored in a URL parameter it could lead to and Information Disclosure vulnerability, because the URLs could be inadvertently "
                                    + "saved in browser history, proxy server logs, referrer logs etc. <br />"
                                    + "<br /><b>References:</b><br />"
                                    + "http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files<br />",
                                    "Change the <i>tracking-mode</i> value to avoid possible Information Disclosure vulnerabilities",
                                    Risk.Low,
                                    Confidence.Tentative));
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }

                /**
                 * Incomplete Error Handling
                 *
                 * https://blog.whitehatsec.com/error-handling-in-java-web-xml/
                 * http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files
                 * http://www.jtmelton.com/2010/06/02/the-owasp-top-ten-and-esapi-part-7-information-leakage-and-improper-error-handling/
                 *
                 */
                try {

                    NodeList exceptionType = doc.getElementsByTagName("exception-type");
                    Boolean incompleteErrorHandling = true;
                    int excTypeLen = exceptionType.getLength();

                    for (int i = 0; i < excTypeLen; i++) {
                        Node s = exceptionType.item(i);
                        String value = s.getTextContent();

                        if (value.equalsIgnoreCase("java.lang.Throwable")) {
                            incompleteErrorHandling = false;
                            break;
                        }
                    }
                    if (incompleteErrorHandling) {
                        cb.addScanIssue(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                baseRequestResponse,
                                "Compliance Checks - web.xml - Incomplete Error Handling (Throwable)",
                                "J2EEScan identified a potential Information Disclosure vulnerabilitiy inspecting"
                                + " the remote web.xml resource.<br /><br />"
                                + "The remote application seems to not correctly handle application errors; the web.xml does not "
                                + "provide an error page for <i>java.lang.Throwable</i> exceptions.<br /><br />"
                                + "<b>References:</b><br />"
                                + "https://blog.whitehatsec.com/error-handling-in-java-web-xml/<br />"
                                + "http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files<br />",
                                "Modify the error handling catching the <i>java.lang.Throwable</i> exception to avoid possible Information Disclosure vulnerabilities<br /><br />"
                                + "<div style=\"font: courier;\"><pre>"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;404&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;500&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;exception-type&gt;java.lang.Throwable&lt;/exception-type&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "</pre></div>",
                                Risk.Low,
                                Confidence.Tentative));
                    }
                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }

                
                try {

                    NodeList exceptionType = doc.getElementsByTagName("error-code");
                    Boolean incompleteErrorHandling500 = true;
                    int excTypeLen = exceptionType.getLength();

                    for (int i = 0; i < excTypeLen; i++) {
                        Node s = exceptionType.item(i);
                        String value = s.getTextContent();

                        if (value.equalsIgnoreCase("500")) {
                            incompleteErrorHandling500 = false;
                            break;
                        }
                    }
                    if (incompleteErrorHandling500) {
                        cb.addScanIssue(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                baseRequestResponse,
                                "Compliance Checks - web.xml - Incomplete Error Handling (HTTP Code 500)",
                                "J2EEScan identified a potential Information Disclosure vulnerabilitiy inspecting"
                                + " the remote web.xml resource.<br /><br />"
                                + "The remote application seems to not correctly handle application errors; the web.xml does not "
                                + "provide an error page for <i>500</i> HTTP code.<br /><br />"
                                + "<b>References:</b><br />"
                                + "https://blog.whitehatsec.com/error-handling-in-java-web-xml/<br />"
                                + "http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files<br />",
                                "Modify the error handling catching the <i>500</i> error code to avoid possible Information Disclosure vulnerabilities<br /><br />"
                                + "<div style=\"font: courier;\"><pre>"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;404&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;500&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;exception-type&gt;java.lang.Throwable&lt;/exception-type&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "</pre></div>",
                                Risk.Low,
                                Confidence.Tentative));
                    }
                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }

                
                try {

                    NodeList exceptionType = doc.getElementsByTagName("error-code");
                    Boolean incompleteErrorHandling404 = true;
                    int excTypeLen = exceptionType.getLength();

                    for (int i = 0; i < excTypeLen; i++) {
                        Node s = exceptionType.item(i);
                        String value = s.getTextContent();

                        if (value.equalsIgnoreCase("404")) {
                            incompleteErrorHandling404 = false;
                            break;
                        }
                    }
                    if (incompleteErrorHandling404) {
                        cb.addScanIssue(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                baseRequestResponse,
                                "Compliance Checks - web.xml - Incomplete Error Handling (HTTP Code 404)",
                                "J2EEScan identified a potential Information Disclosure vulnerabilitiy inspecting"
                                + " the remote web.xml resource.<br /><br />"
                                + "The remote application seems to not correctly handle application errors; the web.xml does not "
                                + "provide an error page for <i>404</i> HTTP code.<br /><br />"
                                + "<b>References:</b><br />"
                                + "https://blog.whitehatsec.com/error-handling-in-java-web-xml/<br />"
                                + "http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files<br />",
                                "Modify the error handling catching the <i>404</i> error code to avoid possible Information Disclosure vulnerabilities<br /><br />"
                                + "<div style=\"font: courier;\"><pre>"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;404&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;error-code&gt;500&lt;/error-code&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "&lt;error-page&gt;\n"
                                + "  &lt;exception-type&gt;java.lang.Throwable&lt;/exception-type&gt;\n"
                                + "  &lt;location&gt;/error.jsp&lt;/location&gt;\n"
                                + "&lt;/error-page&gt;\n"
                                + "</pre></div>",
                                Risk.Low,
                                Confidence.Tentative));
                    }
                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }
                
                
                /**
                 * InvokerServlet
                 */
                try {

                    NodeList exceptionType = doc.getElementsByTagName("servlet-class");

                    int excTypeLen = exceptionType.getLength();

                    for (int i = 0; i < excTypeLen; i++) {
                        Node s = exceptionType.item(i);
                        String value = s.getTextContent();

                        if (value.contains("InvokerServlet")) {
                            cb.addScanIssue(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    baseRequestResponse,
                                    "Compliance Checks - web.xml - Invoker Servlet",
                                    "J2EEScan identified the <i>InvokerServlet</> enabled inspecting"
                                    + " the remote web.xml resource.<br /><br />"
                                    + "It allows any class in your classpath to be accessed, as long as the class is a valid servlet. <br />"
                                    + "This functionality could potentially introduces a security risk; different servlets could be directly accessed from remote bypassing any Authorization Layers<br /><br />"
                                    + "<b>References:</b><br />"
                                    + "http://www.coderanch.com/how-to/java/InvokerServlet<br />"
                                    + "https://tomcat.apache.org/tomcat-4.1-doc/catalina/funcspecs/fs-invoker.html<br />",
                                    "Disable or restrict access to the remote InvokerServlet",
                                    Risk.Medium,
                                    Confidence.Tentative));
                            break;
                        }

                    }
                } catch (Exception ex) {
                    ex.printStackTrace(stderr);
                }

            } catch (ParserConfigurationException | SAXException | IOException ex) {
                ex.printStackTrace(stderr);
            }
        }

    }
}
