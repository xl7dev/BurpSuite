package burp.j2ee.issues.impl;

import burp.j2ee.CustomScanIssue;
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
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

public class JBossJMXInvoker implements IModule{

    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();

    private static final String TITLE_JMXINVOKER_UNPROTECTED = "JMXInvokerServlet/EJBInvokerServlet Remote Command Execution";
    private static final String DESCRIPTION_JMXINVOKER_UNPROTECTED = "J2EEscan identified the JBoss HttpAdaptor"
            + " JMXInvokerServlet accessible "
            + " to unauthenticated remote users. This issue could be exploited by "
            + "malicious user to execute remote commands on the target.<br /><br />"
            + "<b>References:</b><br /><br />"
            + "http://www.exploit-db.com/exploits/21080/<br />"
            + "http://www.jboss.org/community/wiki/SecureJBoss<br />"
            + "http://book.soundonair.ru/java/ch02lev1sec4.html#ch02lev4sec16<br />"
            + "http://blog.imperva.com/2013/11/threat-advisory-a-jboss-as-exploit-web-shell-code-injection.html<br />"
            + "https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/4.3/html/Installation_Guide/Adminstration_Console_User_Guide-Configuration-Security-HTTPInvoker.html";

    private static final String TITLE_JMXINVOKER_WEAK_PASSWORD = "Jboss Invoker Servlet Weak Password";
    private static final String DESCRIPTION_JMXINVOKER_WEAK_PASSWORD = "J2EEscan identified the Jboss Invoker Servlet"
            + " protected by a weak password. <br />"
            + " This issue could be exploited by malicious user to execute remote commands"
            + " on the target.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html<br />"
            + "http://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/<br />"
            + "https://access.redhat.com/documentation/en-US/JBoss_Enterprise_Application_Platform/4.3/html/Installation_Guide/Adminstration_Console_User_Guide-Configuration-Security-HTTPInvoker.html"; 
    
    private static final String REMEDY = "Disable or restrict access to the JMXInvokerServlet/EJBInvokerServlet";

    private static final List<String> JBOSS_INVOKER_PATHS = Arrays.asList(
            "/invoker/EJBInvokerServlet",
            "/invoker/JMXInvokerServlet"
    );   

    private static final byte[] GREP_STRING = "org.jboss.invocation.MarshalledValue".getBytes();
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

            for (String JBOSS_INVOKER_PATH : JBOSS_INVOKER_PATHS) {

                try {

                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), JBOSS_INVOKER_PATH);
                    byte[] jbosstest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, jbosstest);

                    IResponseInfo jbossInvokerInfo = helpers.analyzeResponse(response);

                    if (jbossInvokerInfo.getStatusCode() == 200) {

                        // look for matches of our active check grep string
                        List<int[]> matcheInvoker = getMatches(response, GREP_STRING, helpers);
    
                        if (matcheInvoker.size() > 0){

                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), JBOSS_INVOKER_PATH),
                                    new CustomHttpRequestResponse(jbosstest, response, baseRequestResponse.getHttpService()),
                                    TITLE_JMXINVOKER_UNPROTECTED,
                                    DESCRIPTION_JMXINVOKER_UNPROTECTED,
                                    REMEDY,
                                    Risk.High,
                                    Confidence.Certain
                            ));
                            
                            return issues;
                        }

                    }
 
                    
                    if (jbossInvokerInfo.getStatusCode() == 401) {
                        // Test Weak Passwords
                        CustomHttpRequestResponse httpWeakPasswordResult;
                        httpWeakPasswordResult = HTTPBasicBruteforce(callbacks, urlToTest);

                        if (httpWeakPasswordResult != null) {
                            issues.add(new CustomScanIssue(
                                    baseRequestResponse.getHttpService(),
                                    new URL(protocol, url.getHost(), url.getPort(), urlToTest.getPath()),
                                    httpWeakPasswordResult,
                                    TITLE_JMXINVOKER_WEAK_PASSWORD,
                                    DESCRIPTION_JMXINVOKER_WEAK_PASSWORD,
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
