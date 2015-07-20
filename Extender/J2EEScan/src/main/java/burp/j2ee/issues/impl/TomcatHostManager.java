package burp.j2ee.issues.impl;

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
 * This module checks the Apache Tomcat Host Manager, and test for weak/default
 * credentials
 *
 */
public class TomcatHostManager implements IModule{

    private static final String TITLE = "Tomcat Host Manager Weak Password";
    private static final String DESCRIPTION = "J2EEscan identified Tomcat Host Manager installed"
            + " on the remote system with a weak password";
    private static final String REMEDY = "Change default/weak password and/or restrict access to the management console only from trusted hosts/networks";
    
    // List of host and port system already tested
    private static LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;
    
    private static final List<String> TOMCAT_HOST_MANAGER_PATHS = Arrays.asList(
            "/host-manager/html?j2eescan"
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

            for (String TOMCAT_HOST_MANAGER_PATH : TOMCAT_HOST_MANAGER_PATHS) {

                try {
                    // Test the presence of tomcat console
                    URL urlToTest = new URL(protocol, url.getHost(), url.getPort(), TOMCAT_HOST_MANAGER_PATH);
                    byte[] tomcattest = helpers.buildHttpRequest(urlToTest);

                    byte[] response = callbacks.makeHttpRequest(url.getHost(),
                            url.getPort(), isSSL, tomcattest);

                    IResponseInfo tomcatManagerInfo = helpers.analyzeResponse(response);
                    
                    if (tomcatManagerInfo.getStatusCode() == 401) {
                        // Check Authorization header

                        /**
                         * HTTP/1.1 401 Unauthorized 
                         * Server: Apache-Coyote/1.1
                         * WWW-Authenticate:Basic realm="Tomcat Host Manager Application"
                         */
                        List<String> responseHeaders = tomcatManagerInfo.getHeaders();
                        
                        for (int h = 0; h < responseHeaders.size(); h++) {
                            
                            if (responseHeaders.get(h).toLowerCase().contains("tomcat host manager")) {

                                issues.add(new CustomScanIssue(
                                        baseRequestResponse.getHttpService(),
                                        new URL(protocol, url.getHost(), url.getPort(), TOMCAT_HOST_MANAGER_PATH),
                                        new CustomHttpRequestResponse(tomcattest, response, baseRequestResponse.getHttpService()),
                                        "Tomcat Host Manager Installed",
                                        "Tomcat Host Manager is installed on the remote system",
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
                                            new URL(protocol, url.getHost(), url.getPort(), TOMCAT_HOST_MANAGER_PATH),
                                            httpWeakPasswordResult,
                                            TITLE,
                                            DESCRIPTION,
                                            REMEDY,
                                            Risk.High,
                                            Confidence.Certain));

                                    return issues;
                                }
                                
                                return issues;
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
