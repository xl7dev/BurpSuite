package burp.j2ee.issues.impl;

import burp.CustomHttpRequestResponse;
import burp.HTTPParser;
import static burp.HTTPParser.getResponseHeaderValue;
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
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class HTTPWeakPassword implements IModule{

    private static final String TITLE = "HTTP Weak Password";
    private static final String DESCRIPTION = "J2EEscan identified a remote resource protected"
            + "using HTTP Authentication with a weak password.<br />";

    private static final String REMEDY = "Change the weak/default password";
    
    // List of host and port system already tested
    private LinkedHashSet hs = new LinkedHashSet();
    private PrintWriter stderr;


    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        byte[] response = baseRequestResponse.getResponse();
        if (response == null) {
            return issues;
        }

        IResponseInfo respInfo = helpers.analyzeResponse(response);

        URL url = reqInfo.getUrl();
        short responseCode = respInfo.getStatusCode();
        String wwwAuthHeader = getResponseHeaderValue(respInfo, "WWW-Authenticate");
        
        if (responseCode == 401 && wwwAuthHeader != null) {

            // Application path not yet tested for this vulnerability
            if (!hs.contains(url)) {

                hs.add(url);

                // Test Weak Passwords
                CustomHttpRequestResponse httpWeakPasswordResult;
                httpWeakPasswordResult = HTTPBasicBruteforce(callbacks, url);

                // Retrieve the weak credentials
                String weakCredential = null;
                String weakCredentialDescription = "";
                try {

                    IRequestInfo reqInfoPwd = callbacks.getHelpers().analyzeRequest(baseRequestResponse.getHttpService(), httpWeakPasswordResult.getRequest());
                    weakCredential = new String(helpers.base64Decode(HTTPParser.getHTTPBasicCredentials(reqInfoPwd)));
                } catch (Exception ex) {
                    stderr.println("Error during Authorization Header parsing " + ex);
                }

                if (weakCredential != null) {
                    weakCredentialDescription += String.format("<br /><br /> The weak credentials are "
                            + "<b>%s</b><br /><br />", weakCredential);
                }

                if (httpWeakPasswordResult != null) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            url,
                            httpWeakPasswordResult,
                            TITLE,
                            DESCRIPTION + weakCredentialDescription,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));

                }

            }

        }
        
        return issues;
    }
}
