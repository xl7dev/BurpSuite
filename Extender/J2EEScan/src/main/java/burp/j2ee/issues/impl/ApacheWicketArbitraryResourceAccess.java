package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

import java.util.List;

public class ApacheWicketArbitraryResourceAccess implements IModule {

    private static final String TITLE = "Apache Wicket - Arbitrary Resource Access";
    private static final String DESCRIPTION = "J2EEScan identified a vulnerable Apache Wicket library; "
            + "it's possible to access remotely to arbitrary resources in"
            + " the classpath of the wicket application using the <i>int</i> scope<br /><br />"
            + "<b>References</b>:<br />"
            + "https://issues.apache.org/jira/browse/WICKET-4427<br />"
            + "https://issues.apache.org/jira/browse/WICKET-4430";

    private static final String REMEDY = "Update the remote Apache Wicket vulnerable library";

    private static final byte[] GREP_STRING = "initializer=".getBytes();
    private static final List<String> PAYLOADS = Arrays.asList(
            "wicket/resource/int/wicket.properties,/bla/ HTTP",
            "wicket/resources/int/wicket.properties,/bla/ HTTP"
    );

    private PrintWriter stderr;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        
        if (curURL.getPath().contains("wicket/resource")) {
            byte[] rawrequest = baseRequestResponse.getRequest();
            String plainRequest = helpers.bytesToString(rawrequest);

            for (String PAYLOAD : PAYLOADS) {
                
                byte[] wicketRequest = helpers.stringToBytes(plainRequest.replaceFirst("wicket\\/resource.*? HTTP", PAYLOAD));

                IRequestInfo rawWicketRequestInfo = helpers.analyzeRequest(wicketRequest);

                List<String> headers = rawWicketRequestInfo.getHeaders();
                byte message[] = helpers.buildHttpMessage(headers, Arrays.copyOfRange(wicketRequest, rawWicketRequestInfo.getBodyOffset(), wicketRequest.length));
                IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

                // look for matches of our active check grep string in the response body
                byte[] httpResponse = resp.getResponse();
                List<int[]> matches = getMatches(httpResponse, GREP_STRING, helpers);
                if (matches.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            resp,
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

        return issues;

    }
}
