package burp.j2ee.issues.impl;


import burp.HTTPMatcher;
import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.J2EELFIRetriever;
import static burp.J2EELocalAssessment.analyzeWEBXML;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * 
 * Sometimes in J2EE environments absolute LFI attempts fails, because
 * the issue is limited to the web application context.
 * 
 * The module tries to retrieve the web.xml file of the remote J2EE application
 */
public class LFIModule implements IModule{

    private static final String TITLE = "Local File include - web.xml retrieved";
    private static final String DESCRIPTION = "J2EEscan identified a local file include vulnerability. "
            + "It was possible to retrieve the web file descriptor of the remote web application.<br /><br />"
            + "This vulnerability could be used to disclose any file under the web app root (example: Java classes "
            + "and source code, J2EE jar libraries, properties files with sensitive credentials)."
            + "<br />";
            
    private static final String LFI_REMEDY = "Execute a code review activity to mitigate the LFI vulnerability<br />"
                + "<b>References</b>:<br /><br />"
                + "http://www.hpenterprisesecurity.com/vulncat/en/vulncat/java/file_disclosure_spring_webflow.html<br />"
                + "https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion<br />"
                + "http://cwe.mitre.org/data/definitions/22.html<br />"
                + "https://www.securecoding.cert.org/confluence/display/cplusplus/FIO02-CPP.+Canonicalize+path+names+originating+from+untrusted+sources<br />"
                + "https://www.securecoding.cert.org/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them";
        
    private PrintWriter stderr;
    private static final byte[] GREP_STRING = "<web-app".getBytes();
    private static final List<byte[]> LFI_INJECTION_TESTS = Arrays.asList(
            "../../../../WEB-INF/web.xml".getBytes(),
            "../../../WEB-INF/web.xml".getBytes(),
            "../../WEB-INF/web.xml".getBytes(),
            "../WEB-INF/web.xml".getBytes(),
            // Spring Webflow payloads
            "../../../WEB-INF/web.xml;x=".getBytes(),
            "../../WEB-INF/web.xml;x=".getBytes(),  
            "../WEB-INF/web.xml;x=".getBytes()          
    );    
    
    
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        
        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        for (byte[] INJ_TEST : LFI_INJECTION_TESTS) {
            
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);
            
            try {
                
                // look for matches
                byte[] response =  checkRequestResponse.getResponse();
                List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                if (matches.size() > 0) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION + " " +  HTTPMatcher.getServletsDescription(helpers.bytesToString(response)),
                            LFI_REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                    
                    // Security Audit web.xml
                    analyzeWEBXML(response, callbacks, checkRequestResponse);
            
                    // Try to retrieve more configuration files using this threat
                    J2EELFIRetriever.download(callbacks, 
                                checkRequestResponse,
                                checkRequest,
                                "web.xml");
                        
                        
                    return issues;
                }
                
            } catch (Exception ex){
                stderr.println(ex);
            }
        }
        
        return issues;
    }
}
