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

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * 
 * This module tries to detect common Expression Language Injection on different
 * J2EE frameworks (Spring, SEAM).
 * 
 * This vulnerability usually could lead to Remote command execution or 
 * Authorization bypass issues
 */

public class ELInjection implements IModule {

    private static final String TITLE = "EL (Expression Language) Injection";
    private static final String DESCRIPTION = "J2EEscan identified an EL (Expression Language) "
            + "Injection vulnerability; an expression language makes it possible to easily "
            + "access application data stored in JavaBeans components. <br />"
            + "The EL Injection vulnerability allows a remote user to control data passed "
            + "to the EL Interpreter, allowing attackers, in some cases, to execute code on the server."  
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "http://www.mindedsecurity.com/fileshare/ExpressionLanguageInjection.pdf<br />"
            + "http://cwe.mitre.org/data/definitions/917.html<br />"
            + "https://www.owasp.org/index.php/Expression_Language_Injection<br />"
            + "http://support.springsource.com/security/cve-2011-2730<br />"
            + "http://www.blackhat.com/html/bh-dc-10/bh-dc-10-briefings.html#Byrne<br />"            
            + "http://danamodio.com/application-security/discoveries/spring-remote-code-with-expression-language-injection/<br />"
            + "http://jcp.org/aboutJava/communityprocess/mrel/jsr245/index.html<br />"
            + "JSF - https://java.net/jira/browse/JAVASERVERFACES-2247<br />"
            + "MYFACES - https://issues.apache.org/jira/browse/MYFACES-3405<br />"; 
            

    private static final String REMEDY = "Update the remote vulnerable library";
    
    private static final byte[] GREP_STRING = "javax.servlet.context".getBytes();  
    private static final List<byte[]> EL_INJECTION_TESTS = Arrays.asList(
            "${applicationScope}".getBytes(), 
            "#{applicationScope}".getBytes());            
     
    
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        
        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        
        // Skip test for not j2ee applications
        if (curURL.getPath().contains(".php") || 
            curURL.getPath().contains(".asp") ||
            curURL.getPath().contains(".cgi") ||
            curURL.getPath().contains(".pl")
           ) {            
            return issues;
        }
        
        for (byte[] INJ_TEST : EL_INJECTION_TESTS) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);


            // look for matches of our active check grep string
            List<int[]> matches = getMatches(checkRequestResponse.getResponse(), GREP_STRING, helpers);
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
            }
            
        }    
          
        return issues;
    }
}
