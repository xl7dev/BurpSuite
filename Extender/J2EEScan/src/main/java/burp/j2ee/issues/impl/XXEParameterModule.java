package burp.j2ee.issues.impl;

import burp.HTTPMatcher;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extend detection for XXE attacks
 *
 * XXE test on all HTTP parameters, not only on SOAP XML POST requests
 *
 */
public class XXEParameterModule implements IModule{

    private static final String TITLE = "XML Security - XML External Entities Injection (XXE)";
    private static final String DESCRIPTION = "J2EEscan detect a XML External Entities Injection vulnerability.<br />"
            + "The XML parsing library supports the use of custom entity references "
            + "in the XML document; custom entities "
            + "can be defined by including a user defined <pre>DOCTYPE</pre> that "
            + "reference an external resource to be included.<br /> "
            + "This option could be abused to carry on XXE attacks, leading "
            + "to <i>DoS</i> conditions, "
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

    private static final String REMEDY = "It's reccomended to disable <pre>DOCTYPE</pre> resolution on the XML library or update it with the last security patches. <br />"
            + "https://github.com/jmurty/java-xmlbuilder/issues/6<br />"
            + "https://www.java.net/xxe-xml-external-entity-attack-jaxb-and-jersey<br />"
            + "<strong>JAXB</strong><br />"
            + "Disable the following properties <pre>IS_SUPPORTING_EXTERNAL_ENTITIES</pre> and"
            + " <pre>XMLInputFactory.SUPPORT_DTD</pre><br /><br />";

    private static final List<byte[]> XXE_INJECTION_TESTS = Arrays.asList(
            "<?xml version=\"\"1.0\"\" encoding=\"\"ISO-8859-1\"\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"\"file:////etc/passwd\"\">]><foo>&xxe;</foo>".getBytes());

    private static final List<Pattern> XXE_RE_MATCHES = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
            Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        for (byte[] INJ_TEST : XXE_INJECTION_TESTS) {
            
            // Test for XXE only if the injection point is an xml stream
            String baseValue = insertionPoint.getBaseValue();            
            if (!HTTPMatcher.isXML(baseValue)){
                return issues;
            }
                
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);

            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            String response = helpers.bytesToString(checkRequestResponse.getResponse());

            for (Pattern xxeMatcher : XXE_RE_MATCHES) {

                Matcher matcher = xxeMatcher.matcher(response);

                if (matcher.find()) {

                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
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
