package burp.j2ee;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse httpMessages;
    private String name;
    private String detail;
    private Risk severity;
    private String remedy;
    private Confidence confidence = Confidence.Certain;
    
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse httpMessages,
            String name,
            String detail,
            String remedy,
            Risk severity,
            Confidence confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remedy = remedy;
        this.severity = severity;
        this.confidence = confidence;
    }      
    

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity.toString();
    }

    @Override
    // "Certain", "Firm" or "Tentative"
    public String getConfidence() {
        return confidence.toString();
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remedy;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{httpMessages};
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}
