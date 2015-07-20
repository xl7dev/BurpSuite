package burp.j2ee.issues;


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import java.util.List;

public interface IModule {
 
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks,
            IHttpRequestResponse baseRequestResponse, 
            IScannerInsertionPoint insertionPoint);
}