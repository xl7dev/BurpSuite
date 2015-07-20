package burp;

import burp.j2ee.CustomScanIssue;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class WeakPasswordBruteforcer {

    private static PrintWriter stderr;
    private static PrintWriter stdout;
    
    /**
     * HTTP Basic Authentication (rfc-2617) Weak Password test
     * 
     * @param callbacks
     * @param urlToTest
     * @return 
     */
    public static CustomHttpRequestResponse HTTPBasicBruteforce(IBurpExtenderCallbacks callbacks, final URL urlToTest) {

        
        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);

        List<Map.Entry<String, String>> credentials;
        credentials = WeakPassword.getCredentials();

        byte[] httpAuthTest = helpers.buildHttpRequest(urlToTest);

        String protocol = urlToTest.getProtocol();
        Boolean isSSL = (protocol.equals("https"));

        byte[] response = callbacks.makeHttpRequest(urlToTest.getHost(),
                urlToTest.getPort(), isSSL, httpAuthTest);

        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        if (responseInfo.getStatusCode() == 401) {
            stdout.println("Checking weak credentials on " + urlToTest);
            
            //Retrieve request headers
            IRequestInfo requestInfo = helpers.analyzeRequest(httpAuthTest);
            List requestHeaders = requestInfo.getHeaders();

            for (Map.Entry<String, String> credential : credentials) {

                try {
                    List<String> requestHeadersToTest = new ArrayList<>(requestHeaders);

                    String user = credential.getKey();
                    String pwd = credential.getValue();

                    requestHeadersToTest.add("Authorization: Basic "
                            + helpers.base64Encode(user + ":" + pwd));

                    byte[] makeHttpRequest = helpers.buildHttpMessage(requestHeadersToTest, null);

                    byte[] responseWeakPassword = callbacks.makeHttpRequest(urlToTest.getHost(),
                            urlToTest.getPort(),
                            isSSL,
                            makeHttpRequest);

                    IResponseInfo httpAuthAttemptResponse = helpers.analyzeResponse(responseWeakPassword);
                    IHttpService httpServiceInstance = new IHttpService() {

                        @Override
                        public String getHost() {
                            return urlToTest.getHost();
                        }

                        @Override
                        public int getPort() {
                            return urlToTest.getPort();
                        }

                        @Override
                        public String getProtocol() {
                            return urlToTest.getProtocol();
                        }
                    };

                    // Weak Password found
                    if (httpAuthAttemptResponse.getStatusCode() == 200) {
                        stdout.println("[!] Weak Credentils " + user + ":" + pwd+ " on " + urlToTest);
                        CustomHttpRequestResponse result = new CustomHttpRequestResponse(
                                makeHttpRequest,
                                responseWeakPassword,
                                httpServiceInstance);
        

                        HTTPMatcher.getVulnerabilityByPageParsing(result, callbacks);
                                
                        return result;
                    }

                } catch (Exception e) {
                    stderr.println("Error during HTTP Bruteforcing on " 
                            + urlToTest + ". Error " + e);
                }
            }

        }

        return null;

    }
}
