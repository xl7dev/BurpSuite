package burp;


/*
 * @(#)IHttpRequestResponse.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 * 
 * This code may be used to extend the functionality of Burp Suite and Burp
 * Suite Professional, provided that this usage does not violate the 
 * license terms for those products. 
 */

/**
 * This interface is used to allow extensions to access details of HTTP messages
 * that are processed within Burp.
 * 
 * Note that the setter methods generally can only be used before the message 
 * has been forwarded to the application (e.g. using 
 * IBurpExtender.processHttpMessage()) and not in read-only contexts (e.g. using 
 * IBurpExtender.getProxyHistory()). Conversely, the getter methods relating to 
 * response details can only be used after the message has been forwarded to the
 * application.
 */

public interface IHttpRequestResponse
{
    /**
     * Returns the name of the application host.
     * 
     * @return The name of the application host.
     */
    String getHost();
    
    /**
     * Returns the port number used by the application.
     * 
     * @return The port number used by the application.
     */
    int getPort();
    
    /**
     * Returns the protocol used by the application.
     * 
     * @return The protocol used by the application.
     */
    String getProtocol();
    
    /**
     * Sets the name of the application host to which the request should 
     * be sent.
     * 
     * @param host The name of the application host to which the request should 
     * be sent.
     * @throws java.lang.Exception
     */
    void setHost(String host) throws Exception;
    
    /**
     * Sets the port number to which the request should be sent.
     * 
     * @param port The port number to which the request should be sent.
     * @throws java.lang.Exception
     */
    void setPort(int port) throws Exception;
    
    /**
     * Sets the protocol which should be used by the request.
     * 
     * @param protocol The protocol which should be used by the request. Valid 
     * values are "http" and "https".
     * @throws java.lang.Exception
     */
    void setProtocol(String protocol) throws Exception;
    
    /**
     * Returns the full request contents.
     * 
     * @return The full request contents.
     * @throws java.lang.Exception
     */
    byte[] getRequest() throws Exception;
    
    /**
     * Returns the URL within the request.
     * 
     * @return The URL within the request.
     * @throws java.lang.Exception
     */
    java.net.URL getUrl() throws Exception;
    
    /**
     * Sets the request contents which should be sent to the application.
     * 
     * @param message The request contents which should be sent to the 
     * application.
     * @throws java.lang.Exception
     */
    void setRequest(byte[] message) throws Exception; 
    
    /**
     * Returns the full response contents.
     * 
     * @return The full response contents.
     * @throws java.lang.Exception
     */
    byte[] getResponse() throws Exception; 
    
    /**
     * Sets the response contents which should be processed by the 
     * invoking Burp tool.
     * 
     * @param message The response contents which should be processed by the 
     * invoking Burp tool.
     * @throws java.lang.Exception
     */
    void setResponse(byte[] message) throws Exception;
    
    /**
     * Returns the HTTP status code contained within the response.
     * 
     * @return The HTTP status code contained within the response.
     * @throws java.lang.Exception
     */
    short getStatusCode() throws Exception;

    /**
     * Returns the user-annotated comment for this item, if applicable.
     *
     * @return The user-annotated comment for this item, or null if none is set.
     */
    String getComment() throws Exception;

    /**
     * Sets the user-annotated comment for this item.
     *
     * @param comment The comment to be associated with this item.
     * @throws Exception
     */
    void setComment(String comment) throws Exception;

}
