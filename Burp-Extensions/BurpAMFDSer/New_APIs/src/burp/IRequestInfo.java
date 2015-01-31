package burp;

/*
 * @(#)IRequestInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.URL;
import java.util.List;

/**
 * This interface is used to retrieve key details about an HTTP request.
 * Extensions can obtain an
 * <code>IRequestInfo</code> object for a given request by calling
 * <code>IExtensionHelpers.analyzeRequest()</code>.
 */
public interface IRequestInfo
{
    /**
     * This method is used to obtain the HTTP method used in the request.
     *
     * @return The HTTP method used in the request.
     */
    String getMethod();

    /**
     * This method is used to obtain the URL in the request.
     *
     * @return The URL in the request.
     */
    URL getUrl();

    /**
     * This method is used to obtain the HTTP headers contained in the request.
     *
     * @return The HTTP headers contained in the request.
     */
    List<String> getHeaders();

    /**
     * This method is used to obtain the parameters contained in the request.
     *
     * @return The parameters contained in the request.
     */
    List<IParameter> getParameters();

    /**
     * This method is used to obtain the offset within the request where the
     * message body begins.
     *
     * @return The offset within the request where the message body begins.
     */
    int getBodyOffset();
}
