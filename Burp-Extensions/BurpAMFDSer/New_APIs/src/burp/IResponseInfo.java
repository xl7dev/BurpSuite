package burp;

/*
 * @(#)IResponseInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used to retrieve key details about an HTTP response.
 * Extensions can obtain an
 * <code>IResponseInfo</code> object for a given response by calling
 * <code>IExtensionHelpers.analyzeResponse()</code>.
 */
public interface IResponseInfo
{
    /**
     * This method is used to obtain the HTTP headers contained in the response.
     *
     * @return The HTTP headers contained in the response.
     */
    List<String> getHeaders();

    /**
     * This method is used to obtain the offset within the response where the
     * message body begins.
     *
     * @return The offset within the response where the message body begins.
     */
    int getBodyOffset();

    /**
     * This method is used to obtain the HTTP status code contained in the
     * response.
     *
     * @return The HTTP status code contained in the response.
     */
    short getStatusCode();
}
