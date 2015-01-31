/**
 * Copyright (c) 2012 centeractive ag. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */
package com.centeractive.ws.legacy;

/**
 * This class was extracted from the soapUI code base by centeractive ag in October 2011.
 * The main reason behind the extraction was to separate the code that is responsible
 * for the generation of the SOAP messages from the rest of the soapUI's code that is
 * tightly coupled with other modules, such as soapUI's graphical user interface, etc.
 * The goal was to create an open-source java project whose main responsibility is to
 * handle SOAP message generation and SOAP transmission purely on an XML level.
 * <br/>
 * centeractive ag would like to express strong appreciation to SmartBear Software and
 * to the whole team of soapUI's developers for creating soapUI and for releasing its
 * source code under a free and open-source licence. centeractive ag extracted and
 * modifies some parts of the soapUI's code in good faith, making every effort not
 * to impair any existing functionality and to supplement it according to our
 * requirements, applying best practices of software design.
 *
 * Changes done:
 * - changing location in the package structure
 * - removal of dependencies and code parts that are out of scope of SOAP message generation
 * - minor fixes to make the class compile out of soapUI's code base
 */

/**
 * Namespace Constants
 *
 * @author ole.matzura
 */

interface Constants {
    public static final String XSD_NS = "http://www.w3.org/2001/XMLSchema";
    public static final String XML_NS = "http://www.w3.org/2000/xmlns/";
    public static final String WSDL11_NS = "http://schemas.xmlsoap.org/wsdl/";
    public static final String SOAP_ENCODING_NS = "http://schemas.xmlsoap.org/soap/encoding/";
    public static final String SOAP11_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String SOAP_HTTP_TRANSPORT = "http://schemas.xmlsoap.org/soap/http";
    public static final String SOAP_HTTP_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap/";
    public static final String SOAP12_HTTP_BINDING_NS = "http://www.w3.org/2003/05/soap/bindings/HTTP/";
    public static final String XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";
    public static final String XSI_NS_2000 = "http://www.w3.org/2000/XMLSchema-instance";
    public static final String SOAP12_ENVELOPE_NS = "http://www.w3.org/2003/05/soap-envelope";
    public static final String WADL10_NS = "http://research.sun.com/wadl/2006/10";
    public static final String WADL11_NS = "http://wadl.dev.java.net/2009/02";
    public static final String SOAP_MICROSOFT_TCP = "http://schemas.microsoft.com/wse/2003/06/tcp";
}
