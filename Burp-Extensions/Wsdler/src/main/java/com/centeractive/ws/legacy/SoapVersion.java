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

import org.apache.commons.lang3.StringUtils;
import org.apache.xmlbeans.*;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.util.List;

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
 * Public behaviour for a SOAP Version
 *
 * @author ole.matzura
 */
interface SoapVersion {
    public static final SoapVersion11 Soap11 = SoapVersion11.instance;
    public static final SoapVersion12 Soap12 = SoapVersion12.instance;

    public QName getEnvelopeQName();

    public QName getBodyQName();

    public QName getHeaderQName();

    public void validateSoapEnvelope(String soapMessage, List<XmlError> errors);

    public String getContentTypeHttpHeader(String encoding, String soapAction);

    public String getEnvelopeNamespace();

    public String getFaultDetailNamespace();

    public String getEncodingNamespace();

    public XmlObject getSoapEncodingSchema() throws XmlException, IOException;

    public XmlObject getSoapEnvelopeSchema() throws XmlException, IOException;

    /**
     * Checks if the specified validation error should be ignored for a message
     * with this SOAP version. (The SOAP-spec may allow some constructions not
     * allowed by the corresponding XML-Schema)
     */

    public boolean shouldIgnore(XmlValidationError xmlError);

    public String getContentType();

    public SchemaType getEnvelopeType();

    public SchemaType getFaultType();

    public String getName();

    /**
     * Utilities
     *
     * @author ole.matzura
     */

    public static class Utils {
        public static SoapVersion getSoapVersionForContentType(String contentType, SoapVersion def) {
            if (StringUtils.isBlank(contentType))
                return def;

            SoapVersion soapVersion = contentType.startsWith(SoapVersion.Soap11.getContentType()) ? SoapVersion.Soap11
                    : null;
            soapVersion = soapVersion == null && contentType.startsWith(SoapVersion.Soap12.getContentType()) ? SoapVersion.Soap12
                    : soapVersion;

            return soapVersion == null ? def : soapVersion;
        }
    }

    public String getSoapActionHeader(String soapAction);
}
