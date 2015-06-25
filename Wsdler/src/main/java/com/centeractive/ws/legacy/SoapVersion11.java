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

import com.centeractive.ws.SoapBuilderException;
import com.centeractive.ws.common.ResourceUtils;
import org.apache.xmlbeans.*;
import org.xmlsoap.schemas.soap.envelope.EnvelopeDocument;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URL;

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
 * - changing the mechanism using which external resources are loaded
 */

/**
 * SoapVersion for SOAP 1.1
 *
 * @author ole.matzura
 */
class SoapVersion11 extends AbstractSoapVersion {
    private final static QName envelopeQName = new QName(Constants.SOAP11_ENVELOPE_NS, "Envelope");
    private final static QName bodyQName = new QName(Constants.SOAP11_ENVELOPE_NS, "Body");
    private final static QName faultQName = new QName(Constants.SOAP11_ENVELOPE_NS, "Fault");
    private final static QName headerQName = new QName(Constants.SOAP11_ENVELOPE_NS, "Header");

    SchemaTypeLoader soapSchema;
    SchemaType soapEnvelopeType;
    private XmlObject soapSchemaXml;
    private XmlObject soapEncodingXml;
    private SchemaType soapFaultType;

    public final static SoapVersion11 instance = new SoapVersion11();

    private SoapVersion11() {
        try {
            XmlOptions options = new XmlOptions();
            options.setCompileNoValidation();
            options.setCompileNoPvrRule();
            options.setCompileDownloadUrls();
            options.setCompileNoUpaRule();
            options.setValidateTreatLaxAsSkip();

            URL soapSchemaXmlResource = ResourceUtils.getResourceWithAbsolutePackagePath(getClass(),
                    "/xsds/", "soapEnvelope.xsd");
            soapSchemaXml = XmlUtils.createXmlObject(soapSchemaXmlResource, options);
            soapSchema = XmlBeans.loadXsd(new XmlObject[]{soapSchemaXml});

            soapEnvelopeType = soapSchema.findDocumentType(envelopeQName);
            soapFaultType = soapSchema.findDocumentType(faultQName);

            URL soapEncodingXmlResource = ResourceUtils.getResourceWithAbsolutePackagePath(getClass(),
                    "/xsds/", "soapEncoding.xsd");
            soapEncodingXml = XmlUtils.createXmlObject(soapEncodingXmlResource, options);

        } catch (XmlException ex) {
            throw new SoapBuilderException(ex);
        }
    }

    public SchemaType getEnvelopeType() {
        return EnvelopeDocument.type;
    }

    public String getEnvelopeNamespace() {
        return Constants.SOAP11_ENVELOPE_NS;
    }

    public String getEncodingNamespace() {
        return Constants.SOAP_ENCODING_NS;
    }

    public XmlObject getSoapEncodingSchema() throws XmlException, IOException {
        return soapEncodingXml;
    }

    public XmlObject getSoapEnvelopeSchema() throws XmlException, IOException {
        return soapSchemaXml;
    }

    public String toString() {
        return "SOAP 1.1";
    }

    public String getContentTypeHttpHeader(String encoding, String soapAction) {
        if (encoding == null || encoding.trim().length() == 0)
            return getContentType();
        else
            return getContentType() + ";charset=" + encoding;
    }

    public String getSoapActionHeader(String soapAction) {
        if (soapAction == null || soapAction.length() == 0) {
            soapAction = "\"\"";
        } else {
            soapAction = "\"" + soapAction + "\"";
        }

        return soapAction;
    }

    public String getContentType() {
        return "text/xml";
    }

    public QName getBodyQName() {
        return bodyQName;
    }

    public QName getEnvelopeQName() {
        return envelopeQName;
    }

    public QName getHeaderQName() {
        return headerQName;
    }

    protected SchemaTypeLoader getSoapEnvelopeSchemaLoader() {
        return soapSchema;
    }

    public SchemaType getFaultType() {
        return soapFaultType;
    }

    public String getName() {
        return "SOAP 1.1";
    }

    public String getFaultDetailNamespace() {
        return "";
    }
}
