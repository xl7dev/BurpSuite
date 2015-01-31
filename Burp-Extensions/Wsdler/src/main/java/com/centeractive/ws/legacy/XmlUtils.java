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

import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.Writer;
import java.net.URL;
import java.util.*;

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
 * - adding utility method to handle XML-String from/to XML-Source transformation
 */

/**
 * General XML-related utilities
 */
@SuppressWarnings("deprecation")
final class XmlUtils {
    private static DocumentBuilder documentBuilder;
    private final static Logger log = Logger.getLogger(XmlUtils.class);

    static synchronized public Document parse(InputStream in) {
        try {
            return ensureDocumentBuilder().parse(in);
        } catch (Exception e) {
            log.error("Error parsing InputStream; " + e.getMessage(), e);
        }

        return null;
    }

    static synchronized public Document parse(String fileName) throws IOException {
        try {
            return ensureDocumentBuilder().parse(fileName);
        } catch (SAXException e) {
            log.error("Error parsing fileName [" + fileName + "]; " + e.getMessage(), e);
        }

        return null;
    }


    static synchronized public Document parse(InputSource inputSource) throws IOException {
        try {
            return ensureDocumentBuilder().parse(inputSource);
        } catch (SAXException e) {
            throw new IOException(e.toString());
        }
    }

    private static DocumentBuilder ensureDocumentBuilder() {
        if (documentBuilder == null) {
            try {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                documentBuilder = dbf.newDocumentBuilder();
            } catch (ParserConfigurationException e) {
                log.error("Error creating DocumentBuilder; " + e.getMessage());
            }
        }

        return documentBuilder;
    }


    public static XmlObject createXmlObject(String input, XmlOptions xmlOptions) throws XmlException {
        return XmlObject.Factory.parse(input, xmlOptions);
    }

    public static XmlObject createXmlObject(URL input, XmlOptions xmlOptions) throws XmlException {
        try {
            return XmlObject.Factory.parse(input, xmlOptions);
        } catch (Exception e) {
            throw new XmlException(e.toString());
        }
    }


    public static XmlObject createXmlObject(String input) throws XmlException {
        return XmlObject.Factory.parse(input);
    }

    public static XmlObject createXmlObject(URL input) throws XmlException {
        try {
            return XmlObject.Factory.parse(input);
        } catch (Exception e) {

            throw new XmlException(e);
        }
    }


    static public void setElementText(Element elm, String text) {
        Node node = elm.getFirstChild();
        if (node == null) {
            if (text != null)
                elm.appendChild(elm.getOwnerDocument().createTextNode(text));
        } else if (node.getNodeType() == Node.TEXT_NODE) {
            if (text == null)
                node.getParentNode().removeChild(node);
            else
                node.setNodeValue(text);
        } else if (text != null) {
            Text textNode = node.getOwnerDocument().createTextNode(text);
            elm.insertBefore(textNode, elm.getFirstChild());
        }
    }


    public static Document parseXml(String xmlString) throws IOException {
        return parse(new InputSource(new StringReader(xmlString)));
    }


    /**
     * Returns absolute xpath for specified element, ignores namespaces
     *
     * @param element the element to create for
     * @return the elements path in its containing document
     */


    /**
     * Gets the index of the specified element amongst elements with the same
     * name
     *

     * @return the index of the element, will be >= 1
     */


    public static boolean setNodeValue(Node domNode, String string) {
        if (domNode == null)
            return false;

        short nodeType = domNode.getNodeType();

        switch (nodeType) {
            case Node.ELEMENT_NODE: {
                setElementText((Element) domNode, string);
                break;
            }
            case Node.ATTRIBUTE_NODE:
            case Node.TEXT_NODE: {
                domNode.setNodeValue(string);
                break;
            }
            case Node.PROCESSING_INSTRUCTION_NODE: {
                ((ProcessingInstruction) domNode).setData(string);
                break;
            }
            case Node.CDATA_SECTION_NODE: {
                ((CDATASection) domNode).setData(string);
                break;
            }
            default: {
                return false;
            }
        }

        return true;
    }

    public static String declareXPathNamespaces(XmlObject xmlObject) {
        Map<QName, String> map = new HashMap<QName, String>();
        XmlCursor cursor = xmlObject.newCursor();

        while (cursor.hasNextToken()) {
            if (cursor.toNextToken().isNamespace())
                map.put(cursor.getName(), cursor.getTextValue());
        }

        cursor.dispose();

        Iterator<QName> i = map.keySet().iterator();
        int nsCnt = 0;

        StringBuffer buf = new StringBuffer();
        Set<String> prefixes = new HashSet<String>();
        Set<String> usedPrefixes = new HashSet<String>();

        while (i.hasNext()) {
            QName name = i.next();
            String prefix = name.getLocalPart();
            if (prefix.length() == 0)
                prefix = "ns" + Integer.toString(++nsCnt);
            else if (prefix.equals("xsd") || prefix.equals("xsi"))
                continue;

            if (usedPrefixes.contains(prefix)) {
                int c = 1;
                while (usedPrefixes.contains(prefix + c))
                    c++;

                prefix = prefix + Integer.toString(c);
            } else
                prefixes.add(prefix);

            buf.append("declare namespace ");
            buf.append(prefix);
            buf.append("='");
            buf.append(map.get(name));
            buf.append("';\n");

            usedPrefixes.add(prefix);
        }

        return buf.toString();
    }

    public static String setXPathContent(String xmlText, String xpath, String value) {
        try {
            XmlObject xmlObject = XmlObject.Factory.parse(xmlText);

            String namespaces = declareXPathNamespaces(xmlObject);
            if (namespaces != null && namespaces.trim().length() > 0)
                xpath = namespaces + xpath;

            XmlObject[] path = xmlObject.selectPath(xpath);
            for (XmlObject xml : path) {
                setNodeValue(xml.getDomNode(), value);
            }

            return xmlObject.toString();
        } catch (Exception e) {

            e.printStackTrace();
        }

        return xmlText;
    }

    public static void serializePretty(XmlObject xmlObject, Writer writer) throws IOException {
        XmlOptions options = new XmlOptions();
        options.setSavePrettyPrint();
        options.setSavePrettyPrintIndent(3);
        options.setSaveNoXmlDecl();
        options.setSaveAggressiveNamespaces();
        // StringToStringMap map = new StringToStringMap();
        // map.put( SoapVersion.Soap11.getEnvelopeNamespace(), "SOAPENV" );
        // map.put( SoapVersion.Soap12.getEnvelopeNamespace(), "SOAPENV" );
        //
        // options.setSaveSuggestedPrefixes( map );
        xmlObject.save(writer, options);
    }

}
