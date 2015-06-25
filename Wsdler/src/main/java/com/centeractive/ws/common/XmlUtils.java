/**
 * Copyright (c) 2012 centeractive ag. All Rights Reserved.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.centeractive.ws.common;

import com.centeractive.ws.SoapException;
import org.custommonkey.xmlunit.XMLUnit;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Tom Bujok
 * @since 1.0.0
 */
public final class XmlUtils {

    private XmlUtils() {
    }

    public static Set<String> getNodeNames(Set<Node> nodes) {
        Set<String> names = new HashSet<String>();
        for (Node node : nodes) {
            names.add(node.getLocalName());
        }
        return names;
    }

    public static Set<QName> getNodeTypes(Set<Node> nodes) {
        Set<QName> names = new HashSet<QName>();
        for (Node node : nodes) {
            names.add(nodeToQName(node));
        }
        return names;
    }

    public static Set<Node> getRootNodes(DOMSource request) {
        return populateNodes(request.getNode(), new HashSet<Node>());
    }

    public static Set<Node> populateNodes(Node node, Set<Node> nodes) {
        if (node != null) {
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                nodes.add(node);
            }
            populateNodes(node.getNextSibling(), nodes);
        }
        return nodes;
    }

    public static QName nodeToQName(Node node) {
        return new QName(node.getNamespaceURI(), node.getLocalName());
    }

    public static Source xmlStringToSource(String xmlString) {
        StringReader reader = new StringReader(xmlString);
        InputSource src = new InputSource(reader);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(src);
            Source xmlSource = new javax.xml.transform.dom.DOMSource(dom);
            return xmlSource;
        } catch (ParserConfigurationException ex) {
            throw new SoapException(ex);
        } catch (SAXException ex) {
            throw new SoapException(ex);
        } catch (IOException ex) {
            throw new SoapException(ex);
        }
    }

    public static String sourceToXmlString(Source xmlSource) {
        if (xmlSource == null) {
            return "";
        }
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = null;
        try {
            transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(xmlSource, new StreamResult(writer));
            return writer.toString();
        } catch (TransformerConfigurationException e) {
            throw new SoapException("Error during XML transformer configuration", e);
        } catch (TransformerException e) {
            throw new SoapException("Error during XML source transformation", e);
        }
    }

    public static String serializePretty(Document document) {
        try {
            Writer out = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new DOMSource(document), new StreamResult(out));
            return out.toString();
        } catch (TransformerConfigurationException e) {
            throw new SoapException("Failed to serialize: ", e);
        } catch (TransformerException e) {
            throw new SoapException("Failed to serialize: ", e);
        }
    }

    public static String normalizeAndRemoveValues(String xmlContent) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setCoalescing(true);
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setIgnoringComments(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document document = db.parse(new ByteArrayInputStream(xmlContent.getBytes()));
            document.normalizeDocument();
            processNode(document);
            return XmlUtils.serializePretty(document);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void processNode(Node node) throws Exception {
        if (node.hasChildNodes()) {
            for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
                processNode(child);
            }
        } else {
            node.setTextContent(" ");
        }
    }

    public static boolean isIdenticalNormalizedWithoutValues(String expected, String current) {
        String expectedProcessed = normalizeAndRemoveValues(expected);
        String currentProcessed = normalizeAndRemoveValues(current);
        try {
            return XMLUnit.compareXML(expectedProcessed, currentProcessed).identical();
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
