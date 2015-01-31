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
import com.ibm.wsdl.util.xml.DOM2Writer;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.wsdl.Definition;
import javax.wsdl.Import;
import javax.wsdl.Service;
import javax.wsdl.Types;
import javax.wsdl.extensions.schema.Schema;
import javax.wsdl.extensions.schema.SchemaImport;
import javax.wsdl.extensions.schema.SchemaReference;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.util.*;

/**
 * This class was taken from Axis2 code. It's main responsibility is to marshall wsdl4j Definition instance back into the XML format.
 * By default it only marshalled the WSDL hierarchy. It was adjusted in such a way that it recursively marshalls XSD schemas as well.<p></p>
 *
 * @author Tom Bujok
 * @since 1.0.0
 */
public class Wsdl11Writer {

    public static final String IMPORT_TAG = "import";
    public static final String INCLUDE_TAG = "include";
    public static final String SCHEMA_LOCATION = "schemaLocation";

    private File baseFolder = null;
    private int count;

    public Wsdl11Writer(File baseFolder) {
        this.baseFolder = baseFolder;
        this.count = 0;
    }

    public void writeWSDL(String name, Definition definition) {
        try {
            Map<String, String> baseURIwsdlNameMap = new HashMap<String, String>();
            // add the initial definition to the map
            baseURIwsdlNameMap.put(definition.getDocumentBaseURI(), name + ".wsdl");
            writeWSDL(definition, name + ".wsdl", new HashMap<String, String>(), baseURIwsdlNameMap);
        } catch (Exception e) {
            throw new SoapException("WSDL writing failed!", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void writeWSDL(Definition definition,
                           String fileName,
                           Map<String, String> changedMap,
                           Map baseURIwsdlNameMap) throws Exception {

        // first process the imports and save them.
        Map imports = definition.getImports();
        if (imports != null && (imports.size() > 0)) {
            Vector importsVector = null;
            Import wsdlImport = null;
            String wsdlName = null;
            String wsdlLocation = null;
            for (Iterator improtsVectorIter = imports.values().iterator();
                 improtsVectorIter.hasNext(); ) {
                importsVector = (Vector) improtsVectorIter.next();
                for (Iterator importsIter = importsVector.iterator(); importsIter.hasNext(); ) {
                    wsdlImport = (Import) importsIter.next();
                    wsdlLocation = wsdlImport.getDefinition().getDocumentBaseURI();
                    // we have to process this wsdl file only if it has not been processed earlier
                    if (!baseURIwsdlNameMap.containsKey(wsdlLocation)) {
                        wsdlName = wsdlLocation.substring(wsdlLocation.lastIndexOf('/') + 1);
                        if (!wsdlName.endsWith(".wsdl") && !wsdlName.endsWith(".xsd")) {
                            // this seems to be an online wsdl so we generate a dummy name
                            if (wsdlName.indexOf("xsd") > -1) {
                                wsdlName = "xsd" + count++ + ".xsd";
                            } else {
                                wsdlName = "wsdl" + count++ + ".wsdl";
                            }
                        }

                        //trim the wsdl part
                        while (baseURIwsdlNameMap.containsValue(wsdlName)) {
                            // import file name can either be xsd or wsdl
                            String fileNamePart = wsdlName.substring(0, wsdlName.lastIndexOf("."));
                            String extension = wsdlName.substring(wsdlName.lastIndexOf("."));
                            wsdlName = fileNamePart + count++ + extension;
                        }
                        wsdlName = normalizeName(wsdlName);
                        baseURIwsdlNameMap.put(wsdlLocation, wsdlName);
                        Definition innerDefinition = wsdlImport.getDefinition();
                        writeWSDL(innerDefinition, wsdlName, changedMap, baseURIwsdlNameMap);
                    }

                    wsdlImport.setLocationURI((String) baseURIwsdlNameMap.get(wsdlLocation));
                }
            }
        }
        // change the locations on the imported schemas
        processSchemas(definition, changedMap);
        // finally save the file
        WSDLWriter wsdlWriter = WSDLFactory.newInstance().newWSDLWriter();
        // wsdlWriter.setFeature("javax.wsdl.xml.parseXMLSchemas", true);
        File outputFile = new FileWriter().createClassFile(baseFolder, null, fileName, null);
        FileOutputStream out = new FileOutputStream(outputFile);

        // we have a catch here
        // if there are multimple services in the definition object
        // we have to write only the relavent service.


        if (definition.getServices().size() > 1) {
            List removedServices = new ArrayList();
            List servicesList = new ArrayList();

            Map services = definition.getServices();
            // populate the services list
            for (Iterator iter = services.values().iterator(); iter.hasNext(); ) {
                servicesList.add(iter.next());
            }
            Service service;
            String serviceNameFromFileName = fileName;
            if (fileName.indexOf(".wsdl") > -1) {
                serviceNameFromFileName = fileName.substring(0, fileName.lastIndexOf(".wsdl"));
            }

            if (fileName.indexOf(".xsd") > -1) {
                serviceNameFromFileName = fileName.substring(0, fileName.lastIndexOf(".xsd"));
            }
            for (Iterator iter = servicesList.iterator(); iter.hasNext(); ) {
                service = (Service) iter.next();
                if (!service.getQName().getLocalPart().equals(serviceNameFromFileName)) {
                    definition.removeService(service.getQName());
                    removedServices.add(service);
                }
            }

            //now we have only the required service so write it
            wsdlWriter.writeWSDL(definition, out);

            // again add the removed services
            for (Iterator iter = removedServices.iterator(); iter.hasNext(); ) {
                service = (Service) iter.next();
                definition.addService(service);
            }
        } else {
            // no problem proceed normaly
            wsdlWriter.writeWSDL(definition, out);
        }
        out.flush();
        out.close();
    }

    /**
     * adjust the schema locations in the original wsdl
     *
     * @param definition
     * @param changedSchemaLocations
     */
    private void processSchemas(Definition definition, Map<String, String> changedSchemaLocations) {
        Types wsdlTypes = definition.getTypes();
        if (wsdlTypes != null) {
            List extensibilityElements = wsdlTypes.getExtensibilityElements();
            for (Iterator iter = extensibilityElements.iterator(); iter.hasNext(); ) {
                Object currentObject = iter.next();
                if (currentObject instanceof Schema) {
                    Schema schema = (Schema) currentObject;
                    processSchema(definition, schema, null, changedSchemaLocations);
                }
            }
        }
    }


    private void processSchema(Definition definition, Schema schema, String fileName, Map<String, String> changedSchemaLocations) {
        try {
            if (schema.getIncludes() != null) {
                for (Object o : schema.getIncludes()) {
                    if (o instanceof SchemaReference) {
                        SchemaReference ref = (SchemaReference) o;
                        String fileNameChild = normalizeName(ref.getSchemaLocationURI());
                        Schema includedSchema = ref.getReferencedSchema();
                        if (includedSchema == null) {
                            continue;
                        }
                        changedSchemaLocations.put(ref.getSchemaLocationURI(), fileNameChild);
                        processSchema(definition, includedSchema, fileNameChild, changedSchemaLocations);
                    }
                }
            }
            if (schema.getImports() != null && schema.getImports().values() != null) {
                for (Object o : schema.getImports().values()) {
                    for (Object oi : (Vector) o) {
                        if (oi instanceof SchemaImport) {
                            SchemaImport imp = ((SchemaImport) oi);
                            Schema importedSchema = imp.getReferencedSchema();
                            if (importedSchema == null) {
                                continue;
                            }
                            String fileNameChild = normalizeName(imp.getSchemaLocationURI());
                            changedSchemaLocations.put(imp.getSchemaLocationURI(), fileNameChild);
                            processSchema(definition, importedSchema, fileNameChild, changedSchemaLocations);
                        }
                    }
                }
            }
            changeLocations(schema.getElement(), changedSchemaLocations);
            if (fileName != null) {
                java.io.FileWriter writer = new java.io.FileWriter(new File(baseFolder, fileName));
                DOM2Writer.serializeAsXML(schema.getElement(), definition.getNamespaces(), writer);
                writer.flush();
                writer.close();
            }
        } catch (Exception ex) {
            throw new SoapException("Unexpected error", ex);
        }

    }

    private void changeLocations(Element element, Map<String, String> changedSchemaLocations) {
        NodeList nodeList = element.getChildNodes();
        String tagName;
        for (int i = 0; i < nodeList.getLength(); i++) {
            tagName = nodeList.item(i).getLocalName();
            if (IMPORT_TAG.equals(tagName) || INCLUDE_TAG.equals(tagName)) {
                processImport(nodeList.item(i), changedSchemaLocations);
            }
        }
    }

    private void processImport(Node importNode, Map<String, String> changedSchemaLocations) {
        NamedNodeMap nodeMap = importNode.getAttributes();
        Node attribute;
        String attributeValue;
        for (int i = 0; i < nodeMap.getLength(); i++) {
            attribute = nodeMap.item(i);
            if (attribute.getNodeName().equals(SCHEMA_LOCATION)) {
                attributeValue = attribute.getNodeValue();
                attributeValue = changedSchemaLocations.get(attributeValue);
                if (attributeValue != null) {
                    attribute.setNodeValue(attributeValue);
                }
            }
        }
    }

    private String normalizeName(String name) {
        if (name != null) {
            return name.replaceAll("[^A-Za-z0-9.\\-_]", "_");
        }
        return null;
    }

}
