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
import org.apache.log4j.Logger;

import javax.wsdl.*;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.mime.MIMEContent;
import javax.wsdl.extensions.mime.MIMEMultipartRelated;
import javax.wsdl.extensions.mime.MIMEPart;
import javax.wsdl.extensions.soap.*;
import javax.wsdl.extensions.soap12.*;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
 * Wsdl-related tools
 *
 * @author Ole.Matzura
 */
@SuppressWarnings("unchecked")
class WsdlUtils {
    private final static Logger log = Logger.getLogger(WsdlUtils.class);

    public static <T extends ExtensibilityElement> T getExtensiblityElement(List<?> list, Class<T> clazz) {
        List<T> elements = getExtensiblityElements(list, clazz);
        return elements.isEmpty() ? null : elements.get(0);
    }

    public static <T extends ExtensibilityElement> List<T> getExtensiblityElements(List list, Class<T> clazz) {
        List<T> result = new ArrayList<T>();

        for (Iterator<T> i = list.iterator(); i.hasNext(); ) {
            T elm = i.next();
            if (clazz.isAssignableFrom(elm.getClass())) {
                result.add(elm);
            }
        }

        return result;
    }


    public static Binding findBindingForOperation(Definition definition, BindingOperation bindingOperation) {
        Map services = definition.getAllServices();
        Iterator<Service> s = services.values().iterator();

        while (s.hasNext()) {
            Map ports = s.next().getPorts();
            Iterator<Port> p = ports.values().iterator();
            while (p.hasNext()) {
                Binding binding = p.next().getBinding();
                List bindingOperations = binding.getBindingOperations();
                for (Iterator iter = bindingOperations.iterator(); iter.hasNext(); ) {
                    BindingOperation op = (BindingOperation) iter.next();
                    if (op.getName().equals(bindingOperation.getName()))
                        return binding;
                }
            }
        }

        Map bindings = definition.getAllBindings();
        Iterator<QName> names = bindings.keySet().iterator();
        while (names.hasNext()) {
            Binding binding = definition.getBinding(names.next());
            List bindingOperations = binding.getBindingOperations();
            for (Iterator iter = bindingOperations.iterator(); iter.hasNext(); ) {
                BindingOperation op = (BindingOperation) iter.next();
                if (op.getName().equals(bindingOperation.getName()))
                    return binding;
            }
        }

        return null;
    }

    public static boolean isInputSoapEncoded(BindingOperation bindingOperation) {
        if (bindingOperation == null)
            return false;

        BindingInput bindingInput = bindingOperation.getBindingInput();
        if (bindingInput == null)
            return false;

        SOAPBody soapBody = WsdlUtils.getExtensiblityElement(bindingInput.getExtensibilityElements(), SOAPBody.class);

        if (soapBody != null) {
            return soapBody.getUse() != null
                    && soapBody.getUse().equalsIgnoreCase("encoded")
                    && (soapBody.getEncodingStyles() == null || soapBody.getEncodingStyles().contains(
                    "http://schemas.xmlsoap.org/soap/encoding/"));
        }

        SOAP12Body soap12Body = WsdlUtils.getExtensiblityElement(bindingInput.getExtensibilityElements(),
                SOAP12Body.class);

        if (soap12Body != null) {
            return soap12Body.getUse() != null
                    && soap12Body.getUse().equalsIgnoreCase("encoded")
                    && (soap12Body.getEncodingStyle() == null || soap12Body.getEncodingStyle().equals(
                    "http://schemas.xmlsoap.org/soap/encoding/"));
        }

        return false;
    }

    public static boolean isOutputSoapEncoded(BindingOperation bindingOperation) {
        if (bindingOperation == null)
            return false;

        BindingOutput bindingOutput = bindingOperation.getBindingOutput();
        if (bindingOutput == null)
            return false;

        SOAPBody soapBody = WsdlUtils.getExtensiblityElement(bindingOutput.getExtensibilityElements(), SOAPBody.class);

        if (soapBody != null) {
            return soapBody.getUse() != null
                    && soapBody.getUse().equalsIgnoreCase("encoded")
                    && (soapBody.getEncodingStyles() == null || soapBody.getEncodingStyles().contains(
                    "http://schemas.xmlsoap.org/soap/encoding/"));
        }

        SOAP12Body soap12Body = WsdlUtils.getExtensiblityElement(bindingOutput.getExtensibilityElements(),
                SOAP12Body.class);

        if (soap12Body != null) {
            return soap12Body.getUse() != null
                    && soap12Body.getUse().equalsIgnoreCase("encoded")
                    && (soap12Body.getEncodingStyle() == null || soap12Body.getEncodingStyle().equals(
                    "http://schemas.xmlsoap.org/soap/encoding/"));
        }

        return false;
    }

    public static boolean isRpc(Definition definition, BindingOperation bindingOperation) {
        SOAPOperation soapOperation = WsdlUtils.getExtensiblityElement(bindingOperation.getExtensibilityElements(),
                SOAPOperation.class);

        if (soapOperation != null && soapOperation.getStyle() != null)
            return soapOperation.getStyle().equalsIgnoreCase("rpc");

        SOAP12Operation soap12Operation = WsdlUtils.getExtensiblityElement(bindingOperation.getExtensibilityElements(),
                SOAP12Operation.class);

        if (soap12Operation != null && soap12Operation.getStyle() != null)
            return soap12Operation.getStyle().equalsIgnoreCase("rpc");

        Binding binding = findBindingForOperation(definition, bindingOperation);
        if (binding == null) {
            log.error("Failed to find binding for operation [" + bindingOperation.getName() + "] in definition ["
                    + definition.getDocumentBaseURI() + "]");
            return false;
        }

        return isRpc(binding);
    }

    public static boolean isRpc(Binding binding) {
        SOAPBinding soapBinding = WsdlUtils
                .getExtensiblityElement(binding.getExtensibilityElements(), SOAPBinding.class);

        if (soapBinding != null)
            return "rpc".equalsIgnoreCase(soapBinding.getStyle());

        SOAP12Binding soap12Binding = WsdlUtils.getExtensiblityElement(binding.getExtensibilityElements(),
                SOAP12Binding.class);

        if (soap12Binding != null)
            return "rpc".equalsIgnoreCase(soap12Binding.getStyle());

        return false;
    }

    /**
     * Returns a list of parts for the specifed operation, either as specified in
     * body or all
     */

    public static Part[] getInputParts(BindingOperation operation) {
        List<Part> result = new ArrayList<Part>();
        Input input = operation.getOperation().getInput();
        if (input == null || operation.getBindingInput() == null)
            return new Part[0];

        Message msg = input.getMessage();

        if (msg != null) {
            SOAPBody soapBody = WsdlUtils.getExtensiblityElement(operation.getBindingInput().getExtensibilityElements(),
                    SOAPBody.class);

            if (soapBody == null || soapBody.getParts() == null) {
                SOAP12Body soap12Body = WsdlUtils.getExtensiblityElement(operation.getBindingInput()
                        .getExtensibilityElements(), SOAP12Body.class);

                if (soap12Body == null || soap12Body.getParts() == null) {
                    if (msg != null)
                        result.addAll(msg.getOrderedParts(null));
                } else {
                    Iterator i = soap12Body.getParts().iterator();
                    while (i.hasNext()) {
                        String partName = (String) i.next();
                        Part part = msg.getPart(partName);

                        result.add(part);
                    }
                }
            } else {
                Iterator i = soapBody.getParts().iterator();
                while (i.hasNext()) {
                    String partName = (String) i.next();
                    Part part = msg.getPart(partName);

                    result.add(part);
                }
            }
        } else {
        }

        return result.toArray(new Part[result.size()]);
    }

    public static boolean isAttachmentInputPart(Part part, BindingOperation operation) {
        return getInputMultipartContent(part, operation).length > 0;
    }

    public static boolean isAttachmentOutputPart(Part part, BindingOperation operation) {
        return getOutputMultipartContent(part, operation).length > 0;
    }

    public static MIMEContent[] getOutputMultipartContent(Part part, BindingOperation operation) {
        BindingOutput output = operation.getBindingOutput();
        if (output == null)
            return new MIMEContent[0];

        MIMEMultipartRelated multipartOutput = WsdlUtils.getExtensiblityElement(output.getExtensibilityElements(),
                MIMEMultipartRelated.class);

        return getContentParts(part, multipartOutput);
    }

    public static MIMEContent[] getInputMultipartContent(Part part, BindingOperation operation) {
        BindingInput bindingInput = operation.getBindingInput();
        if (bindingInput == null)
            return new MIMEContent[0];

        MIMEMultipartRelated multipartInput = WsdlUtils.getExtensiblityElement(bindingInput.getExtensibilityElements(),
                MIMEMultipartRelated.class);

        return getContentParts(part, multipartInput);
    }

    public static MIMEContent[] getContentParts(Part part, MIMEMultipartRelated multipart) {
        List<MIMEContent> result = new ArrayList<MIMEContent>();

        if (multipart != null) {
            List<MIMEPart> parts = multipart.getMIMEParts();

            for (int c = 0; c < parts.size(); c++) {
                List<MIMEContent> contentParts = WsdlUtils.getExtensiblityElements(parts.get(c)
                        .getExtensibilityElements(), MIMEContent.class);

                for (MIMEContent content : contentParts) {
                    if (content.getPart().equals(part.getName()))
                        result.add(content);
                }
            }
        }

        return result.toArray(new MIMEContent[result.size()]);
    }

    public static Part[] getFaultParts(BindingOperation bindingOperation, String faultName) throws Exception {
        List<Part> result = new ArrayList<Part>();

        BindingFault bindingFault = bindingOperation.getBindingFault(faultName);
        SOAPFault soapFault = WsdlUtils.getExtensiblityElement(bindingFault.getExtensibilityElements(), SOAPFault.class);

        Operation operation = bindingOperation.getOperation();
        if (soapFault != null && soapFault.getName() != null) {
            Fault fault = operation.getFault(soapFault.getName());
            if (fault == null)
                throw new Exception("Missing Fault [" + soapFault.getName() + "] in operation [" + operation.getName()
                        + "]");
            result.addAll(fault.getMessage().getOrderedParts(null));
        } else {
            SOAP12Fault soap12Fault = WsdlUtils.getExtensiblityElement(bindingFault.getExtensibilityElements(),
                    SOAP12Fault.class);

            if (soap12Fault != null && soap12Fault.getName() != null) {
                Fault fault = operation.getFault(soap12Fault.getName());
                if (fault != null && fault.getMessage() != null)
                    result.addAll(fault.getMessage().getOrderedParts(null));
            } else {
                Fault fault = operation.getFault(faultName);
                if (fault != null && fault.getMessage() != null)
                    result.addAll(fault.getMessage().getOrderedParts(null));
            }
        }

        return result.toArray(new Part[result.size()]);
    }

    public static Part[] getOutputParts(BindingOperation operation) {
        BindingOutput bindingOutput = operation.getBindingOutput();
        if (bindingOutput == null)
            return new Part[0];

        List<Part> result = new ArrayList<Part>();
        Output output = operation.getOperation().getOutput();
        if (output == null)
            return new Part[0];

        Message msg = output.getMessage();
        if (msg != null) {
            SOAPBody soapBody = WsdlUtils
                    .getExtensiblityElement(bindingOutput.getExtensibilityElements(), SOAPBody.class);

            if (soapBody == null || soapBody.getParts() == null) {
                SOAP12Body soap12Body = WsdlUtils.getExtensiblityElement(bindingOutput.getExtensibilityElements(),
                        SOAP12Body.class);

                if (soap12Body == null || soap12Body.getParts() == null) {
                    result.addAll(msg.getOrderedParts(null));
                } else {
                    Iterator i = soap12Body.getParts().iterator();
                    while (i.hasNext()) {
                        String partName = (String) i.next();
                        Part part = msg.getPart(partName);

                        result.add(part);
                    }
                }
            } else {
                Iterator i = soapBody.getParts().iterator();
                while (i.hasNext()) {
                    String partName = (String) i.next();
                    Part part = msg.getPart(partName);

                    result.add(part);
                }
            }
        } else {
            log.warn("Missing output message for binding operation [" + operation.getName() + "]");
        }

        return result.toArray(new Part[result.size()]);
    }

    public static String getSoapEndpoint(Port port) {
        SOAPAddress soapAddress = WsdlUtils.getExtensiblityElement(port.getExtensibilityElements(), SOAPAddress.class);
        if (soapAddress != null && StringUtils.isNotBlank(soapAddress.getLocationURI())) {
            try {
                return URLDecoder.decode(soapAddress.getLocationURI(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                return soapAddress.getLocationURI();
            }
        }

        SOAP12Address soap12Address = WsdlUtils.getExtensiblityElement(port.getExtensibilityElements(),
                SOAP12Address.class);
        if (soap12Address != null && StringUtils.isNotBlank(soap12Address.getLocationURI())) {
            try {
                return URLDecoder.decode(soap12Address.getLocationURI(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                return soap12Address.getLocationURI();
            }
        }

        return null;
    }

    public static boolean replaceSoapEndpoint(Port port, String endpoint) {
        SOAPAddress soapAddress = WsdlUtils.getExtensiblityElement(port.getExtensibilityElements(), SOAPAddress.class);
        if (soapAddress != null) {
            soapAddress.setLocationURI(endpoint);
            return true;
        }

        SOAP12Address soap12Address = WsdlUtils.getExtensiblityElement(port.getExtensibilityElements(),
                SOAP12Address.class);
        if (soap12Address != null) {
            soap12Address.setLocationURI(endpoint);
            return true;
        }

        return false;
    }

    public static String getSoapBodyNamespace(List<?> list) {
        SOAPBody soapBody = WsdlUtils.getExtensiblityElement(list, SOAPBody.class);
        if (soapBody != null)
            return soapBody.getNamespaceURI();

        SOAP12Body soap12Body = WsdlUtils.getExtensiblityElement(list, SOAP12Body.class);
        if (soap12Body != null)
            return soap12Body.getNamespaceURI();

        return null;
    }

    /**
     * A SOAP-Header wrapper
     *
     * @author ole.matzura
     */

    public interface SoapHeader {
        public QName getMessage();

        public String getPart();
    }

    /**
     * SOAP 1.1 Header implementation
     *
     * @author ole.matzura
     */

    public static class Soap11Header implements SoapHeader {
        private final SOAPHeader soapHeader;

        public Soap11Header(SOAPHeader soapHeader) {
            this.soapHeader = soapHeader;
        }

        public QName getMessage() {
            return soapHeader.getMessage();
        }

        public String getPart() {
            return soapHeader.getPart();
        }
    }

    /**
     * SOAP 1.2 Header implementation
     *
     * @author ole.matzura
     */

    public static class Soap12Header implements SoapHeader {
        private final SOAP12Header soapHeader;

        public Soap12Header(SOAP12Header soapHeader) {
            this.soapHeader = soapHeader;
        }

        public QName getMessage() {
            return soapHeader.getMessage();
        }

        public String getPart() {
            return soapHeader.getPart();
        }
    }

    public static List<SoapHeader> getSoapHeaders(List list) {
        List<SoapHeader> result = new ArrayList<SoapHeader>();

        List<SOAPHeader> soapHeaders = WsdlUtils.getExtensiblityElements(list, SOAPHeader.class);
        if (soapHeaders != null && !soapHeaders.isEmpty()) {
            for (SOAPHeader header : soapHeaders)
                result.add(new Soap11Header(header));
        } else {
            List<SOAP12Header> soap12Headers = WsdlUtils.getExtensiblityElements(list, SOAP12Header.class);
            if (soap12Headers != null && !soap12Headers.isEmpty()) {
                for (SOAP12Header header : soap12Headers)
                    result.add(new Soap12Header(header));
            }
        }

        return result;
    }


    public static BindingOperation findBindingOperation(Binding binding, String bindingOperationName, String inputName,
                                                        String outputName) {
        if (binding == null)
            return null;

        if (inputName == null)
            inputName = ":none";

        if (outputName == null)
            outputName = ":none";

        BindingOperation result = binding.getBindingOperation(bindingOperationName, inputName, outputName);

        if (result == null && (inputName.equals(":none") || outputName.equals(":none"))) {
            // fall back to this behaviour for WSDL4j 1.5.0 compatibility
            result = binding.getBindingOperation(bindingOperationName, inputName.equals(":none") ? null : inputName,
                    outputName.equals(":none") ? null : outputName);
        }
        return result;
    }


    public static String getTargetNamespace(Definition definition) {
        return definition.getTargetNamespace() == null ? XMLConstants.NULL_NS_URI : definition.getTargetNamespace();
    }


}
