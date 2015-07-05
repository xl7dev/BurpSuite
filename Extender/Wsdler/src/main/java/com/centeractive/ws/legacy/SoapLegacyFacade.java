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
import com.centeractive.ws.SoapContext;

import javax.wsdl.*;
import javax.wsdl.extensions.soap.SOAPBinding;
import javax.wsdl.extensions.soap12.SOAP12Binding;
import javax.xml.namespace.QName;
import java.io.File;
import java.net.URL;
import java.util.Collection;
import java.util.List;

/**
 * @author Tom Bujok
 * @since 1.0.0
 */
public class SoapLegacyFacade {

    public static enum Soap {SOAP_1_1, SOAP_1_2}

    private SoapMessageBuilder messageBuilder;

    public SoapLegacyFacade(URL wsdlUrl) throws WSDLException {
        this.messageBuilder = new SoapMessageBuilder(wsdlUrl);
    }

    public String buildSoapMessageFromInput(Binding binding, BindingOperation bindingOperation, SoapContext context) {
        try {
            return messageBuilder.buildSoapMessageFromInput(binding, bindingOperation, context);
        } catch (Exception e) {
            throw new SoapBuilderException(e);
        }
    }

    public String buildSoapMessageFromOutput(Binding binding, BindingOperation bindingOperation, SoapContext context) {
        try {
            return messageBuilder.buildSoapMessageFromOutput(binding, bindingOperation, context);
        } catch (Exception e) {
            throw new SoapBuilderException(e);
        }
    }

    public String buildFault(String code, String message, Binding binding, SoapContext context) {
        return messageBuilder.buildFault(code, message, binding, context);
    }

    public String buildEmptyFault(Binding binding, SoapContext context) {
        return messageBuilder.buildEmptyFault(binding, context);
    }

    public String buildEmptyMessage(Binding binding, SoapContext context) {
        return messageBuilder.buildEmptyMessage(binding, context);
    }

    public URL saveWsdl(String rootFileName, File folder) {
        return messageBuilder.saveWsdl(rootFileName, folder);
    }

    public static URL saveWsdl(String rootFileName, URL wsdlUrl, File folder) {
        try {
            return SoapMessageBuilder.saveWsdl(rootFileName, wsdlUrl, folder);
        } catch (WSDLException e) {
            throw new SoapBuilderException(e);
        }
    }

    public Binding getBindingByName(QName bindingName) {
        return messageBuilder.getBindingByName(bindingName);
    }

    public List<QName> getBindingNames() {
        return messageBuilder.getBindingNames();
    }

    public static String buildEmptyMessage(SoapVersion soapVersion, SoapContext context) {
        return SoapMessageBuilder.buildEmptyMessage(soapVersion, context);
    }

    public static String buildEmptyFault(SoapVersion soapVersion, SoapContext context) {
        return SoapMessageBuilder.buildEmptyFault(soapVersion, context);
    }

    public static String buildFault(String code, String message, SoapVersion soapVersion, SoapContext context) {
        return SoapMessageBuilder.buildFault(code, message, soapVersion, context);
    }

    private static SoapVersion transformSoapVersion(Soap soapVersion) {
        if (soapVersion.equals(Soap.SOAP_1_1)) {
            return SoapVersion.Soap11;
        } else {
            return SoapVersion.Soap12;
        }
    }

    public static String buildEmptyMessage(Soap version, SoapContext context) {
        return SoapLegacyFacade.buildEmptyMessage(transformSoapVersion(version), context);
    }

    public static String buildEmptyFault(Soap version, SoapContext context) {
        return SoapLegacyFacade.buildEmptyFault(transformSoapVersion(version), context);
    }

    public static String buildFault(Soap version, String code, String message, SoapContext context) {
        return SoapLegacyFacade.buildFault(code, message, transformSoapVersion(version), context);
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

    public static String getSoapEndpoint(Port port) {
        return WsdlUtils.getSoapEndpoint(port);
    }

    @SuppressWarnings("unchecked")
    public Collection<Service> getServices() {
        return (Collection<Service>) messageBuilder.getDefinition().getServices().values();
    }

}
