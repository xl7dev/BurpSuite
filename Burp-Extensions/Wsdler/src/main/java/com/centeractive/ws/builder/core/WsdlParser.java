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
package com.centeractive.ws.builder.core;

import com.centeractive.ws.SoapBuilderException;
import com.centeractive.ws.SoapContext;
import com.centeractive.ws.builder.*;
import com.centeractive.ws.legacy.SoapLegacyFacade;
import com.google.common.base.Preconditions;
import org.apache.commons.lang3.StringUtils;

import javax.wsdl.Binding;
import javax.wsdl.WSDLException;
import javax.xml.namespace.QName;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Tom Bujok
 * @since 1.0.0
 */
public final class WsdlParser {

    private final URL wsdlUrl;
    private final SoapLegacyFacade soapFacade;

    private WsdlParser(URL wsdlUrl) {
        try {
            this.wsdlUrl = wsdlUrl;
            this.soapFacade = new SoapLegacyFacade(wsdlUrl);
        } catch (WSDLException e) {
            throw new SoapBuilderException(e);
        }
    }

    public static WsdlParser parse(URL wsdlUrl) {
        Preconditions.checkNotNull(wsdlUrl, "URL of the WSDL cannot be null");
        return new WsdlParser(wsdlUrl);
    }

    public static WsdlParser parse(String wsdlUrl) {
        Preconditions.checkNotNull(wsdlUrl, "URL of the WSDL cannot be null");
        try {
            return new WsdlParser(new URL(wsdlUrl));
        } catch (MalformedURLException e) {
            throw new SoapBuilderException(e);
        }
    }

    public List<QName> getBindings() {
        return soapFacade.getBindingNames();
    }

    public void printBindings() {
        System.out.println(wsdlUrl);
        for (QName bindingName : soapFacade.getBindingNames()) {
            System.out.println("\t" + bindingName.toString());
        }
    }

    public SoapBuilderFinderResult binding(final String bindingName) {
        Preconditions.checkNotNull(bindingName);
        return new SoapBuilderFinderResult() {
            @Override
            public SoapBuilder builder() {
                return getBuilder(QName.valueOf(bindingName), SoapContext.DEFAULT);
            }

            @Override
            public SoapBuilder builder(final SoapContext context) {
                return getBuilder(QName.valueOf(bindingName), context);
            }

            @Override
            public SoapOperationFinder operation() {
                return builder().operation();
            }
        };
    }

    public SoapBuilderFinderResult binding(final QName bindingName) {
        Preconditions.checkNotNull(bindingName);
        return new SoapBuilderFinderResult() {
            @Override
            public SoapBuilder builder() {
                return getBuilder(bindingName, SoapContext.DEFAULT);
            }

            @Override
            public SoapBuilder builder(final SoapContext context) {
                return getBuilder(bindingName, context);
            }

            @Override
            public SoapOperationFinder operation() {
                return builder().operation();
            }
        };
    }

    public SoapBuilderFinder binding() {
        return new SoapBuilderFinder() {
            private String namespaceURI;
            private String localPart;
            private String prefix;

            @Override
            public SoapBuilderFinder namespaceURI(String namespaceURI) {
                this.namespaceURI = namespaceURI;
                return this;
            }

            @Override
            public SoapBuilderFinder localPart(String localPart) {
                this.localPart = localPart;
                return this;
            }

            @Override
            public SoapBuilderFinder prefix(String prefix) {
                this.prefix = prefix;
                return this;
            }

            @Override
            public SoapBuilder builder() {
                validate();
                return getBuilder(getBindingName(), SoapContext.DEFAULT);
            }

            @Override
            public SoapBuilder builder(SoapContext context) {
                validate();
                return getBuilder(getBindingName(), context);
            }

            @Override
            public SoapOperationFinder operation() {
                return builder().operation();
            }

            private QName getBindingName() {
                List<QName> result = new ArrayList<QName>();
                for(QName bindingName : soapFacade.getBindingNames()) {
                    if(bindingName.getLocalPart().equals(localPart)) {
                        if(namespaceURI != null) {
                            if(!bindingName.getNamespaceURI().equals(namespaceURI)) {
                                continue;
                            }
                        }
                        if(prefix != null) {
                            if(!bindingName.getPrefix().equals(prefix)) {
                                continue;
                            }
                        }
                        result.add(bindingName);
                    }
                }
                if(result.isEmpty()) {
                    throw new SoapBuilderException("Binding not found");
                }
                if(result.size() > 1) {
                    throw new SoapBuilderException("Found more than one binding " + result);
                }
                return result.iterator().next();
            }

            private void validate() {
                if (StringUtils.isBlank(localPart)) {
                    throw new SoapBuilderException("Specify at least localPart of the binding's QName");
                }
            }
        };
    }

    public SoapBuilder getBuilder(String bindingName) {
        return getBuilder(QName.valueOf(bindingName));
    }

    public SoapBuilder getBuilder(QName bindingName) {
        return getBuilder(bindingName, SoapContext.builder().build());
    }

    public SoapBuilder getBuilder(String bindingName, SoapContext context) {
        return getBuilder(QName.valueOf(bindingName), context);
    }

    public SoapBuilder getBuilder(QName bindingName, SoapContext context) {
        Preconditions.checkNotNull(context, "SoapContext cannot be null");
        Binding binding = soapFacade.getBindingByName(bindingName);
        return new SoapBuilderImpl(soapFacade, binding, context);
    }

    public URL saveWsdl(String rootFileName, File folder) {
        return soapFacade.saveWsdl(rootFileName, folder);
    }

    public static URL saveWsdl(URL wsdlUrl, String rootFileName, File folder) {
        return SoapLegacyFacade.saveWsdl(rootFileName, wsdlUrl, folder);
    }

}
