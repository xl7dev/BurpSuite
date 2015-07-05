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
import com.centeractive.ws.builder.SoapBuilder;
import com.centeractive.ws.builder.SoapOperation;
import com.centeractive.ws.builder.SoapOperationBuilder;
import com.centeractive.ws.builder.SoapOperationFinder;
import com.centeractive.ws.legacy.SoapLegacyFacade;

import javax.wsdl.Binding;
import javax.wsdl.BindingOperation;
import javax.wsdl.Port;
import javax.wsdl.Service;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Tom Bujok
 * @since 1.0.0
 */
class SoapBuilderImpl implements SoapBuilder {

    private final SoapLegacyFacade soapFacade;
    private final Binding binding;
    private final SoapContext context;
    private final List<String> serviceUrls;

    SoapBuilderImpl(SoapLegacyFacade soapFacade, Binding binding, SoapContext context) {
        this.soapFacade = soapFacade;
        this.binding = binding;
        this.context = context;
        this.serviceUrls = new ArrayList<String>();
        initializeServiceUrls();
    }

    @SuppressWarnings("unchecked")
    private void initializeServiceUrls() {
        for (Service service : soapFacade.getServices()) {
            for (Port port : (Collection<Port>) service.getPorts().values()) {
                String address = SoapLegacyFacade.getSoapEndpoint(port);
                if (address != null) {
                    serviceUrls.add(address);
                }
            }
        }
    }

    public BindingOperation getBindingOperation(SoapOperation op) {
        BindingOperation operation = binding.getBindingOperation(op.getOperationName(),
                op.getOperationInputName(), op.getOperationOutputName());
        if (operation == null) {
            throw new SoapBuilderException("Operation not found");
        }
        return operation;
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<SoapOperation> getOperations() {
        List<SoapOperation> operationNames = new ArrayList<SoapOperation>();
        for (BindingOperation operation : (List<BindingOperation>) binding.getBindingOperations()) {
            operationNames.add(SoapOperationImpl.create(this, binding, operation));
        }
        return operationNames;
    }

    @Override
    public SoapContext getContext() {
        return context;
    }

    @Override
    public SoapOperationBuilder getOperationBuilder(SoapOperation operation) {
        BindingOperation bindingOperation = getBindingOperation(operation);
        return SoapOperationImpl.create(this, binding, bindingOperation);
    }

    @Override
    public SoapOperationFinder operation() {
        return new SoapOperationFinderImpl(this, binding);
    }

    @Override
    public String buildInputMessage(SoapOperation operation) {
        return buildInputMessage(operation, context);
    }

    @Override
    public String buildInputMessage(SoapOperation operation, SoapContext context) {
        try {
            return soapFacade.buildSoapMessageFromInput(binding, getBindingOperation(operation), context);
        } catch (Exception e) {
            throw new SoapBuilderException(e);
        }
    }

    @Override
    public String buildOutputMessage(SoapOperation operation) {
        return buildOutputMessage(operation, context);
    }

    @Override
    public String buildOutputMessage(SoapOperation operation, SoapContext context) {
        try {
            return soapFacade.buildSoapMessageFromOutput(binding, getBindingOperation(operation), context);
        } catch (Exception e) {
            throw new SoapBuilderException(e);
        }
    }

    @Override
    public String buildFault(String code, String message) {
        return soapFacade.buildFault(code, message, binding, context);
    }

    @Override
    public String buildFault(String code, String message, SoapContext context) {
        return soapFacade.buildFault(code, message, binding, context);
    }

    @Override
    public String buildEmptyFault() {
        return soapFacade.buildEmptyFault(binding, context);
    }

    @Override
    public String buildEmptyFault(SoapContext context) {
        return soapFacade.buildEmptyFault(binding, context);
    }

    @Override
    public String buildEmptyMessage() {
        return soapFacade.buildEmptyMessage(binding, context);
    }

    @Override
    public String buildEmptyMessage(SoapContext context) {
        return soapFacade.buildEmptyMessage(binding, context);
    }

    @Override
    public QName getBindingName() {
        return binding.getQName();
    }

    @Override
    public Binding getBinding() {
        return binding;
    }

    @Override
    public List<String> getServiceUrls() {
        return new ArrayList<String>(serviceUrls);
    }

}
