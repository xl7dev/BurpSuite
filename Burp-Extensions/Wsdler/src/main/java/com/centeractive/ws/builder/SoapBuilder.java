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
package com.centeractive.ws.builder;

import com.centeractive.ws.SoapContext;

import javax.wsdl.Binding;
import javax.xml.namespace.QName;
import java.util.List;

/**
 * @author Tom Bujok
 * @since 1.0.0
 */
public interface SoapBuilder {

    List<SoapOperation> getOperations();

    SoapOperationFinder operation();

    SoapContext getContext();

    SoapOperationBuilder getOperationBuilder(SoapOperation operation);

    String buildInputMessage(SoapOperation operation);

    String buildInputMessage(SoapOperation operation, SoapContext context);

    String buildOutputMessage(SoapOperation operation);

    String buildOutputMessage(SoapOperation operation, SoapContext context);

    String buildFault(String code, String message);

    String buildFault(String code, String message, SoapContext context);

    String buildEmptyFault();

    String buildEmptyFault(SoapContext context);

    String buildEmptyMessage();

    String buildEmptyMessage(SoapContext context);

    QName getBindingName();

    Binding getBinding();

    List<String> getServiceUrls();

}
