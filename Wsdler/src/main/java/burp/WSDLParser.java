package burp;

import com.centeractive.ws.SoapContext;
import com.centeractive.ws.builder.SoapBuilder;
import com.centeractive.ws.builder.SoapOperation;
import com.centeractive.ws.builder.core.SoapUtils;
import com.centeractive.ws.builder.core.WsdlParser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import javax.wsdl.BindingOperation;
import javax.xml.namespace.QName;

public class WSDLParser {

  private IExtensionHelpers helpers;
  private IBurpExtenderCallbacks callbacks;
  private WSDLParserTab tab;

  public WSDLParser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, WSDLParserTab tab) {
    this.helpers = helpers;
    this.callbacks = callbacks;
    this.tab = tab;

  }

  public void parseWSDL(IHttpRequestResponse requestResponse) {
    File temp;
    temp = createTempFile(requestResponse);
    if (temp == null) {
      return;
    }
    WSDLTab wsdltab = tab.createTab();
    WsdlParser parser = WsdlParser.parse(temp.toURI().toString());
    try {
      temp.delete();
    } catch (Exception e) {
      System.out.println("Temp file could not be deleted");
    }
    List<QName> bindings = parser.getBindings();
    SoapBuilder builder;
    List<SoapOperation> operations;
    SoapOperation operation;
    String bindingName;
    String operationName;
    byte[] xmlRequest;
    List<String> endpoints;
    for (QName i : bindings) {
      bindingName = i.getLocalPart();
      builder = parser.binding().localPart(bindingName).builder();
      operations = builder.getOperations();
      for (SoapOperation j : operations) {
        operationName = j.getOperationName();
        operation = builder.operation().name(operationName).find();
        xmlRequest = createRequest(requestResponse, builder, operation);
        endpoints = builder.getServiceUrls();
        wsdltab.addEntry(new WSDLEntry(bindingName, xmlRequest, operationName, endpoints, requestResponse));
      }
    }
  }

  private File createTempFile(IHttpRequestResponse requestResponse) {
    File temp = null;
    IHttpRequestResponse response = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
    while (response.getResponse().length < 200) {
      response = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
    }
    int offset = helpers.analyzeResponse(response.getResponse()).getBodyOffset();
    String body = new String(response.getResponse(), offset, response.getResponse().length - offset);
    if (!body.contains("definitions")) {
      System.out.println("WSDL definition not found");
      return temp;
    }

    try {
      temp = File.createTempFile("temp", ".wsdl");
      BufferedWriter bw = new BufferedWriter(new FileWriter(temp));

      bw.write(body);
      bw.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
    return temp;
  }

  private byte[] createRequest(IHttpRequestResponse requestResponse, SoapBuilder builder, SoapOperation operation) {
    SoapContext context = SoapContext.builder()
        .alwaysBuildHeaders(true).exampleContent(true).typeComments(true).buildOptional(true).build();

    String message = builder.buildInputMessage(operation, context);
    String endpointURL = getEndPoint(builder.getServiceUrls().get(0), requestResponse);
    BindingOperation
        soapActionOperation =
        builder.getBinding().getBindingOperation(builder.getOperationBuilder(operation).getOperationName(), builder.getOperationBuilder(operation).getOperationInputName(),
                                                 builder.getOperationBuilder(operation).getOperationOutputName());

    List<String> headers = new ArrayList<String>();

    headers.add("POST " + endpointURL + " HTTP/1.1");
    headers.add("Accept-Encoding: gzip,deflate");
    headers.add("Content-Type: text/xml;charset=UTF-8");
    headers.add("SOAPAction: " + SoapUtils.getSOAPActionUri(soapActionOperation));
    headers.add("Host: " + requestResponse.getHttpService().getHost());

    return helpers.buildHttpMessage(headers, message.getBytes());
  }

  private String getEndPoint(String endpoint, IHttpRequestResponse requestResponse) {

    int index = endpoint.indexOf("//") + 2;
    String j = endpoint.substring(index, endpoint.length());

    j = j.replace(requestResponse.getHttpService().getHost(), "");

    return j;
  }
}
