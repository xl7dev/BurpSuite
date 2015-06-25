/*
 Copyright (C) 2013  Cyberis Ltd. Author geoff.jones@cyberis.co.uk

 This file is part of POST2JSON, a Burp Suite extender to convert a POST 
 request to a JSON message.

 POST2JSON is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 POST2JSON is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package burp;

import java.util.ArrayList;
import java.util.List;

/**
 * @author geoff.jones@cyberis.co.uk
 * @Copyright Cyberis Limited 2013
 *
 * Class to represent a JSON message. Takes a HTTP POST Request and converts to
 * a JSON message. Moves any .NET __RequestVerificationToken to the request
 * headers if found
 */
class JsonMessage {

    private final List<IParameter> myParameters;
    private final List<IParameter> myJsonParameters;
    private final List<String> myHeaders;
    private final IRequestInfo myRequest;
    private final byte[] body;

    public JsonMessage(IHttpRequestResponse message) {
        myRequest = BurpExtender.helpers.analyzeRequest(message.getRequest());
        myHeaders = new ArrayList<>();
        //myParamerts will hold all parameters EXCEPT JSON (body) parameters
        myParameters = new ArrayList<>();
        myJsonParameters = new ArrayList<>();

        //Change the content type, retain all other headers
        List<String> headers = myRequest.getHeaders();
        for (String i : headers) {
            if (i.startsWith("Content-Type:")) {
                myHeaders.add("Content-Type: application/json");
            } else {
                myHeaders.add(i);
            }
        }

        //Add the XMLHttpRequest header
        myHeaders.add("X-Requested-With: XMLHttpRequest");

        //Construct parameters, adding the verification token to the headers if found
        List<IParameter> parameters = myRequest.getParameters();
        for (IParameter i : parameters) {
            if (i.getType() == IParameter.PARAM_BODY) {
                if (i.getName().equals("__RequestVerificationToken")) {
                    String value = BurpExtender.helpers.urlDecode(i.getValue());
                    myHeaders.add("__RequestVerificationToken: " + value);
                } else {
                    myJsonParameters.add(i);
                }
            } else {
                myParameters.add(i);
            }
        }

        //Build the JSON body from the parameters
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        String delim = "";
        for (IParameter i : myJsonParameters) {
            String name = i.getName().replace("\"", "\\\"");
            String value = "";

            //Check we have a value for the parameter
            if (!i.getValue().isEmpty()) {
                value = BurpExtender.helpers.urlDecode(i.getValue()
                        .replace("\"", "\\\""));
            }

            sb.append(delim).append("\"").append(name)
                    .append("\":").append("\"").append(value).append("\"");
            delim = ",";
        }
        sb.append("}");

        //Convert the constructed body to a byte[]
        body = sb.toString().getBytes();
    }

    /**
     * Get the HTTP generated request
     *
     * @return byte[]
     */
    public byte[] getMessage() {
        return BurpExtender.helpers.buildHttpMessage(myHeaders, body);
    }
}
