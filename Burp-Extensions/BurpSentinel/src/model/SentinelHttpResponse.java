/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package model;

import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import gui.categorizer.CategorizerManager;
import gui.categorizer.ResponseCategory;
import java.awt.Color;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import util.BurpCallbacks;

/**
 *
 * @author unreal
 */
public class SentinelHttpResponse implements Serializable {
    transient private IResponseInfo responseInfo; // re-init upon deserializing in readObject()
    private byte[] response;
    
    private int size = 0;
    private int domCount = 0;
    
    private LinkedList<ResponseCategory> categories = new LinkedList<ResponseCategory>();
    private LinkedList<ResponseHighlight> responseHighlights = new LinkedList<ResponseHighlight>();

    SentinelHttpResponse() {
        // Deserializing Constructor
    }
    
    // Deserializing
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        // As I dont want to re-implement IResponseInfo, make it transient
        // and redo responseInfo upon deserializing
        if (response != null) {
            responseInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeResponse(response);
        }
    }
    
    
    SentinelHttpResponse(byte[] response) {
        this.response = response;
        parseResponse();
    }
    
    SentinelHttpResponse(IHttpRequestResponse httpMessage) {
        response = httpMessage.getResponse();
        parseResponse();
    }

    byte[] getByteResponse() {
        return response;
    }
    
    private void parseResponse() {
        if (response == null || response.length <= 0) {
            return;
        }
        
        // Burp Analyze Response
        responseInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeResponse(response);
        
        // Populate domcount
        domCount = 0;
        for(int n=0; n<response.length; n++) {
            if (response[n] == '<') {
                domCount++;
            }
        }
        
        // Get response length
        size = -1;
        for(String header: responseInfo.getHeaders()) {
            String a[] = header.split(": ");
            if (a[0].toLowerCase().equals("Content-Length".toLowerCase()) && a.length == 2) {
                this.size = Integer.parseInt(a[1]);
            }
        }
        // if no content-length is given (for example, HTTP1.0), use default
        // response size. 
        if (size == -1) {
            size = response.length;
        }
        
        // Categorize response
        categorizeResponse();
    }

    
    public void categorizeResponse() {
        categories.clear();
        categories.addAll(CategorizerManager.getInstance().categorize(new String(response)));
        for(ResponseCategory category: categories) {
            ResponseHighlight highlight = new ResponseHighlight(category.getIndicator(), Color.orange);
            addHighlight(highlight);
        }
    }
    
    public LinkedList<ResponseCategory> getCategories() {
        return categories;
    }
        
    public int getDom() {
        return domCount;
    }
    
    public boolean hasResponseParam(String value) {
        if (response == null) {
            return false;
        }

        String s = new String(response);
        if (s.contains(value)) {
            return true;
        } else {
            return false;
        }
    }

    public String getResponseStr() {
        String s;

        if (response != null) {
            s = new String(response);
        } else {
            s = "Sentinel: Response does not exist";
        }
        return s;
    }

    public boolean hasResponse() {
        if (response == null) {
            return false;
        } else {
            return true;
        }
    }

    public int getSize() {
        return size;
    }

    public String getHttpCode() {
        if (responseInfo != null) {
            return Integer.toString(responseInfo.getStatusCode());
        } else {
            return "";
        }
    }


    
    /**
     * ************************** Getters*************************************
     * 
     * Note: the following functions are slow, as it extracts on the fly
     * 
     */
    public String extractFirstLine() {
        String http = getResponseStr().substring(0, getResponseStr().indexOf("\r\n"));
        return http;
    }

    public List<String> extractHeaders() {
        return responseInfo.getHeaders();
    }

    public String extractBody() {
        byte[] body = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
        String s = BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(body);
        
        if (s == null) {
            s = "";
        }
        return s;
    }

    
    /**
     * ************************** Highlights**********************************
     */       

    public void addHighlight(ResponseHighlight h) {
        responseHighlights.add(h);
    }

    public Iterable<ResponseHighlight> getResponseHighlights() {
        return responseHighlights;
    }
}
