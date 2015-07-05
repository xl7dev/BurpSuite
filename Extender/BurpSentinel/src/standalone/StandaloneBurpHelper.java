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
package standalone;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScannerInsertionPoint;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import model.SentinelHttpService;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class StandaloneBurpHelper implements IExtensionHelpers {

    @Override
    public IRequestInfo analyzeRequest(IHttpRequestResponse request) {
        return new StandaloneBurpRequestInfo(request);
    }

    @Override
    public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) {
        return new StandaloneBurpRequestInfo(httpService, request);
    }

    @Override
    public IRequestInfo analyzeRequest(byte[] request) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IResponseInfo analyzeResponse(byte[] response) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IParameter getRequestParameter(byte[] request, String parameterName) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String urlDecode(String data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String urlEncode(String data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] urlDecode(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] urlEncode(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] base64Decode(String data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] base64Decode(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String base64Encode(String data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String base64Encode(byte[] data) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] stringToBytes(String data) {
        return data.getBytes();
    }

    @Override
    public String bytesToString(byte[] data) {
        String s = "";
        try {
            s = new String(data, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(StandaloneBurpHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return s;
    }

    @Override
    public int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] buildHttpMessage(List<String> headers, byte[] body) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] buildHttpRequest(URL url) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] addParameter(byte[] request, IParameter parameter) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] removeParameter(byte[] request, IParameter parameter) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] updateParameter(byte[] request, IParameter parameter) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] toggleRequestMethod(byte[] request) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IHttpService buildHttpService(String host, int port, String protocol) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IHttpService buildHttpService(String host, int port, boolean useHttps) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IParameter buildParameter(String name, String value, byte type) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public IScannerInsertionPoint makeScannerInsertionPoint(String insertionPointName, byte[] baseRequest, int from, int to) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
