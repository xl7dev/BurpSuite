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

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class StandaloneBurpRequestInfo implements IRequestInfo {

    private String request;
    private IHttpService httpService;
    
    StandaloneBurpRequestInfo(IHttpRequestResponse request) {
        this.request = new String(request.getRequest());
        this.httpService = request.getHttpService();
        init();
    }

    StandaloneBurpRequestInfo(IHttpService httpService, byte[] request) {
        this.request = new String(request);
        this.httpService = httpService;
        init();
    }
    
    private String method;
    private URL url;
    private List<String> headers;
    private List<IParameter> parameters;
    private int bodyoffset;
    
    private void init() {
        bodyoffset = request.indexOf("\r\n\r\n");
        
        String[] lines = request.split("\r\n");
        String[] head = lines[0].split(" ");
        
        method = head[0];
        
        String urls = httpService.getProtocol() + "://" + httpService.getHost() + head[1];
        try {
            url = new URL(urls);
        } catch (MalformedURLException ex) {
            Logger.getLogger(StandaloneBurpRequestInfo.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        headers = new LinkedList<String>();
        for(int n=1; n<lines.length; n++) {
            if (lines[n].length() == 0) {
                break;
            }
            
            headers.add(lines[n]);
        }
        
        parameters = new LinkedList<IParameter>();
    }

    @Override
    public String getMethod() {
        return method;
    }

    @Override
    public URL getUrl() {
          return url;
    }

    @Override
    public List<String> getHeaders() {
        return headers;
    }

    @Override
    public List<IParameter> getParameters() {
        return parameters;
    }

    @Override
    public int getBodyOffset() {
        return bodyoffset;
    }
    
}
