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

import burp.IHttpService;
import java.io.Serializable;

/**
 *
 * @author unreal
 */
public class SentinelHttpService implements IHttpService, Serializable {

    private String host;
    private int port;
    private String protocol;
    
    public SentinelHttpService(String host, int port, String protocol) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }
    
    public SentinelHttpService(String host, int port, boolean https) {
        this.host = host;
        this.port = port;
        
        if (https) {
            protocol = "https";
        } else {
            protocol = "http";
        }
    }
    

    SentinelHttpService(IHttpService httpService) {
        this.host = httpService.getHost();
        this.port = httpService.getPort();
        this.protocol = httpService.getProtocol();
    }
    
    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }
    
}
