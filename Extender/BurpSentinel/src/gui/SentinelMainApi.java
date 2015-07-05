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
package gui;

import burp.IHttpRequestResponse;
import burp.IMessageEditorTabFactory;
import burp.IProxyListener;
import burp.IScannerCheck;
import model.ModelRoot;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import service.SentinelEditorFactoryInfo;
import service.SentinelPassiveScanner;
import service.SentinelProxyListener;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SentinelMainApi {
    
    private SentinelMainUi sentinelMainUi;
    private SentinelProxyListener proxyListener;
    private SentinelPassiveScanner passiveScanner;
    private SentinelEditorFactoryInfo editorFactory;
    private ModelRoot modelRoot;
    
    static private SentinelMainApi sentinelMainApi;
    
    static public SentinelMainApi getInstance() {
        if (sentinelMainApi == null) {
            sentinelMainApi = new SentinelMainApi();
        }
        
        return sentinelMainApi;
    }
    
    public SentinelMainApi() {
    }
    
    public void init() {
        modelRoot = ModelRoot.getInstance();
        sentinelMainUi = new SentinelMainUi(modelRoot);
    }
    
    public SentinelMainUi getMainUi() {
        return sentinelMainUi;
    }
    
    
    public IScannerCheck getPassiveScanner() {
        if (passiveScanner == null) {
            passiveScanner = new SentinelPassiveScanner();
        }
        return passiveScanner;
    }

    public IProxyListener getProxyListener() {
        if (proxyListener == null) {
            proxyListener = new SentinelProxyListener();
        }
        return proxyListener;
    }
    
    public IMessageEditorTabFactory getEditorFactoryInfo() {
        if (editorFactory == null) {
            editorFactory = new SentinelEditorFactoryInfo();
        }
        return editorFactory;
    }

    
    /* Add new HttpRequestResponse
     * 
     * This gets called from (external) Burp Menu entry
     * this is the main entry point for new HttpMessages (IHttpRequestResponse)
     * The message will be added to the main model.
     */
    public void addNewMessage(IHttpRequestResponse iHttpRequestResponse) {
        // Make a sentinel http message from the burp message
        SentinelHttpMessageOrig myHttpMessage = new SentinelHttpMessageOrig(iHttpRequestResponse);
        
        modelRoot.addNewMessage(myHttpMessage);
    }
    
    /* Add new HttpRequestResponse from Attack Message
     * 
     * This gets called from panel right popup, where we already have attack message
     */
    public void addNewMessage(SentinelHttpMessageAtk atkMsg) {
        // Make a sentinel http message from the atk message
        SentinelHttpMessageOrig myHttpMessage = new SentinelHttpMessageOrig(atkMsg);
        modelRoot.addNewMessage(myHttpMessage);
    }
    
    /*
     * Add new OriginalHttpMessage
     * 
     * Used when restoring previously saved messages.
     */
    public void addMessage(SentinelHttpMessageOrig httpMessage) {
        modelRoot.addNewMessage(httpMessage);
    }
    
    
    public ModelRoot getModelRoot() {
        return modelRoot;
    }

    
    /*
     * Init testcase messages
     */
    public void initTestMessages() {
        String a = "";
        a += "GET /vulnerable/test1.php?testparam=test%27 HTTP/1.1\r\n";
        a += "Host: www.dobin.ch\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "\r\n";
        SentinelHttpMessage httpMessage = new SentinelHttpMessageOrig(a, "www.dobin.ch", 80, false);
        addNewMessage(httpMessage);


        a = "";
        a += "GET /vulnerable/test1.php?abcdefgh HTTP/1.1\r\n";
        a += "Host: www.dobin.ch\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Cookie: jsessionid=asdfa; bbbbb=ddddd\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "\r\n";
        httpMessage = new SentinelHttpMessageOrig(a, "www.dobin.ch", 80, false);
        addNewMessage(httpMessage);


        a = "";
        a += "POST /vulnerable/test2.php HTTP/1.1\r\n";
        a += "Host: www.dobin.ch\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "Cookie: jsessionid=useraaaa; bbbbb=ddddd\r\n";
        a += "Content-Type: application/x-www-form-urlencoded\r\n";
        a += "Content-Length: 26\r\n";
        a += "\r\n";
        a += "bla=blaaa&testparam=teeest";
        httpMessage = new SentinelHttpMessageOrig(a, "www.dobin.ch", 80, false);
        addNewMessage(httpMessage);


        a = "";
        a += "GET /vulnerable/test3.php?name=test1&testparam=test2 HTTP/1.1\r\n";
        a += "Host: www.dobin.ch\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "Cookie: jsessionid=useraaaa; bbbbb=ddddd\r\n";
        a += "\r\n";
        httpMessage = new SentinelHttpMessageOrig(a, "www.dobin.ch", 80, false);
        addNewMessage(httpMessage);


        a = "";
        a += "POST http://192.168.140.134/vulnerable/testing.php?name=test1&testparam=&aaa= HTTP/1.1\r\n";
        a += "Host: 192.168.140.134\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "Cookie: jsessionid=userbbb; jive.server.info=\"serverName=as-3:serverPort=80:contextPath=:localName=localhost:localPort=9001:localAddr=127.0.0.1\"; ROUTEID=.AS-3; SPRING_SECURITY_REMEMBER_ME_COOKIE=YzEwMDAwMDoxMzU3MDI5NzM1Njk2OjQxZGJkNGRiODZhNWZlNjU4OWQ4YjEyYWM0Y2QyZDVi; jive.user.loggedIn=true\r\n";
        a += "\r\n";
        a += "lll1=aaa1\r\n";
        a += "lll2=aaa2\r\n";
        httpMessage = new SentinelHttpMessageOrig(a, "192.168.140.134", 80, false);
        addNewMessage(httpMessage);


        a = "";
        a += "POST http://192.168.140.134/vulnerable/testing.php?name=test1&testparam=&aaa= HTTP/1.1\r\n";
        a += "Host: 192.168.140.134\r\n";
        a += "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0\r\n";
        a += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        a += "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n";
        a += "Accept-Encoding: gzip, deflate\r\n";
        a += "Proxy-Connection: keep-alive\r\n";
        a += "\r\n";
        a += "Content-Type: multipart/form-data; boundary=---------------------------1645864822313206347576655232\r\n";
        a += "Content-Length: 3153\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";
        a += "Content-Disposition: form-data; name=\"utf8\"\r\n";
        a += "\r\n";
        a += "aaa\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";
        a += "Content-Disposition: form-data; name=\"_method\"\r\n";
        a += "\r\n";
        a += "put\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";
        a += "Content-Disposition: form-data; name=\"authenticity_token\"\r\n";
        a += "\r\n";
        a += "PTNmG3crwtME0kRijri1uNfS6b8l9ET2CLvZydnEhD4=\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";
        a += "Content-Disposition: form-data; name=\"dossier[title]\"\r\n";
        a += "\r\n";
        a += "\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";
        a += "Content-Disposition: form-data; name=\"dossier[prename]\"\r\n";
        a += "\r\n";
        a += "Snb5\r\n";
        a += "-----------------------------1645864822313206347576655232\r\n";

        httpMessage = new SentinelHttpMessageOrig(a, "192.168.140.134", 80, false);
        addNewMessage(httpMessage);
    }


}
