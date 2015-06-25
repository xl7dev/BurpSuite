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
package util;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import gui.viewMessage.ExternalUpdater;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import model.SentinelHttpMessage;
import model.SentinelHttpService;

/**
 *
 * @author unreal
 */
public class BurpCallbacks {

    static private BurpCallbacks burpCallbacks = null;
    private IBurpExtenderCallbacks callback;
    private PrintWriter stdout;

    public void init(IBurpExtenderCallbacks callback) {
        this.callback = callback;
        stdout = new PrintWriter(callback.getStdout(), true);
    }

    public IBurpExtenderCallbacks getBurp() {
        return callback;
    }

    public void print(String s) {
        if (stdout != null) {
            stdout.println(s);
        }
    }

    public static BurpCallbacks getInstance() {
        if (burpCallbacks == null) {
            burpCallbacks = new BurpCallbacks();
        }
        return burpCallbacks;
    }
    
    public void sendRessource(final SentinelHttpMessage sentinelMessage, final boolean followRedirect, final ExternalUpdater updater) {
        Thread queryThread = new Thread() {
            public void run() {
                try {
                    sendRessource(sentinelMessage, followRedirect);
                    updater.externalUpdate();
                } catch (ConnectionTimeoutException ex) {
                    BurpCallbacks.getInstance().print("Error sendingz");
                }
            }
        };
        queryThread.start();
        
    }

    public void sendRessource(SentinelHttpMessage httpMessage, boolean followRedirect) throws ConnectionTimeoutException {
        if (getBurp() == null) {
            BurpCallbacks.getInstance().print("sendRessource: No burp available. Abort.");
            return;
        }
        if (httpMessage == null) {
            BurpCallbacks.getInstance().print("sendRessource: Void httpmessage! See previous errors. Abort.");
            return;
        }
        if (httpMessage.getHttpService() == null || httpMessage.getRequest() == null) {
            BurpCallbacks.getInstance().print("sendRessource: Void data! Abort.");
            return;
        }
        
//        try {
            IHttpRequestResponse r = null;
            long timeStart = System.currentTimeMillis();
            r = getBurp().makeHttpRequest(httpMessage.getHttpService(), httpMessage.getRequest());
            long time = System.currentTimeMillis() - timeStart;
            httpMessage.setLoadTime(time);

            
            if (r.getResponse() == null) {
                throw new ConnectionTimeoutException();
            }
            
            if (followRedirect) {
                int n = 0;
                while (isRedirect(r.getResponse()) && ++n <= 10) {
                    BurpCallbacks.getInstance().print("Is redir, following...");
                    httpMessage.setRedirected(true);
                    r = followRedirect(r);
                }
                if (n >= 10) {
                    String s = "Redirected 10 times, aborting...";
                    httpMessage.setResponse(s.getBytes());
                } else {
                    httpMessage.setResponse(r.getResponse());
                }
            } else {
                httpMessage.setResponse(r.getResponse());
            }
  //      } catch (Exception ex) {
   //         BurpCallbacks.getInstance().print("sendRessource(): " + ex.getLocalizedMessage());
    //    }
    }

    private boolean isRedirect(byte[] response) {
        IResponseInfo responseInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeResponse(response);
        if (responseInfo.getStatusCode() == 302) {
            return true;
        } else {
            return false;
        }
    }

    private IHttpRequestResponse followRedirect(IHttpRequestResponse r) {
        byte[] response = r.getResponse();
        
        IResponseInfo responseInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeResponse(response);
        String redirStr = null;

        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("location: ")) {
                String[] h = header.split(": ");
                if (h.length == 2) {
                    redirStr = h[1];
                }
            }
        }

        if (redirStr == null) {
            BurpCallbacks.getInstance().print("302 found, but could not extract location header!");
            return null;
        }
        
        /* 302 has 3 possible values:
         * 1) http://www.bla.ch/asdf/test.cgi?a=b
         * 2) /asdf/test.cgi?a=b
         * 3) test.cgi?a=b
         * URL will handle all of em
         */
        
        URL redirUrl = null;
        redirUrl = followRedirectUrl(redirStr, r);
        if (redirUrl == null) {
            return null;
        }
        
        byte[] req = BurpCallbacks.getInstance().getBurp().getHelpers().buildHttpRequest(redirUrl);
        int port = redirUrl.getPort();
        if (port == -1) {
            port = redirUrl.getDefaultPort();
        }
        IHttpService httpService = new SentinelHttpService(
                redirUrl.getHost(), port, redirUrl.getProtocol());
        IHttpRequestResponse res = getBurp().makeHttpRequest(httpService, req);
        
        return res;
    }
    
    private URL followRedirectUrl(String redirStr, IHttpRequestResponse message) {
        // get old url
        IRequestInfo requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(message);
        URL origUrl = requestInfo.getUrl();
        
        // create new url
        URL url;
        try {
            url = new URL(origUrl, redirStr);
        } catch (MalformedURLException ex) {
            BurpCallbacks.getInstance().print("302 found, but could not convert location header!");
            return null;
        }
        
        return url;
    }

    public void sendToRepeater(SentinelHttpMessage httpMessage) {
        try {
            String s = "";
            if (httpMessage.getTableIndexAttack() >= 0) {
                s = "Sentinel " + httpMessage.getTableIndexMain() + "/" + httpMessage.getTableIndexAttack();
            } else {
                s = "Sentinel " + httpMessage.getTableIndexMain();
            }
            
            this.getBurp().sendToRepeater(
                    httpMessage.getHttpService().getHost(),
                    httpMessage.getHttpService().getPort(),
                    (httpMessage.getHttpService().getProtocol().equals("http") ? false : true),
                    httpMessage.getRequest(),
                    s);
        } catch (Exception ex) {
            BurpCallbacks.getInstance().print(ex.getLocalizedMessage());
        }
    }
}
