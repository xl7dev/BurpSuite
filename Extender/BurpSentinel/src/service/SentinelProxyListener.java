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
package service;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import gui.SentinelMainApi;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageOrig;
import util.BurpCallbacks;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SentinelProxyListener implements IProxyListener {

    private Boolean next2Repeater = false;
    private Boolean next2Sentinel = false;

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            processRequest(message);
        } else {
            processResponse(message);
        }
    }

    private void processResponse(IInterceptedProxyMessage message) {
    }

    private void processRequest(IInterceptedProxyMessage message) {
        if (next2Repeater) {
            SentinelHttpMessage httpMessage = new SentinelHttpMessageOrig(message.getMessageInfo());
            BurpCallbacks.getInstance().getBurp().sendToRepeater(
                    httpMessage.getHttpService().getHost(),
                    httpMessage.getHttpService().getPort(),
                    (httpMessage.getHttpService().getProtocol().equals("http") ? false : true),
                    httpMessage.getRequest(),
                    "");
            next2Repeater = false;
        }
        if (next2Sentinel) {
            SentinelHttpMessage httpMessage = new SentinelHttpMessageOrig(message.getMessageInfo());
            //SentinelMainUi.getMainUi().addNewMessage(httpMessage);
            SentinelMainApi.getInstance().addNewMessage(httpMessage);
            next2Sentinel = false;
        }

        sentinelCheck(message);
    }

    private void sentinelCheck(IInterceptedProxyMessage message) {
        SentinelHttpMessage msg = new SentinelHttpMessageOrig(message.getMessageInfo());

        String url = msg.getReq().getUrl().toString();

        if (url.startsWith("http://sentinel")) {
            if (url.contains("nextToRepeater")) {
                next2Repeater = true;
            }
            if (url.contains("nextToSentinel")) {
                next2Sentinel = true;
            }

            if (url.contains("enableIntercept")) {
                BurpCallbacks.getInstance().getBurp().setProxyInterceptionEnabled(true);
            }
            if (url.contains("disableIntercept")) {
                BurpCallbacks.getInstance().getBurp().setProxyInterceptionEnabled(false);
            }

            // Removed, because did not really remove request
//            message.getMessageInfo().setRequest("GET http://burp/ HTTP1.1\r\nHost: burp\r\n\r\n".getBytes());
            message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
        }
    }
}
