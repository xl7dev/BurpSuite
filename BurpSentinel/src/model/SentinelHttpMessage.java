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
import burp.IHttpService;
import java.io.Serializable;
import java.util.Date;
import java.util.LinkedList;
import java.util.Observable;
import util.BurpCallbacks;

/**
 * HttpMessage Model
 *
 * Capsules IHttpRequestResponse from burp Handles all data modifications of the
 * request and response
 *
 * @author Dobin
 */
public abstract class SentinelHttpMessage extends Observable implements IHttpRequestResponse, Serializable {

    private SentinelHttpResponse httpResponse;
    private SentinelHttpRequest httpRequest;
    private String comment;
    private SentinelHttpService httpService;
    private Date createTime;
    private long loadTime = 0;

    public SentinelHttpMessage() {
        // Deserializing Constructor
    }

    public SentinelHttpMessage(IHttpRequestResponse httpMessage) {
        httpRequest = new SentinelHttpRequest(httpMessage);
        httpService = new SentinelHttpService(httpMessage.getHttpService());
        httpResponse = new SentinelHttpResponse(httpMessage);

        createTime = new Date(System.currentTimeMillis());
        comment = httpMessage.getComment();
    }

    public SentinelHttpMessage(SentinelHttpMessage httpMessage) {
        this((IHttpRequestResponse) httpMessage);
        this.tableIndexMain = httpMessage.getTableIndexMain();
    }

    public SentinelHttpMessage(String s, String host, int port, boolean https) {
        //httpService = BurpCallbacks.getInstance().getBurp().getHelpers().buildHttpService(host, port, https);
        httpService = new SentinelHttpService(host, port, https);
        httpRequest = new SentinelHttpRequest(s, httpService);

        httpResponse = new SentinelHttpResponse();

        createTime = new Date(System.currentTimeMillis());
    }

    public SentinelHttpMessage(String s, IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
        httpRequest = new SentinelHttpRequest(s, httpService);

        createTime = new Date(System.currentTimeMillis());
    }

    public SentinelHttpRequest getReq() {
        return httpRequest;
    }

    public SentinelHttpResponse getRes() {
        return httpResponse;
    }

    public Date getCreateTime() {
        return createTime;
    }
    private boolean isRedirected;

    public void setLoadTime(long time) {
        this.loadTime = time;
    }

    public long getLoadTime() {
        return loadTime;
    }

    public void setRedirected(boolean b) {
        isRedirected = b;
    }

    public boolean isRedirected() {
        return isRedirected;
    }

////////////////////////////////////////////////
    @Override
    public String getHighlight() {
        BurpCallbacks.getInstance().print("NOT SUPPORTED");
        return "";
    }

    @Override
    public void setHighlight(String color) {
        BurpCallbacks.getInstance().print("NOT SUPPORTED");
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
    }


    @Override
    public byte[] getRequest() {
        return httpRequest.getRequestByte();
    }

    @Override
    public void setRequest(byte[] message) {
        httpRequest = new SentinelHttpRequest(message, httpService);
    }

    @Override
    public byte[] getResponse() {
        return httpResponse.getByteResponse();
    }

    @Override
    public void setResponse(byte[] message) {
        httpResponse = new SentinelHttpResponse(message);
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }
    /**
     * *****************************************
     */
    private int tableIndexMain = -1;

    public int getTableIndexMain() {
        return tableIndexMain;
    }

    public void setTableIndexMain(int index) {
        this.tableIndexMain = index;
    }
    private int tableIndexAttack = -1;

    public int getTableIndexAttack() {
        return tableIndexAttack;
    }

    public void setTableIndexAttack(int index) {
        this.tableIndexAttack = index;
    }
}
