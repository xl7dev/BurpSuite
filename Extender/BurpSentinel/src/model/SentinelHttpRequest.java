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
import burp.IParameter;
import burp.IRequestInfo;
import gui.session.SessionManager;
import gui.session.SessionUser;
import java.io.IOException;
import java.io.Serializable;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import util.BurpCallbacks;

/**
 *
 * @author unreal
 */
public class SentinelHttpRequest implements Serializable {

    private LinkedList<SentinelHttpParam> httpParams = new LinkedList<SentinelHttpParam>();
    private LinkedList<SentinelHttpParamVirt> httpParamsVirt = new LinkedList<SentinelHttpParamVirt>();
    
    private SentinelHttpParam changeParam;
    private SentinelHttpParam origParam;
    
    private byte[] request;
    
    transient private IRequestInfo requestInfo; // re-init upon deserializing in readObject()
    private SentinelHttpService httpService;

    public SentinelHttpRequest() {
        // Void Deserializing constructor
    }

    // Deserializing
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        // As I dont want to re-implement IRequestInfo, make it transient
        // and redo requestInfo upon deserializing
        
        if (request != null) {
            requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        } else {
            System.out.println("Could not restore requestInfo upon deserializing!");
        }
    }
    
    public SentinelHttpRequest(IHttpRequestResponse httpMessage) {
        request = httpMessage.getRequest();
        this.httpService = new SentinelHttpService(httpMessage.getHttpService());
        
        init(httpMessage);
    }
    
    public SentinelHttpRequest(String r, IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
        this.request = BurpCallbacks.getInstance().getBurp().getHelpers().stringToBytes(r);
        
        init();
    }
    
    public SentinelHttpRequest(byte[] request, IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
        this.request = request;
        
        init();
    }

    /* IHttpPequestResponse has httpService
     * therefor it is able to set URL correctly
     */
    private void init(IHttpRequestResponse httpMessage) {
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpMessage);
        if (requestInfo == null) {
            BurpCallbacks.getInstance().print("Requestinfo null!!!");
            return;
        }        
        
        init2();
    }

    /* request and httpServices are seperated
     * May use old existing httpService, assuming it matches current request
     */
    private void init() {
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        if (requestInfo == null) {
            BurpCallbacks.getInstance().print("Requestinfo null!!!");
            return;
        }
        
        init2();
    }
    
    /*
     * requestInfo has to be set before calling this function
     */
    private void init2() {
        httpParams.clear();
        LinkedList<SentinelHttpParam> httpParamsNew = new LinkedList<SentinelHttpParam>();
        
        // Add standard parameter
        if (requestInfo.getParameters() != null) {
            for(IParameter param: requestInfo.getParameters()) {
                httpParamsNew.add(new SentinelHttpParam(param));
            }
        } else {
            BurpCallbacks.getInstance().print("requestinfo null!");
        }
        
        // Sort parameter
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() == SentinelHttpParam.PARAM_URL) {
                httpParams.add(sortParam);
            }
        }
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() == SentinelHttpParam.PARAM_BODY) {
                httpParams.add(sortParam);
            }
        }
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() != SentinelHttpParam.PARAM_URL
                    && sortParam.getType() != SentinelHttpParam.PARAM_BODY ) {
                httpParams.add(sortParam);
            }
        }
        
        // add additional parameter
        initMyParams();
    }
        
    private void initMyParams() {
        String req = BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(request);
        
        int newlineIndex = req.indexOf("\r\n");
        if (newlineIndex < 0) {
            BurpCallbacks.getInstance().print("Error in HTTP Request: no newline");
            return;
        }
        
        String firstLine = req.substring(0, newlineIndex);
        //String rest = req.substring(req.indexOf("\r\n"), req.length());
        
        String header[] = firstLine.split(" ");
        if (header.length != 3) {
            return;
        }
        
        // Check if we have arguments
        int endPath = header[1].indexOf("?");
        if (endPath == -1) {
            endPath = header[1].length();
        }
        String myHeader = header[1].substring(0, endPath);

        // Extract path
        String path = "";
        if (myHeader.startsWith("/")) {
            path = myHeader;
        } else {
            int n = myHeader.indexOf('/', 9);
            path = myHeader.substring(n, myHeader.length());
        }
        
        // Split path
        LinkedList<SentinelHttpParam> pathParams = new LinkedList<SentinelHttpParam>();
        String[] p = path.split("/");
        int i = 0;
        for (String pathPart : p) {
            if (pathPart.length() == 0) {
                continue;
            }
            
            int valStart = firstLine.indexOf('/' + pathPart);
            valStart++; // because of /

            SentinelHttpParam sentParam = new SentinelHttpParam(
                    SentinelHttpParam.PARAM_PATH,
                    Integer.toString(i), 0, 0, 
                    pathPart, valStart, valStart + pathPart.length());
            //httpParams.add(sentParam);
            pathParams.push(sentParam);
            i++;
        }
        httpParams.addAll(pathParams);

    }
    
    
    public URL getUrl() {
        return requestInfo.getUrl();
    }
    
    public String getMethod() {
        return requestInfo.getMethod();
    }
    
    
    /**
     * ************************** Getters*************************************
     * 
     * Note: the following functions are slow, as it extracts on the fly
     * 
     */
    public String extractFirstLine() {
        String http = getRequestStr().substring(0, getRequestStr().indexOf("\r\n"));
        return http;
    }

    public List<String> extractHeaders() {
        return requestInfo.getHeaders();
    }

    public String extractBody() {
        String req = getRequestStr();

        String body = getRequestStr().substring(requestInfo.getBodyOffset());

        if (body.length() > 0) {
            return body;
        } else {
            return "";
        }
    }

    
    /**
     * ************************** Param **************************************
     */
    public void setChangeParam(SentinelHttpParam changeParam) {
        this.changeParam = changeParam;
        // TODO: Set orig param
    }
    
    
    // Write request
    public boolean applyChangeParam() {
        if (request == null || request.length == 0) {
            BurpCallbacks.getInstance().print("ApplyChangeParam: Cant apply changeparam - no request");
            return false;
        }
        if (origParam == null) {
            BurpCallbacks.getInstance().print("ApplyChangeParam: no orig param");
            return false;
        }

        byte paramType = changeParam.getType();
        if (paramType == SentinelHttpParam.PARAM_PATH) {
            request = updateParameterPath(request, changeParam);
        } else {
            request = BurpCallbacks.getInstance().getBurp().getHelpers().updateParameter(request, changeParam);
        }
        
        // Update httpparams linked with this request with correct offsets
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        for(IParameter newParam: requestInfo.getParameters()) {
            if (changeParam.isThisParameter(newParam)) {
                changeParam.updateLocationWith(newParam);
            }
        }
        
        // Update change param to reflect new state
        init();
        
        return true;
    }
    
    private byte[] updateParameterPath(byte[] request, SentinelHttpParam changeParam) {
        String req = BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(request);

        req = req.replaceFirst("\\/" + origParam.getValue(), "\\/" + changeParam.getValue());
        
        return BurpCallbacks.getInstance().getBurp().getHelpers().stringToBytes(req);
    }
    

    public SentinelHttpParam getOrigParam() {
        return origParam;
    }

    public void setOrigParam(SentinelHttpParam origParam) {
        this.origParam = origParam;
    }

    public SentinelHttpParam getChangeParam() {
        return changeParam;
    }
    
    public String getRequestStr() {
        return BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(request);
    }
    
    public byte[] getRequestByte() {
        return request;
    }

    public Iterable<SentinelHttpParam> getParams() {
        return httpParams;
    }

    public SentinelHttpParam getParam(String name, byte type) {
        for(SentinelHttpParam param: httpParams) {
            if (param.getType() == type && param.getName().equals(name)) {
                return param;
            }
        }

        return null;
    }
    
    public void addParamVirt(SentinelHttpParamVirt paramVirt) {
        httpParamsVirt.add(paramVirt);
    }
    
    public Iterable<SentinelHttpParamVirt> getParamsVirt() {
        return httpParamsVirt;
    }
    

    /**
     * ************************** Session ************************************
     */
    public void changeSession(String sessionVarName, String sessionVarValue) {
        SentinelHttpParam updateParam = null;

        SentinelHttpParam param = getParam(sessionVarName, SentinelHttpParam.PARAM_COOKIE);
        if (param == null) {
            BurpCallbacks.getInstance().print("HttpRequest: ChangeSession(): Could not identify session var!");
            return;
        }
        
        // Dont update if they are already equal
        if (param.getValue().equals(sessionVarValue)) {
            return;
        }

        updateParam = new SentinelHttpParam(param);
        updateParam.changeValue(sessionVarValue);

        request = BurpCallbacks.getInstance().getBurp().getHelpers().updateParameter(request, updateParam);
        init();
    }
    
    public String getSessionValue() {
        String sessionName = SessionManager.getInstance().getSessionVarName();
        
        SentinelHttpParam sessionParam = getParam(sessionName, SentinelHttpParam.PARAM_COOKIE);
        if (sessionParam != null) {
            return sessionParam.getValue();
        } else{
            return null;
        }
    }
    
    public String getSessionValueTranslated() {
        String s = getSessionValue();
        if (s == null) {
            return "-";
        }
        
        SessionUser u = SessionManager.getInstance().getUserFor(s);
        if (u == null) {
            return s;
        } else {
            return u.getName();
        }
        
    }

    
}