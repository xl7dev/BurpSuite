package burp;


public class CustomHttpRequestResponse implements IHttpRequestResponse {

    private byte[] _request = null;
    private byte[] _response = null;
    private IHttpService _httpService;
    private String _comment = "";


    
    public CustomHttpRequestResponse(byte[] request, byte[] response, IHttpService httpService){
        this._request = request;
        this._response = response;
        this._httpService = httpService;
    }

    @Override
    public byte[] getRequest() {
        return this._request;
    }


    @Override
    public byte[] getResponse()  {
        return this._response;
    }


    @Override
    public String getComment()  {
        return this._comment;
    }


    @Override
    public void setComment(String comment) {
        this._comment = "";
    }
    
    @Override
    public void setRequest(byte[] message)  {
        this._request = message;
    }

   

    @Override
    public void setResponse(byte[] message) {
        this._response = message;
    }

    @Override
    public String getHighlight() {
        return "";
    }

    @Override
    public void setHighlight(String color) {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public IHttpService getHttpService() {
        return this._httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this._httpService = httpService;
    }
}