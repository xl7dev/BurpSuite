package burp;


public class HTTPParser {


    public static String getRequestHeaderValue(IRequestInfo requestInfo, String headerName) {
        headerName = headerName.toLowerCase().replace(":", "");
        for (String header : requestInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName)) {
                return header.split(":", 0)[1];
            }
        }
        return null;
    }    
    
    public static String getResponseHeaderValue(IResponseInfo responseInfo, String headerName) {
        headerName = headerName.toLowerCase().replace(":", "");
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName)) {
                return header.split(":", 0)[1];
            }
        }
        return null;
    }    
    
    public static String getHTTPBasicCredentials(IRequestInfo requestInfo) throws Exception{
        String authHeader  = getRequestHeaderValue(requestInfo, "Authorization").trim(); 
        String[] parts = authHeader.split("\\s");
        
        if (parts.length != 2)
            throw new Exception("Wrong number of HTTP Authorization header parts");

        if (!parts[0].equalsIgnoreCase("Basic"))
            throw new Exception("HTTP authentication must be Basic");

        return parts[1]; 
    }
    
}
