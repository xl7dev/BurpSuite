package burp;

public class InsertionPoint implements IScannerInsertionPoint {
	
	private BurpExtender parent;
    private byte[] baseRequest;
    private String baseName;
    private String baseValue;

    InsertionPoint(BurpExtender newParent, byte[] baseRequest, String basename, String basevalue)
    {
    	this.parent = newParent;
        this.baseRequest = baseRequest;
        this.baseName = basename;
        this.baseValue = basevalue;
        
    }

    // 
    // implement IScannerInsertionPoint
    //
    
    @Override
    public String getInsertionPointName()
    {
        return "AES Encrypted Input";
    }

    @Override
    public String getBaseValue()
    {
        return baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload)
    {
    	String payloadPlain = parent.helpers.bytesToString(payload);
    	String payloadEncrypted = "";
        try {
        	payloadEncrypted = parent.encrypt(payloadPlain);
        } catch(Exception e) {
        	parent.callbacks.issueAlert(e.toString());
        }
        parent.callbacks.issueAlert("Inserting " + payloadPlain + " [" + payloadEncrypted + "] in parameter " + baseName);
        
        // TODO: Only URL parameters, must change to support POST parameters, cookies, etc.
        return parent.helpers.updateParameter(baseRequest, parent.helpers.buildParameter(baseName, payloadEncrypted, IParameter.PARAM_URL));
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload)
    {
        // since the payload is being inserted into a serialized data structure, there aren't any offsets 
        // into the request where the payload literally appears
        return null;
    }

    @Override
    public byte getInsertionPointType()
    {
        return INS_EXTENSION_PROVIDED;
    }
}