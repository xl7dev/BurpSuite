package burp;

public class IntruderPayloadProcessor implements IIntruderPayloadProcessor {

	private BurpExtender parent;
	
	// 0 is decrypt, 1 encrypt
	private int proc_type;
	
	public IntruderPayloadProcessor(BurpExtender newParent, int type) {
		parent = newParent;
		proc_type = type;
	}
	
    @Override
    public String getProcessorName() {
    	if (proc_type == 0) {
    		return "AES Decrypt";
    	} else {
    		return "AES Encrypt";
    	}
    }
    
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        try {
            String payloadString = new String(currentPayload);
            String result;
            if (proc_type == 0) {
            	result = parent.decrypt(payloadString);
            } else { 
            	result = parent.encrypt(payloadString);
            }
            return result.getBytes();
        } catch(Exception e) {
        	parent.callbacks.issueAlert(e.toString());
        	return null;
        }

    }
}


