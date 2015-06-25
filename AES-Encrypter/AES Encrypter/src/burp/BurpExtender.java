package burp;

import java.awt.*;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import sun.misc.*;

public class BurpExtender implements IBurpExtender, IIntruderPayloadProcessor {

    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Encrypted AES Payloads");

        // register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(this);
    }
    
    @Override
    public String getProcessorName() {
        return "AES Encypter";
    }


    public static String encrypt(String plainText) throws Exception {
        // generate key
        byte[] keyValue=new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
        Key skeySpec = new SecretKeySpec(keyValue, "AES");

        // Generate null IV
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

        byte[] encVal = cipher.doFinal(plainText.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue.toString();
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        try {
            String payloadString = new String(currentPayload);
            String result = BurpExtender.encrypt(payloadString);
            return result.getBytes();
        } catch(Exception e) {
            return null;
        }
    }
}
