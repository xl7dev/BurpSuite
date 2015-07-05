package burp;
import java.net.URL;
import java.util.Arrays;

import org.apache.jmeter.protocol.amf.util.AmfXmlConverter;

public class AMFUtilities {
	static final String X_BURP_DESERIALIZED = "X-Burp: Deserialized";
	static final String X_BURP_INITDESERIALIZED = "X-Burp: InitDeserialized";

	static final String X_BURP_SERIALIZED = "X-Burp: Serialized";
	static String DOUBLELINEBREAK = "\\r\\n\\r\\n";
	static String LINESEPARATOR = System.getProperty("line.separator");

	static String AMF_CONTENT_TYPE = "application/x-amf";
	static String CONTENT_TYPE = "content-type: ";

	public static byte[] getBody(byte[] message) {

		String testStr = new String(message);
		String[] strHeadersAndContent = testStr.split(DOUBLELINEBREAK);
		byte[] reqBody = Arrays.copyOfRange(message, strHeadersAndContent[0].getBytes().length + 4, message.length);
		return reqBody;
	}
	public static String getHeader(byte[] message) {

		String testStr = new String(message);
		String[] strHeadersAndContent = testStr.split(DOUBLELINEBREAK);
		return strHeadersAndContent[0];
	}


	public static byte[] deserializeProxyItem(byte[] message) {
		try {
			String testStr = new String(message);
			String[] strHeadersAndContent = testStr.split(DOUBLELINEBREAK);
			String xml = AmfXmlConverter.convertAmfMessageToXml(getBody(message), true);
			if (xml == null) {
				return null;
			}
			String headerWithUpdatedLength = strHeadersAndContent[0].replaceAll("Content-Length: .*", "Content-Length: " + String.valueOf(xml.length()));
			return (headerWithUpdatedLength + LINESEPARATOR + X_BURP_DESERIALIZED + LINESEPARATOR + LINESEPARATOR + xml).getBytes();
		} catch (Exception e) {
			e.printStackTrace();
			return message;
		}
	}

	public static byte[] serializeProxyItem(byte[] message) {

		try {
			String strMessage = new String(message);
			String[] strHeadersAndContent = strMessage.split(DOUBLELINEBREAK);
			byte[] content = AmfXmlConverter.convertXmlToAmfMessage(strHeadersAndContent[1]);
			if (content == null)
				return null;
			String headerWithUpdatedLength = strHeadersAndContent[0].replaceAll("Content-Length: .*", "Content-Length: " + String.valueOf(content.length));
			byte[] header = (headerWithUpdatedLength  + LINESEPARATOR + LINESEPARATOR).getBytes();
			byte[] retArray = new byte[header.length + content.length];
			System.arraycopy(header, 0, retArray, 0, header.length);
			System.arraycopy(content, 0, retArray, header.length, content.length);
			return retArray;
		} catch (Exception e) {
			e.printStackTrace();
			return message;
		}

	}

	public static byte[] serializeProxyItem(byte[] message, byte[] body) {

		try {
			String strMessage = new String(message);
			String[] strHeadersAndContent = strMessage.split(DOUBLELINEBREAK);
			byte[] content = AmfXmlConverter.convertXmlToAmfMessage(new String(body));
			if (content == null)
				return null;
			String headerWithUpdatedLength = strHeadersAndContent[0].replaceAll("Content-Length: .*", "Content-Length: " + String.valueOf(content.length));
			byte[] header = (headerWithUpdatedLength + LINESEPARATOR + LINESEPARATOR).getBytes();
			byte[] retArray = new byte[header.length + content.length];
			System.arraycopy(header, 0, retArray, 0, header.length);
			System.arraycopy(content, 0, retArray, header.length, content.length);
			return retArray;
		} catch (Exception e) {
			e.printStackTrace();
			return message;
		}

	}
	public static void print(byte[] header) {
		System.out.println(new String(header));
	}

	public static void print(String header) {
		System.out.println(header);
	}

	public static void print(URL url) {
		System.out.println(url.getPath());
	}

}
