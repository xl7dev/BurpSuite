package helpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public class HTTPHelpers {

	// Source:
	// http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
	public byte[] decompress(byte[] data, boolean gzip) throws IOException, DataFormatException {
		Inflater inflater = new Inflater(true);
		inflater.setInput(data);
	
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
		byte[] buffer = new byte[1024];
		while (!inflater.finished()) {
			int count = inflater.inflate(buffer);
			outputStream.write(buffer, 0, count);
		}
		outputStream.close();
		byte[] output = outputStream.toByteArray();
	
		inflater.end();
	
		return output;
	}

	// Source:
	// http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
	public byte[] compress(byte[] data, boolean gzip) throws IOException {
		Deflater deflater = new Deflater(5,gzip);
		deflater.setInput(data);
	
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
	
		deflater.finish();
		byte[] buffer = new byte[1024];
		while (!deflater.finished()) {
			int count = deflater.deflate(buffer);								
			outputStream.write(buffer, 0, count);
		}
		outputStream.close();
		byte[] output = outputStream.toByteArray();
	
		deflater.end();
	
		return output;
	}

	
	
}
