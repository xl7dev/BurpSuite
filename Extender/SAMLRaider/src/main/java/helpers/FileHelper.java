package helpers;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class FileHelper {

	/**
	 * Read file from JAR and export it to temporary file
	 * 
	 * @param filename
	 * @return temporary file name
	 */
	public String exportRessourceFromJar(String filename) throws IOException {
		InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filename);
		File outputFile = File.createTempFile(filename, "");
		outputFile.deleteOnExit();
		Files.copy(inputStream, outputFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
		return outputFile.getAbsolutePath();
	}

	/**
	 * Helper method for exporting PEM object.
	 * 
	 * @param object
	 *            to export in PEM format.
	 * @param filename
	 *            for the file to export.
	 */
	public void exportPEMObject(Object pemObject, String filename) throws IOException {
		Writer writer;
		writer = new FileWriter(filename);
		JcaPEMWriter jcaPemWriter = new JcaPEMWriter(writer);
		jcaPemWriter.writeObject(pemObject);
		jcaPemWriter.flush();
		jcaPemWriter.close();
	}

	/**
	 * Checks if the program is started from jar.
	 * 
	 * @return true if started from jar.
	 */
	public boolean startedFromJar() {
		// Check if running from a jar or not and add certificates
		// https://stackoverflow.com/questions/482560/can-you-tell-on-runtime-if-youre-running-java-from-within-a-jar
		String className = getClass().getName().replace('.', '/');
		String classJar = getClass().getResource("/" + className + ".class").toString();
		return classJar.startsWith("jar:");
	}
}
