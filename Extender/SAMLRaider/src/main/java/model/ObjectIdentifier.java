package model;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;

public final class ObjectIdentifier {

	private static Map<String, String> extensionsMap;
	private static Map<String, String> extendedKeyUsageMap;
	private static Map<Integer, String> subjectAlternativeNamesMap;
	private static Map<Integer, String> keyUsageMap;
	private static HashMap<String, Integer> x509keyUsage;
	private static HashMap<String, KeyPurposeId> x509KeyPurpose;
	private static HashMap<String, Integer> x509SubjectAlternativeName;
	private static List<String> signatureAlgorithms;
	private static List<String> publicKeyAlgorithms;
	private static List<String> supportedExtensions;

	public static String getExtension(String s) {
		return extensionsMap.get(s);
	}

	public static String getExtendedKeyUsage(String s) {
		return extendedKeyUsageMap.get(s);
	}

	public static String getSubjectAlternativeNames(int i) {
		return subjectAlternativeNamesMap.get(i);
	}

	public static String getKeyUsage(int i) {
		return keyUsageMap.get(i);
	}

	public static Collection<String> getAllExtensions() {
		return extensionsMap.values();
	}

	public static Collection<String> getAllExtendedKeyUsages() {
		return x509KeyPurpose.keySet();
	}

	public static Collection<String> getAllSubjectAlternativeNames() {
		return subjectAlternativeNamesMap.values();
	}

	public static Collection<String> getAllKeyUsages() {
		return keyUsageMap.values();
	}

	public static Integer getX509KeyUsage(String keyUsage) {
		return x509keyUsage.get(keyUsage);
	}

	public static KeyPurposeId getX509KeyPurposeId(String keyPurposeId) {
		return x509KeyPurpose.get(keyPurposeId);
	}

	public static Integer getX509SubjectAlternativeNames(String subjectAlternativeName) {
		return x509SubjectAlternativeName.get(subjectAlternativeName);
	}

	public static List<String> getAllSignatureAlgorithms() {
		return signatureAlgorithms;
	}

	public static List<String> getAllPublicKeyAlgorithms() {
		return publicKeyAlgorithms;
	}

	public static boolean extensionsIsSupported(String extensionOID){
		for (String s : supportedExtensions){
			if (s.equals(extensionOID)){
				return true;
			}
		}
		return false;
	}


	static {
		
		/*
		 * Maps for reading Certificates
		 */

		extensionsMap = new HashMap<>();
		extensionsMap.put("2.5.29.14", "SubjectKeyIdentifier");
		extensionsMap.put("2.5.29.15", "KeyUsage");
		extensionsMap.put("2.5.29.16", "PrivateKeyUsage");
		extensionsMap.put("2.5.29.17", "SubjectAlternativeName");
		extensionsMap.put("2.5.29.18", "IssuerAlternativeName");
		extensionsMap.put("2.5.29.19", "BasicConstraints");
		extensionsMap.put("2.5.29.30", "NameConstraints");
		extensionsMap.put("2.5.29.31", "CRLDistributionPoints");
		extensionsMap.put("2.5.29.32", "CertificatePolicies");
		extensionsMap.put("2.5.29.33", "PolicyMappings");
		extensionsMap.put("2.5.29.35", "AuthorityKeyIdentifier");
		extensionsMap.put("2.5.29.36", "PolicyConstraints");
		extensionsMap.put("2.5.29.37", "ExtKeyUsage");
		extensionsMap.put("1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess");

		extendedKeyUsageMap = new HashMap<>();
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.1", "Server Authentication");
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.2", "Client Authentication");
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.3", "Code signing");
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.4", "E-Mail Protection");
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.8", "Timestamping");
		extendedKeyUsageMap.put("1.3.6.1.5.5.7.3.9", "OSCP Signing");

		subjectAlternativeNamesMap = new HashMap<>();
		subjectAlternativeNamesMap.put(1, "E-Mail"); // RFC822
		subjectAlternativeNamesMap.put(2, "DNS");
		subjectAlternativeNamesMap.put(3, "X400 Address");
		subjectAlternativeNamesMap.put(4, "Directory Name");
		subjectAlternativeNamesMap.put(5, "EDI Party Name");
		subjectAlternativeNamesMap.put(6, "URI");
		subjectAlternativeNamesMap.put(7, "IP Address");
		subjectAlternativeNamesMap.put(8, "Registered ID");

		keyUsageMap = new HashMap<>();
		keyUsageMap.put(0, "Digital Signature");
		keyUsageMap.put(1, "Non Repudiation");
		keyUsageMap.put(2, "Key Encipherment");
		keyUsageMap.put(3, "Data Encipherment");
		keyUsageMap.put(4, "Key Agreement");
		keyUsageMap.put(5, "Key Certificate Signing");
		keyUsageMap.put(6, "CRL Signing");
		keyUsageMap.put(7, "Encipher only");
		keyUsageMap.put(8, "Decipher only");
		
		/*
		 * Maps used for Certificate generation
		 */

		x509keyUsage = new HashMap<>();
		x509keyUsage.put("Digital Signature", X509KeyUsage.digitalSignature);
		x509keyUsage.put("Non Repudiation", X509KeyUsage.nonRepudiation);
		x509keyUsage.put("Key Encipherment", X509KeyUsage.keyEncipherment);
		x509keyUsage.put("Data Encipherment", X509KeyUsage.dataEncipherment);
		x509keyUsage.put("Key Agreement", X509KeyUsage.keyAgreement);
		x509keyUsage.put("Key Certificate Signing", X509KeyUsage.keyCertSign);
		x509keyUsage.put("CRL Signing", X509KeyUsage.cRLSign);
		x509keyUsage.put("Encipher only", X509KeyUsage.encipherOnly);
		x509keyUsage.put("Decipher only", X509KeyUsage.decipherOnly);

		x509KeyPurpose = new HashMap<>();
		x509KeyPurpose.put("Server Authentication", KeyPurposeId.id_kp_serverAuth);
		x509KeyPurpose.put("Client Authentication", KeyPurposeId.id_kp_clientAuth);
		x509KeyPurpose.put("Code signing", KeyPurposeId.id_kp_codeSigning);
		x509KeyPurpose.put("E-Mail Protection", KeyPurposeId.id_kp_emailProtection);
		x509KeyPurpose.put("Timestamping", KeyPurposeId.id_kp_timeStamping);
		x509KeyPurpose.put("OCSP Signing", KeyPurposeId.id_kp_OCSPSigning);

		x509SubjectAlternativeName = new HashMap<>();
		x509SubjectAlternativeName.put("E-Mail", GeneralName.rfc822Name); // E-Mail
		x509SubjectAlternativeName.put("DNS", GeneralName.dNSName);
		x509SubjectAlternativeName.put("X400 Address", GeneralName.x400Address);
		x509SubjectAlternativeName.put("Directory Name", GeneralName.directoryName);
		x509SubjectAlternativeName.put("EDI Party Name", GeneralName.ediPartyName);
		x509SubjectAlternativeName.put("URI", GeneralName.uniformResourceIdentifier);
		x509SubjectAlternativeName.put("IP Address", GeneralName.iPAddress);
		x509SubjectAlternativeName.put("Registered ID", GeneralName.registeredID);
		
		/*
		 * Supported Algorithms and Extensions
		 */
		
		signatureAlgorithms = new LinkedList<>();
		signatureAlgorithms.add("MD2withRSA");
		signatureAlgorithms.add("MD5withRSA");
		signatureAlgorithms.add("SHA1withRSA");
		signatureAlgorithms.add("SHA224withRSA");
		signatureAlgorithms.add("SHA256withRSA");
		signatureAlgorithms.add("SHA384withRSA");
		signatureAlgorithms.add("SHA512withRSA");

		publicKeyAlgorithms = new LinkedList<>();
		publicKeyAlgorithms.add("RSA");
		
		supportedExtensions = new LinkedList<>();
		supportedExtensions.add("2.5.29.19"); // BasicConstraints
		supportedExtensions.add("2.5.29.15"); // KeyUsage
		supportedExtensions.add("2.5.29.37"); // ExtKeyUsage
		supportedExtensions.add("2.5.29.17"); // SubjectAlternativeName
		supportedExtensions.add("2.5.29.18"); // IssuerAlternativeName
		supportedExtensions.add("2.5.29.14"); // SubjectKeyIdentifier
		supportedExtensions.add("2.5.29.35"); // AuthorityKeyIdentifier

	}
}
