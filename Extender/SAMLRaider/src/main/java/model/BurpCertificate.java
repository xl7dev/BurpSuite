package model;

import helpers.CertificateHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class BurpCertificate {

	private X509Certificate certificate;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private String source;

	public BurpCertificate() {
	}

	public BurpCertificate(X509Certificate certificate) {
		this.certificate = certificate;
		source = "default";
	}

	public BurpCertificate(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public int getVersionNumber() {
		return certificate.getVersion();
	}

	public BigInteger getSerialNumberBigInteger() {
		return certificate.getSerialNumber();
	}

	public String getSerialNumber() {
		return CertificateHelper.bigIntegerToHexString(getSerialNumberBigInteger());
	}

	public String getIssuer() {
		return certificate.getIssuerX500Principal().toString();
	}

	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	public Date getNotAfter() {
		return certificate.getNotAfter();
	}

	public boolean isValidOn(Date date) {
		try {
			certificate.checkValidity(date);
			return true;
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			return false;
		}
	}

	public String getSubject() {
		return certificate.getSubjectX500Principal().toString();
	}

	public boolean hasExtensions() {
		return (!certificate.getCriticalExtensionOIDs().isEmpty()) || (!certificate.getNonCriticalExtensionOIDs().isEmpty());
	}

	public int getExtensionsCount() {
		return certificate.getCriticalExtensionOIDs().size() + certificate.getNonCriticalExtensionOIDs().size();
	}

	public String getSignatureAlgorithm() {
		return certificate.getSigAlgName();
	}

	public String getSignature() {
		return CertificateHelper.addHexColons(CertificateHelper.byteArrayToHex(certificate.getSignature()));
	}

	public String getPublicKeyAlgorithm() {
		return certificate.getPublicKey().getAlgorithm();
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}


	public int getKeySize() {
		if (certificate.getPublicKey() instanceof RSAPublicKey) {
			RSAPublicKey pub = (RSAPublicKey) certificate.getPublicKey();
			return pub.getModulus().bitLength();
		} else {
			return 0;
		}
	}

	public String getPublicKeyModulus() {
		// https://stackoverflow.com/questions/20897065/how-to-get-exponent-and-modulus-value-of-rsa-public-key-from-pfx-file-pem-file-i
		if (certificate.getPublicKey() instanceof RSAPublicKey) {
			RSAPublicKey pub = (RSAPublicKey) certificate.getPublicKey();
			return CertificateHelper.addHexColons(pub.getModulus().toString(16));
		} else {
			return "";
		}
	}

	public String getPublicKeyExponent() {
		Pattern pattern = Pattern.compile("exponent: ([0-9]*)");
		Matcher matcher = pattern.matcher(certificate.getPublicKey().toString());
		if (matcher.find()) {
			return matcher.group(1);
		}
		return "Not found";
	}

	/*
	 * Extensions
	 */

	public List<String> getKeyUsage() {
		boolean[] keyUsage = certificate.getKeyUsage();
		List<String> keyUsageList = new LinkedList<>();

		if (keyUsage == null) {
			return keyUsageList;
		}

		for (int i = 0; i < keyUsage.length; i++) {
			if (keyUsage[i]) {
				keyUsageList.add(ObjectIdentifier.getKeyUsage(i));
			}
		}
		return keyUsageList;
	}

	public List<String> getSubjectAlternativeNames() {
		List<String> subjectAlternativeNames = new LinkedList<String>();

		try {
			if (certificate.getSubjectAlternativeNames() == null) {
				return subjectAlternativeNames;
			}

			for (List<?> i : certificate.getSubjectAlternativeNames()) {
				subjectAlternativeNames.add(i.get(1) + " (" + ObjectIdentifier.getSubjectAlternativeNames((Integer) i.get(0)) + ")");
			}
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}

		return subjectAlternativeNames;
	}

	public List<String> getIssuerAlternativeNames() {
		List<String> issuerAlternativeNames = new LinkedList<String>();

		try {
			if (certificate.getIssuerAlternativeNames() == null) {
				return issuerAlternativeNames;
			}

			for (List<?> i : certificate.getIssuerAlternativeNames()) {
				issuerAlternativeNames.add(i.get(1) + " (" + ObjectIdentifier.getSubjectAlternativeNames((Integer) i.get(0)) + ")");
			}
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}

		return issuerAlternativeNames;
	}

	public boolean isCa() {
		return certificate.getBasicConstraints() == -1 ? false : true;
	}

	public String getPathLimit() {
		int pathLimit = certificate.getBasicConstraints();
		if (pathLimit != -1) {
			return pathLimit == Integer.MAX_VALUE ? "No Limit" : String.valueOf(pathLimit);
		} else {
			return "";
		}
	}
	
	public boolean hasNoPathLimit(){
		return certificate.getBasicConstraints() == Integer.MAX_VALUE;
	}
	
	public String getBasicConstraints() {
		String basicConstraints = "";

		switch (certificate.getBasicConstraints()) {
		case -1:
			basicConstraints = "CA: False";
			break;
		case Integer.MAX_VALUE:
			basicConstraints = "CA: True. No path limit.";
			break;
		default:
			basicConstraints = "CA: True. Path limit: " + certificate.getBasicConstraints() + ".";
		}

		return basicConstraints;
	}

	public List<String> getExtendedKeyUsage() {
		List<String> extendedKeyUsage = new LinkedList<>();

		try {
			if (certificate.getExtendedKeyUsage() == null) {
				return extendedKeyUsage;
			}

			for (String i : certificate.getExtendedKeyUsage()) {
				extendedKeyUsage.add(ObjectIdentifier.getExtendedKeyUsage(i));
			}
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}

		return extendedKeyUsage;
	}

	public String getAuthorityKeyIdentifier() {
		byte[] e = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());

		if (e == null) {
			return "";
		}

		ASN1Primitive ap;
		byte[] k = {};
		try {
			ap = JcaX509ExtensionUtils.parseExtensionValue(e);
			k = ASN1Sequence.getInstance(ap.getEncoded()).getEncoded();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		// Very ugly hack to extract the SHA1 Hash (59 Hex Chars) from the
		// Extension :(
		return CertificateHelper.addHexColons(CertificateHelper.byteArrayToHex(k)).substring(12, k.length * 3 - 1);
	}

	public String getSubjectKeyIdentifier() {
		// https://stackoverflow.com/questions/6523081/why-doesnt-my-key-identifier-match
		byte[] e = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());

		if (e == null) {
			return "";
		}

		ASN1Primitive ap;
		byte[] k = {};
		try {
			ap = JcaX509ExtensionUtils.parseExtensionValue(e);
			k = ASN1OctetString.getInstance(ap.getEncoded()).getOctets();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return CertificateHelper.addHexColons(CertificateHelper.byteArrayToHex(k));
	}

	public List<BurpCertificateExtension> getAllExtensions() {
		List<BurpCertificateExtension> allExtensions = new LinkedList<>();

		Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
		if (criticalExtensionOIDs != null) {
			for (String i : criticalExtensionOIDs) {
				allExtensions.add(new BurpCertificateExtension(i, true, certificate.getExtensionValue(i)));
			}
		}

		Set<String> nonCriticalExtensionOIDs = certificate.getNonCriticalExtensionOIDs();
		if (nonCriticalExtensionOIDs != null) {
			for (String i : nonCriticalExtensionOIDs) {
				allExtensions.add(new BurpCertificateExtension(i, false, certificate.getExtensionValue(i)));
			}
		}

		return allExtensions;
	}

	public boolean hasPrivateKey() {
		return getPrivateKey() != null ? true : false;
	}

	public String toString() {
		String toString = getSubject();
		toString += " [";
		toString += "Private Key: " + hasPrivateKey();
		toString += "; Source: " + getSource();
		toString += "]";

		return toString;
	}

}