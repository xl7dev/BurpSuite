package application;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import gui.CertificateTab;
import helpers.CertificateHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Date;

import model.BurpCertificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CreateCertificateTest {
	CertificateTabController certificateController;
	BurpCertificate certificate;

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();
	
	/*
	 * Create new Certificate
	 */

	@Before
	public void setup() throws CertificateException, IOException, ParseException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			IllegalStateException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());

		String outputFileCertificate = tempFolder.newFile("certificate.pem").toString();
		String outputFilePrivateKey = tempFolder.newFile("privatekey.pem").toString();

		certificateController = new CertificateTabController(new CertificateTab());

		String subject = "O=SAML2 Burp Plugin Test, CN=saml.lan";
		BurpCertificateBuilder burpCertificateBuilder = new FakeBurpCertificateBuilder(subject);
		burpCertificateBuilder.setVersion(3);
		burpCertificateBuilder.setSerial("11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF");
		burpCertificateBuilder.setNotAfter("May 23 23:23:23 2023 GMT");
		burpCertificateBuilder.setNotBefore("May 23 23:23:23 2005 GMT");
		burpCertificateBuilder.setKeySize(2048);
		burpCertificateBuilder.setSignatureAlgorithm("SHA256withRSA");
		burpCertificateBuilder.setIssuer(subject); // Self-signed

		burpCertificateBuilder.setHasBasicConstraints(true);
		burpCertificateBuilder.setPathLimit(23);

		burpCertificateBuilder.addKeyUsage("Key Encipherment");
		burpCertificateBuilder.addKeyUsage("Digital Signature");

		burpCertificateBuilder.addExtendedKeyUsage("Server Authentication");
		burpCertificateBuilder.addExtendedKeyUsage("Client Authentication");

		burpCertificateBuilder.addSubjectAlternativeName("DNS", "foobar.hsr.ch");
		burpCertificateBuilder.addSubjectAlternativeName("E-Mail", "studenten@hsr.ch");
		burpCertificateBuilder.addSubjectAlternativeName("dozenten@hsr.ch (E-Mail)"); // Other Format

		burpCertificateBuilder.addIssuerAlternativeName("DNS", "issuer.example.net");
		burpCertificateBuilder.addIssuerAlternativeName("E-Mail", "issuer23@example.net");
		burpCertificateBuilder.addIssuerAlternativeName("issuer5@example.org (E-Mail)"); // Other Format

		burpCertificateBuilder.setAuthorityKeyIdentifier("01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14");
		
		burpCertificateBuilder.setSubjectKeyIdentifier(true);

		certificate = burpCertificateBuilder.generateSelfSignedCertificate();

		certificateController = new CertificateTabController(new CertificateTab());
		certificateController.exportCertificate(certificate, outputFileCertificate);
		certificateController.exportPrivateKey(certificate, outputFilePrivateKey);

		assertEquals(subject, certificate.getIssuer());
	}
	
	/*
	 * X.509 Fields
	 */

	@Test
	public void versionNumberIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(3, certificate.getVersionNumber());
	}

	@Test
	public void serialNumberIsCorrect() throws IOException, ParseException, CertificateException {
		BigInteger serial = CertificateHelper.hexStringToBigInteger("11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF");
		assertEquals(serial, certificate.getSerialNumberBigInteger());
	}

	@Test
	public void SerialNumberHexIsCorrect() throws IOException, ParseException, CertificateException {
		String serialHex = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF".toLowerCase();
		assertEquals(serialHex, certificate.getSerialNumber());
	}

	@Test
	public void issuerIsCorrect() throws IOException, ParseException, CertificateException {
		String issuer = "O=SAML2 Burp Plugin Test, CN=saml.lan";
		assertEquals(issuer, certificate.getIssuer());
	}

	@Test
	public void notBeforeDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notBefore = CertificateHelper.stringToDate("May 23 23:23:23 2005 GMT");
		assertEquals(notBefore, certificate.getNotBefore());
	}

	@Test
	public void notAfterDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notAfter = CertificateHelper.stringToDate(("May 23 23:23:23 2023 GMT"));
		assertEquals(notAfter, certificate.getNotAfter());
	}

	@Test
	public void validOnDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date testDate = CertificateHelper.stringToDate("May 23 23:23:05 2015 GMT");
		assertTrue(certificate.isValidOn(testDate));
	}

	@Test
	public void subjectIsCorrect() throws IOException, ParseException, CertificateException {
		String subject = "O=SAML2 Burp Plugin Test, CN=saml.lan";
		assertEquals(subject, certificate.getSubject());
	}

	@Test
	public void publicKeyAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("RSA", certificate.getPublicKeyAlgorithm());
	}

	@Test
	public void keySizeIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(512, certificate.getKeySize());
	}

	@Test
	public void modulusIsCorrect() {
		String modulus = "b4:a7:e4:61:70:57:4f:16:a9:70:82:b2:2b:e5:8b:6a:2a:62:97:98:41:9b:e1:28:72:a4:bd:ba:62:6c:fa:e9:90:0f:76:ab:fb:12:13:9d:ce:5d:e5:65:64:fa:b2:b6:54:31:65:a0:40:c6:06:88:74:20:e3:3d:91:ed:7e:d7";
		assertEquals(modulus, certificate.getPublicKeyModulus());
	}

	@Test
	public void exponentIsCorrect() {
		String exponent = "11";
		assertEquals(exponent, certificate.getPublicKeyExponent());
	}

	@Test
	public void signatureAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("SHA256WITHRSA", certificate.getSignatureAlgorithm());
	}

	/*
	 * Signature
	 */

	@Test
	public void signatureValueIsCorrect() throws IOException, ParseException, CertificateException {
		String signatureValue = "36:C0:19:45:50:F8:9D:DC:0A:6C:9A:BC:7A:26:C7:5B:ED:D0:41:10:18:FE:FE:6F:12:22:C9:2E:1F:5A:D1:58:51:0B:5E:CB:59:AE:9C:ED:A3:93:67:90:82:FE:14:0D:E4:8B:E1:AF:DE:FE:31:1E:B4:F8:BD:48:F6:F4:EA:CC";
		assertEquals(signatureValue, certificate.getSignature());
	}
	
	/*
	 * X.509 Extensions
	 */

	@Test
	public void hasExtensionsIsCorrect() throws IOException, ParseException, CertificateException {
		assertTrue(certificate.hasExtensions());
	}

	@Test
	public void extensionsCountIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(7, certificate.getExtensionsCount());
	}

	@Test
	public void subjectAlternativeNamesAreCorrect() throws IOException, ParseException, CertificateException {
		String subjectAlternativeNames = "[foobar.hsr.ch (DNS), studenten@hsr.ch (E-Mail), dozenten@hsr.ch (E-Mail)]";
		assertEquals(subjectAlternativeNames, certificate.getSubjectAlternativeNames().toString());
	}

	@Test
	public void keyUsageIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Digital Signature, Key Encipherment]", certificate.getKeyUsage().toString());
	}

	@Test
	public void extendedKeyUsagesAreCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Server Authentication, Client Authentication]", certificate.getExtendedKeyUsage().toString());
	}

	@Test
	public void issuerAlternativeNameIsCorrect() throws CertificateParsingException {
		assertEquals("[issuer.example.net (DNS), issuer23@example.net (E-Mail), issuer5@example.org (E-Mail)]", certificate.getIssuerAlternativeNames().toString());
	}

	@Test
	public void AuthorityKeyIdentifierIsCorrect() throws IOException, CertificateEncodingException, NoSuchAlgorithmException {
		String authorityKeyIdentifier = "01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14";
		assertEquals(authorityKeyIdentifier, certificate.getAuthorityKeyIdentifier());
	}

	@Test
	public void subjectKeyIdentifierIsCorrect() throws IOException {
		String subjectKeyIdentifier = "D0:6C:EC:6D:35:83:BC:55:12:1B:0C:CB:3E:FE:D7:26:A6:16:64:68";
		assertEquals(subjectKeyIdentifier, certificate.getSubjectKeyIdentifier());
	}

	@Test
	public void basicConstraintsIsCorrect() {
		assertEquals("CA: True. Path limit: 23.", certificate.getBasicConstraints());
	}
	
	/*
	 * Other Tests
	 */

	@Test
	public void createSelfSignedCertificateShort() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException,
			CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException {
		String subject = "C=CH, ST=St. Gallen, L=Rapperswil, O=Hochschule Rapperswil, OU=IT-Systems, CN=www.hsr.ch";
		BurpCertificateBuilder burpCertificateBuilder = new FakeBurpCertificateBuilder(subject);
		BurpCertificate certificate = burpCertificateBuilder.generateSelfSignedCertificate();

		assertEquals(subject, certificate.getIssuer());
	}
}