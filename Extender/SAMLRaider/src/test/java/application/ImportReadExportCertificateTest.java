package application;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import gui.CertificateTab;
import helpers.CertificateHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Date;

import model.BurpCertificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ImportReadExportCertificateTest {
	CertificateTabController certificateTabController;
	BurpCertificate certificate;

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void setup() throws CertificateException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		certificateTabController = new CertificateTabController(new CertificateTab());
		String file = "src/test/resources/hsr.pem";
		certificate = certificateTabController.importCertificate(file);
	}

	@Test
	public void importFromStringWorksCorrect() {

		String inputCertificate = "MIIGJjCCBQ6gAwIBAgIUTWsBgOGCuRA3PeIxfJJ1lHAuiTUwDQYJKoZIhvcNAQEF" + "BQAwazELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHzAd"
				+ "BgNVBAsTFnd3dy5xdW92YWRpc2dsb2JhbC5jb20xIDAeBgNVBAMTF1F1b1ZhZGlz" + "IEdsb2JhbCBTU0wgSUNBMB4XDTEyMDgxNTEwNTY0OVoXDTE1MDgxNTEwNTY0OVow"
				+ "gYExCzAJBgNVBAYTAkNIMRMwEQYDVQQIEwpTdC4gR2FsbGVuMRMwEQYDVQQHEwpS" + "YXBwZXJzd2lsMR4wHAYDVQQKExVIb2Noc2NodWxlIFJhcHBlcnN3aWwxEzARBgNV"
				+ "BAsTCklULVN5c3RlbXMxEzARBgNVBAMTCnd3dy5oc3IuY2gwggIiMA0GCSqGSIb3" + "DQEBAQUAA4ICDwAwggIKAoICAQCZOGior5F+1mhwqlBiIn3IAdURR1XxLYjr1vqw"
				+ "j+o+hrDG6RIbECaA/RGziVDbiVs6LGti8B/64cwHXZRHGUkCp+Gw7vpEfPDBuFpg" + "HwbapU6WtvIDDRnOAg6G1u62Sgly2WHb3JWegr4NtWvQqLVS19Q3GmkmgiobLMkj"
				+ "u116kHPdzrd4GqDSjBa23t5dwuX1mfG9uD/5lU3wu/u2dV+5IhihKlGblTMSOVL9" + "kRdq3CRqMo7+bwilpYa7cyEn5iMQaMuD5CzLOfPe/iRJzZ2693ek9/rt3S1LwtGU"
				+ "HqKS+KY6j4CalQwx5LeQqHw8B9dgLvuRUAquw9geHgmANpjvAYsbN7r/rJ8FxV/s" + "COZ+80u7R5s/aSaWfrunf4UrSLZC3QGeRva0+jSUmqnQ5w/COQPscZO1BT6ClOzO"
				+ "GmeMJt1Qa09JjpjToTBujEjE1HXBR/BRyMpq0sajxQpdLm53TbzPnfPxZsyGxQZU" + "7hR1Q+Z7JxytGqyuCp2FSn/vZ0cDPCjUm4n9WzWL93vz0VAKDUUdO2gqWiDPdk7t"
				+ "mYRULoMUId/xUnkWpm+/Smk1akAlXMeKjURLXX+P6BBhuAz/0crdWj1Fvi9V7631" + "m06U3QsYNg6qEUKfKAwwN1eZpoU41AknDEE7Ep65TyPwrWkMcf0SMd9n01W+5W1e"
				+ "uEcILwIDAQABo4IBqTCCAaUwdAYIKwYBBQUHAQEEaDBmMCoGCCsGAQUFBzABhh5o" + "dHRwOi8vb2NzcC5xdW92YWRpc2dsb2JhbC5jb20wOAYIKwYBBQUHMAKGLGh0dHA6"
				+ "Ly90cnVzdC5xdW92YWRpc2dsb2JhbC5jb20vcXZzc2xpY2EuY3J0MC4GA1UdEQQn" + "MCWCCnd3dy5oc3IuY2iCCmxvZy5oc3IuY2iBC3Jvb3RAaHNyLmNoMFEGA1UdIARK"
				+ "MEgwRgYMKwYBBAG+WAACZAEBMDYwNAYIKwYBBQUHAgEWKGh0dHA6Ly93d3cucXVv" + "dmFkaXNnbG9iYWwuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQDAgWgMB0GA1Ud"
				+ "JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQyTaFP6vCumbbu" + "mwcshAgRUIvifjA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnF1b3ZhZGlz"
				+ "Z2xvYmFsLmNvbS9xdnNzbGljYS5jcmwwHQYDVR0OBBYEFHjRxyuQCYIPx1gmApOo" + "d9ESOMCrMA0GCSqGSIb3DQEBBQUAA4IBAQB07i+XiQxFzCH8BCy7Ri2bR9bnZ4LW"
				+ "XfHScAoxip8s0r396J2DuGSxC1umprjDFOJALDq5cAh/C7h3/EiNGH0xyRk+tHsT" + "v6zRsPuajR1H4oSGTpsQ2tRXUPU22QP+sbdEdV/Wc66j6o0k4vTJltp4Rhk7ger0"
				+ "xZZKPsRYbOag3cO12H8xFGBVvtsqpSb0dQsApDGEo4tldwEb3DDoZb9Xb4fIMFrY" + "KbOGuL0UG3Nb3urnNDeM6199F1n/tiEcXtzMiQR0fJ32IvGtCMthyfH5Qhz1lLTv"
				+ "1B3vHsb1ggI1ggh//jNgmZOLVsx1hw2KEtlcIKZ9I03MsuwQiLHejIy+";

		BurpCertificate importedCertificate = certificateTabController.importCertificateFromString(inputCertificate);
		assertEquals("CN=QuoVadis Global SSL ICA, OU=www.quovadisglobal.com, O=QuoVadis Limited, C=BM", importedCertificate.getIssuer());
	}

	@Test
	public void importCertificate() throws IOException, ParseException, CertificateException, NoSuchAlgorithmException {
		// grep -v "-----BEGIN" hsr.pem | base64 -d | md5sum
		String fileHash = "1e6ec69fd55ba1930e13259316902b63";
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte[] certificateObject = certificate.getCertificate().getEncoded();
		String certificateHash = new String(Hex.encode(md5.digest(certificateObject)));
		assertEquals(fileHash, certificateHash);
	}

	@Test
	public void versionNumberIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(3, certificate.getVersionNumber());
	}

	@Test
	public void serialNumberIsCorrect() throws IOException, ParseException, CertificateException {
		BigInteger serial = CertificateHelper.hexStringToBigInteger("4d:6b:01:80:e1:82:b9:10:37:3d:e2:31:7c:92:75:94:70:2e:89:35");
		assertEquals(serial, certificate.getSerialNumberBigInteger());
	}

	@Test
	public void SerialNumberHexIsCorrect() throws IOException, ParseException, CertificateException {
		String serialHex = "4d:6b:01:80:e1:82:b9:10:37:3d:e2:31:7c:92:75:94:70:2e:89:35";
		assertEquals(serialHex, certificate.getSerialNumber());
	}

	@Test
	public void issuerIsCorrect() throws IOException, ParseException, CertificateException {
		String issuer = "CN=QuoVadis Global SSL ICA, OU=www.quovadisglobal.com, O=QuoVadis Limited, C=BM";
		assertEquals(issuer, certificate.getIssuer());
	}

	@Test
	public void notBeforeDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notBefore = CertificateHelper.stringToDate("Aug 15 10:56:49 2012 GMT");
		assertEquals(notBefore, certificate.getNotBefore());
	}

	@Test
	public void notAfterDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notAfter = CertificateHelper.stringToDate(("Aug 15 10:56:49 2015 GMT"));
		assertEquals(notAfter, certificate.getNotAfter());
	}

	@Test
	public void validOnDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date testDate = CertificateHelper.stringToDate("May 23 23:23:05 2015 GMT");
		assertTrue(certificate.isValidOn(testDate));
	}

	@Test
	public void subjectIsCorrect() throws IOException, ParseException, CertificateException {
		String subject = "CN=www.hsr.ch, OU=IT-Systems, O=Hochschule Rapperswil, L=Rapperswil, ST=St. Gallen, C=CH";
		assertEquals(subject, certificate.getSubject());
	}

	@Test
	public void publicKeyAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("RSA", certificate.getPublicKeyAlgorithm());
	}

	@Test
	public void keySizeIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(4096, certificate.getKeySize());
	}

	@Test
	public void modulusIsCorrect() {
		String modulus = "99:38:68:a8:af:91:7e:d6:68:70:aa:50:62:22:7d:c8:01:d5:11:47:55:f1:2d:88:eb:d6:fa:b0:8f:ea:3e:86:b0:c6:e9:12:1b:10:26:80:fd:11:b3:89:50:db:89:5b:3a:2c:6b:62:f0:1f:fa:e1:cc:07:5d:94:47:19:49:02:a7:e1:b0:ee:fa:44:7c:f0:c1:b8:5a:60:1f:06:da:a5:4e:96:b6:f2:03:0d:19:ce:02:0e:86:d6:ee:b6:4a:09:72:d9:61:db:dc:95:9e:82:be:0d:b5:6b:d0:a8:b5:52:d7:d4:37:1a:69:26:82:2a:1b:2c:c9:23:bb:5d:7a:90:73:dd:ce:b7:78:1a:a0:d2:8c:16:b6:de:de:5d:c2:e5:f5:99:f1:bd:b8:3f:f9:95:4d:f0:bb:fb:b6:75:5f:b9:22:18:a1:2a:51:9b:95:33:12:39:52:fd:91:17:6a:dc:24:6a:32:8e:fe:6f:08:a5:a5:86:bb:73:21:27:e6:23:10:68:cb:83:e4:2c:cb:39:f3:de:fe:24:49:cd:9d:ba:f7:77:a4:f7:fa:ed:dd:2d:4b:c2:d1:94:1e:a2:92:f8:a6:3a:8f:80:9a:95:0c:31:e4:b7:90:a8:7c:3c:07:d7:60:2e:fb:91:50:0a:ae:c3:d8:1e:1e:09:80:36:98:ef:01:8b:1b:37:ba:ff:ac:9f:05:c5:5f:ec:08:e6:7e:f3:4b:bb:47:9b:3f:69:26:96:7e:bb:a7:7f:85:2b:48:b6:42:dd:01:9e:46:f6:b4:fa:34:94:9a:a9:d0:e7:0f:c2:39:03:ec:71:93:b5:05:3e:82:94:ec:ce:1a:67:8c:26:dd:50:6b:4f:49:8e:98:d3:a1:30:6e:8c:48:c4:d4:75:c1:47:f0:51:c8:ca:6a:d2:c6:a3:c5:0a:5d:2e:6e:77:4d:bc:cf:9d:f3:f1:66:cc:86:c5:06:54:ee:14:75:43:e6:7b:27:1c:ad:1a:ac:ae:0a:9d:85:4a:7f:ef:67:47:03:3c:28:d4:9b:89:fd:5b:35:8b:f7:7b:f3:d1:50:0a:0d:45:1d:3b:68:2a:5a:20:cf:76:4e:ed:99:84:54:2e:83:14:21:df:f1:52:79:16:a6:6f:bf:4a:69:35:6a:40:25:5c:c7:8a:8d:44:4b:5d:7f:8f:e8:10:61:b8:0c:ff:d1:ca:dd:5a:3d:45:be:2f:55:ef:ad:f5:9b:4e:94:dd:0b:18:36:0e:aa:11:42:9f:28:0c:30:37:57:99:a6:85:38:d4:09:27:0c:41:3b:12:9e:b9:4f:23:f0:ad:69:0c:71:fd:12:31:df:67:d3:55:be:e5:6d:5e:b8:47:08:2f";
		assertEquals(modulus, certificate.getPublicKeyModulus());
	}

	@Test
	public void exponentIsCorrect() {
		String exponent = "65537";
		assertEquals(exponent, certificate.getPublicKeyExponent());
	}

	@Test
	public void hasExtensionsIsCorrect() throws IOException, ParseException, CertificateException {
		assertTrue(certificate.hasExtensions());
	}

	@Test
	public void extensionsCountIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(8, certificate.getExtensionsCount());
	}

	@Test
	public void subjectAlternativeNamesAreCorrect() throws IOException, ParseException, CertificateException {
		String subjectAlternativeNames = "[www.hsr.ch (DNS), log.hsr.ch (DNS), root@hsr.ch (E-Mail)]";
		assertEquals(subjectAlternativeNames, certificate.getSubjectAlternativeNames().toString());
	}

	@Test
	public void keyUsageIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Digital Signature, Key Encipherment]", certificate.getKeyUsage().toString());
	}

	@Test
	public void signatureAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("SHA1withRSA", certificate.getSignatureAlgorithm());
	}

	@Test
	public void extendedKeyUsagesAreCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Server Authentication, Client Authentication]", certificate.getExtendedKeyUsage().toString());
	}

	@Test
	public void AuthorityKeyIdentifierIsCorrect() throws IOException {
		assertEquals("78:D1:C7:2B:90:09:82:0F:C7:58:26:02:93:A8:77:D1:12:38:C0:AB", certificate.getSubjectKeyIdentifier());
	}

	@Test
	public void subjectKeyIdentifierIsCorrect() throws IOException {
		assertEquals("78:D1:C7:2B:90:09:82:0F:C7:58:26:02:93:A8:77:D1:12:38:C0:AB", certificate.getSubjectKeyIdentifier());
	}

	@Test
	public void basicConstraintsIsCorrect() {
		assertEquals("CA: False", certificate.getBasicConstraints());
	}

	@Test
	public void signatureValueIsCorrect() throws IOException, ParseException, CertificateException {
		String signatureValue = "74:EE:2F:97:89:0C:45:CC:21:FC:04:2C:BB:46:2D:9B:47:D6:E7:67:82:D6:5D:F1:D2:70:0A:31:8A:9F:2C:D2:BD:FD:E8:9D:83:B8:64:B1:0B:5B:A6:A6:B8:C3:14:E2:40:2C:3A:B9:70:08:7F:0B:B8:77:FC:48:8D:18:7D:31:C9:19:3E:B4:7B:13:BF:AC:D1:B0:FB:9A:8D:1D:47:E2:84:86:4E:9B:10:DA:D4:57:50:F5:36:D9:03:FE:B1:B7:44:75:5F:D6:73:AE:A3:EA:8D:24:E2:F4:C9:96:DA:78:46:19:3B:81:EA:F4:C5:96:4A:3E:C4:58:6C:E6:A0:DD:C3:B5:D8:7F:31:14:60:55:BE:DB:2A:A5:26:F4:75:0B:00:A4:31:84:A3:8B:65:77:01:1B:DC:30:E8:65:BF:57:6F:87:C8:30:5A:D8:29:B3:86:B8:BD:14:1B:73:5B:DE:EA:E7:34:37:8C:EB:5F:7D:17:59:FF:B6:21:1C:5E:DC:CC:89:04:74:7C:9D:F6:22:F1:AD:08:CB:61:C9:F1:F9:42:1C:F5:94:B4:EF:D4:1D:EF:1E:C6:F5:82:02:35:82:08:7F:FE:33:60:99:93:8B:56:CC:75:87:0D:8A:12:D9:5C:20:A6:7D:23:4D:CC:B2:EC:10:88:B1:DE:8C:8C:BE";
		assertEquals(signatureValue, certificate.getSignature());
	}

	@Test
	public void exportedCertificateHashIsCorrect() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		String outputFile = tempFolder.newFile("exported.pem").toString();

		certificateTabController.exportCertificate(certificate, outputFile);

		String outputExpected = "-----BEGIN CERTIFICATE-----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-----END CERTIFICATE-----";

		byte[] outputData = Files.readAllBytes(Paths.get(outputFile));
		String outputString = CertificateHelper.byteArrayToString(outputData).replaceAll("\r", "").replace("\n", "");

		assertEquals(outputExpected, outputString);
	}

	@Test
	public void noPrivateKeyAvailable() {
		assertTrue(!certificate.hasPrivateKey());
	}

	@Test
	public void importedPKCS8IsAvailable() {
		certificateTabController.importPKCS8(certificate, "src/test/resources/private_key_pkcs8.pem");
		assertTrue(certificate.hasPrivateKey());
		assertEquals("PKCS#8", certificate.getPrivateKey().getFormat());
	}

	@Test
	public void importedPrivateRSAKeyIsAvailable() {
		certificateTabController.importPrivateKey(certificate, "src/test/resources/private_key.pem");
		assertTrue(certificate.hasPrivateKey());
		assertEquals("PKCS#8", certificate.getPrivateKey().getFormat());
	}

}
