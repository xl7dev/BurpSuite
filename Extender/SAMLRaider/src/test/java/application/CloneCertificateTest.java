package application;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import gui.CertificateTab;
import helpers.CertificateHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
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

public class CloneCertificateTest {
	CertificateTabController certificateTabController;
	BurpCertificate originalCertificate;
	BurpCertificate clonedCertificate;

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void setup() {
		Security.addProvider(new BouncyCastleProvider());
		certificateTabController = new CertificateTabController(new CertificateTab());
		String file = "src/test/resources/hsr.pem";
		originalCertificate = certificateTabController.importCertificate(file);

		clonedCertificate = certificateTabController.cloneCertificate(originalCertificate, new FakeBurpCertificateBuilder(originalCertificate.getSubject()));

		assertTrue(originalCertificate.getSubject().equals(clonedCertificate.getSubject()));
	}

	/*
	 * X.509v1 Fields
	 */

	@Test
	public void versionNumberIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(3, clonedCertificate.getVersionNumber());
	}

	@Test
	public void SerialNumberHexIsCorrect() throws IOException, ParseException, CertificateException {
		String serialHex = "4d:6b:01:80:e1:82:b9:10:37:3d:e2:31:7c:92:75:94:70:2e:89:35";
		assertEquals(serialHex, clonedCertificate.getSerialNumber());
	}

	@Test
	public void serialNumberIsCorrect() throws IOException, ParseException, CertificateException {
		BigInteger serial = CertificateHelper.hexStringToBigInteger("4d:6b:01:80:e1:82:b9:10:37:3d:e2:31:7c:92:75:94:70:2e:89:35");
		assertEquals(serial, clonedCertificate.getSerialNumberBigInteger());
	}

	@Test
	public void issuerIsCorrect() throws IOException, ParseException, CertificateException {
		String issuer = "CN=QuoVadis Global SSL ICA, OU=www.quovadisglobal.com, O=QuoVadis Limited, C=BM";
		assertEquals(issuer, clonedCertificate.getIssuer());
	}

	@Test
	public void notBeforeDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notBefore = CertificateHelper.stringToDate("Aug 15 10:56:49 2012 GMT");
		assertEquals(notBefore, clonedCertificate.getNotBefore());
	}

	@Test
	public void notAfterDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date notAfter = CertificateHelper.stringToDate(("Aug 15 10:56:49 2015 GMT"));
		assertEquals(notAfter, clonedCertificate.getNotAfter());
	}

	@Test
	public void validOnDateIsCorrect() throws IOException, ParseException, CertificateException {
		Date testDate = CertificateHelper.stringToDate("May 23 23:23:05 2015 GMT");
		assertTrue(clonedCertificate.isValidOn(testDate));
	}

	@Test
	public void subjectIsCorrect() throws IOException, ParseException, CertificateException {
		String subject = "CN=www.hsr.ch, OU=IT-Systems, O=Hochschule Rapperswil, L=Rapperswil, ST=St. Gallen, C=CH";
		assertEquals(subject, clonedCertificate.getSubject());
	}

	@Test
	public void publicKeyAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("RSA", clonedCertificate.getPublicKeyAlgorithm());
	}

	@Test
	public void keySizeIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(512, clonedCertificate.getKeySize()); // b/c static key in
															// fake class
	}

	@Test
	public void modulusIsCorrect() {
		String modulus = "b4:a7:e4:61:70:57:4f:16:a9:70:82:b2:2b:e5:8b:6a:2a:62:97:98:41:9b:e1:28:72:a4:bd:ba:62:6c:fa:e9:90:0f:76:ab:fb:12:13:9d:ce:5d:e5:65:64:fa:b2:b6:54:31:65:a0:40:c6:06:88:74:20:e3:3d:91:ed:7e:d7";
		assertEquals(modulus, clonedCertificate.getPublicKeyModulus());
	}

	@Test
	public void exponentIsCorrect() {
		String exponent = "11"; // Static, not cloned from certificate
		assertEquals(exponent, clonedCertificate.getPublicKeyExponent());
	}

	/*
	 * Extensions
	 */

	@Test
	public void hasExtensionsIsCorrect() throws IOException, ParseException, CertificateException {
		assertTrue(clonedCertificate.hasExtensions());
	}

	@Test
	public void extensionsCountIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals(8, clonedCertificate.getExtensionsCount());
	}

	@Test
	public void AuthorityKeyIdentifierIsCorrect() throws IOException, CertificateEncodingException, NoSuchAlgorithmException {
		String autoirityKeyIdentifier = "32:4D:A1:4F:EA:F0:AE:99:B6:EE:9B:07:2C:84:08:11:50:8B:E2:7E";
		assertEquals(autoirityKeyIdentifier, clonedCertificate.getAuthorityKeyIdentifier());
	}

	@Test
	public void subjectKeyIdentifierIsCorrect() throws IOException {
		String subjectkeyIdentifier = "78:D1:C7:2B:90:09:82:0F:C7:58:26:02:93:A8:77:D1:12:38:C0:AB";
		assertEquals(subjectkeyIdentifier, clonedCertificate.getSubjectKeyIdentifier());
	}

	@Test
	public void subjectAlternativeNamesAreCorrect() throws IOException, ParseException, CertificateException {
		String subjectAlternativeNames = "[www.hsr.ch (DNS), log.hsr.ch (DNS), root@hsr.ch (E-Mail)]";
		assertEquals(subjectAlternativeNames, clonedCertificate.getSubjectAlternativeNames().toString());
	}

	@Test
	public void keyUsageIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Digital Signature, Key Encipherment]", clonedCertificate.getKeyUsage().toString());
	}

	@Test
	public void extendedKeyUsagesAreCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("[Server Authentication, Client Authentication]", clonedCertificate.getExtendedKeyUsage().toString());
	}

	@Test
	public void basicConstraintsIsCorrect() {
		assertEquals("CA: False", clonedCertificate.getBasicConstraints());
	}

	/*
	 * Signature
	 */

	@Test
	public void signatureAlgorithmIsCorrect() throws IOException, ParseException, CertificateException {
		assertEquals("SHA1WITHRSA", clonedCertificate.getSignatureAlgorithm());
	}

	@Test
	public void signatureValueIsCorrect() throws IOException, ParseException, CertificateException {
		String signatureValue = "0E:7F:C7:CB:5F:DB:82:5F:26:86:07:39:87:C7:62:D6:62:F6:FD:FC:EE:4D:AA:DD:4C:8D:8C:15:F5:2E:42:E8:D2:20:C2:32:E0:94:CB:AF:26:5C:71:7F:76:51:58:64:0D:56:13:B9:5D:62:54:1B:68:13:7B:BE:0E:A8:F6:3B";
		assertEquals(signatureValue, clonedCertificate.getSignature());
	}

	/*
	 * Private Key
	 */

	@Test
	public void hasPrivateKeyIsCorrect() {
		assertEquals(true, clonedCertificate.hasPrivateKey());
	}

//	@Test
//	public void exportedPrivateKeyIsCorrect() throws IOException, NoSuchAlgorithmException {
//		String outputFile = tempFolder.newFile("export_key.pem").toString();
//
//		certificateTabController.exportPrivateKey(clonedCertificate, outputFile);
//		certificateTabController.exportPrivateKey(clonedCertificate, "/tmp/gugus.pem");
//
//		String outputExpected = "-----BEGIN RSA PRIVATE KEY-----MIIBOwIBAAJBALSn5GFwV08WqXCCsivli2oqYpeYQZvhKHKkvbpibPrpkA92q/sSE53OXeVlZPqytlQxZaBAxgaIdCDjPZHtftcCARECQQCfZvawVBDNUDsnCeiBFdVdrO2U0aNNTjK/gk0N3mAornnF8HtYD13OJA1xEffdsTCnlFzX2VfRkgmU2jifSQyJAiEAwKB1jN8UJW941HCMhr7N6tG1CtStbFxwPiFo+/N4hMsCIQDwFzTXlg6mAHDxsG8ruBv6xI/xkq4YRR1eVsc0paq4pQIhALVLue3/IgUdnuYPk1GkhZG2UAoxlCnAaaPjNaHWFxORAiEA09g9ryoM7NM2eub4rhrrgumsL4Fsb8SDUz2Cl914hM0CIQC49S/G84WT2rtmHT9Q+Il/gQbu5osbznipWxMrTltdGQ==-----END RSA PRIVATE KEY-----";
//
//		byte[] outputData = Files.readAllBytes(Paths.get(outputFile));
//		String outputString = CertificateHelper.byteArrayToString(outputData).replaceAll("\r", "").replace("\n", "");
//
//		assertEquals(outputExpected, outputString);
//	}

	/*
	 * Export
	 */

	@Test
	public void exportClonedCertificate() throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException,
			IllegalStateException, SignatureException, InvalidKeySpecException {
		String outputFile = tempFolder.newFile("export_cloned.pem").toString();

		BurpCertificate clonedCertificate = certificateTabController.cloneCertificate(originalCertificate, new FakeBurpCertificateBuilder(originalCertificate.getSubject()));
		certificateTabController.exportCertificate(clonedCertificate, outputFile);

		String outputExpedted = "-----BEGIN CERTIFICATE-----MIIDmjCCA0SgAwIBAgIUTWsBgOGCuRA3PeIxfJJ1lHAuiTUwDQYJKoZIhvcNAQEFBQAwazELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHzAdBgNVBAsTFnd3dy5xdW92YWRpc2dsb2JhbC5jb20xIDAeBgNVBAMTF1F1b1ZhZGlzIEdsb2JhbCBTU0wgSUNBMB4XDTEyMDgxNTEwNTY0OVoXDTE1MDgxNTEwNTY0OVowgYExCzAJBgNVBAYTAkNIMRMwEQYDVQQIEwpTdC4gR2FsbGVuMRMwEQYDVQQHEwpSYXBwZXJzd2lsMR4wHAYDVQQKExVIb2Noc2NodWxlIFJhcHBlcnN3aWwxEzARBgNVBAsTCklULVN5c3RlbXMxEzARBgNVBAMTCnd3dy5oc3IuY2gwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBEaOCAakwggGlMA4GA1UdDwEB/wQEAwIFoDB0BggrBgEFBQcBAQRoMGYwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnF1b3ZhZGlzZ2xvYmFsLmNvbTA4BggrBgEFBQcwAoYsaHR0cDovL3RydXN0LnF1b3ZhZGlzZ2xvYmFsLmNvbS9xdnNzbGljYS5jcnQwHQYDVR0OBBYEFHjRxyuQCYIPx1gmApOod9ESOMCrMC4GA1UdEQQnMCWCCnd3dy5oc3IuY2iCCmxvZy5oc3IuY2iBC3Jvb3RAaHNyLmNoMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwucXVvdmFkaXNnbG9iYWwuY29tL3F2c3NsaWNhLmNybDBRBgNVHSAESjBIMEYGDCsGAQQBvlgAAmQBATA2MDQGCCsGAQUFBwIBFihodHRwOi8vd3d3LnF1b3ZhZGlzZ2xvYmFsLmNvbS9yZXBvc2l0b3J5MB8GA1UdIwQYMBaAFDJNoU/q8K6Ztu6bByyECBFQi+J+MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAANBAA5/x8tf24JfJoYHOYfHYtZi9v387k2q3UyNjBX1LkLo0iDCMuCUy68mXHF/dlFYZA1WE7ldYlQbaBN7vg6o9js=-----END CERTIFICATE-----";

		byte[] outputData = Files.readAllBytes(Paths.get(outputFile));
		String outputString = CertificateHelper.byteArrayToString(outputData).replaceAll("\r", "").replace("\n", "");

		assertEquals(outputExpedted, outputString);
	}
}