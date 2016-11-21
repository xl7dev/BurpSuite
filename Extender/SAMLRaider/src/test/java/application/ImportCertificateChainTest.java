package application;

import static org.junit.Assert.assertEquals;
import gui.CertificateTab;

import java.security.Security;
import java.util.List;

import model.BurpCertificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class ImportCertificateChainTest {

	static List<BurpCertificate> certificateChain;

	@BeforeClass
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		CertificateTabController certificateTabController = new CertificateTabController(new CertificateTab());
		certificateChain = certificateTabController.importCertificateChain("src/test/resources/hsr_chain.pem");
	}

	@Test
	public void chainSizeIsCorrect() {
		assertEquals(3, certificateChain.size());
	}

	@Test
	public void firstCertificateIsCorrect() {
		String cASubject = "CN=GeoTrust Global CA, O=GeoTrust Inc., C=US";
		assertEquals(cASubject, certificateChain.get(0).getSubject());
	}

	@Test
	public void secondCertificateIsCorrect() {
		String intermediateSubject = "CN=Google Internet Authority G2, O=Google Inc, C=US";
		assertEquals(intermediateSubject, certificateChain.get(1).getSubject());
	}

	@Test
	public void thirCertificateIsCorrect() {
		String certSubject = "CN=google.com, O=Google Inc, L=Mountain View, ST=California, C=US";
		assertEquals(certSubject, certificateChain.get(2).getSubject());

	}
}
